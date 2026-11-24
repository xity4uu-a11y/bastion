from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Finding, Project
from app.schemas import CodeContextLine, FindingCodeContextResponse, FindingResponse, FindingUpdate
from app.services.sarif import build_sarif_report

router = APIRouter(prefix="/api/findings", tags=["findings"])

EXT_TO_LANG = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".jsx": "jsx",
    ".go": "go",
    ".rs": "rust",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".sh": "bash",
    ".sql": "sql",
}


def _serialize_finding(f: Finding) -> FindingResponse:
    return FindingResponse(
        id=f.id,
        run_id=f.run_id,
        project_id=f.project_id,
        gate_number=f.gate_number,
        source_engine=f.source_engine,
        fingerprint=f.fingerprint,
        title=f.title,
        description=f.description,
        detector_or_class=f.detector_or_class,
        file_path=f.file_path,
        line_number=f.line_number,
        verified=f.verified,
        redacted_secret=f.redacted_secret,
        git_commit=f.git_commit,
        verdict=f.verdict,
        severity=f.severity,
        confidence=f.confidence,
        hunter_agent_id=f.hunter_agent_id,
        verifier_agent_id=f.verifier_agent_id,
        root_cause=f.root_cause,
        remediation=f.remediation,
        fixed_code=f.fixed_code,
        trace=json.loads(f.trace_json or "[]"),
        evidence=json.loads(f.evidence_json or "[]"),
        blockers=json.loads(f.blockers_json or "[]"),
        resolved=f.resolved,
        resolution_note=f.resolution_note,
        resolved_at=f.resolved_at,
        created_at=f.created_at,
    )


@router.get("", response_model=list[FindingResponse])
def list_findings(
    project_id: str | None = Query(default=None),
    run_id: str | None = Query(default=None),
    gate_number: int | None = Query(default=None, ge=1, le=2),
    verdict: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    resolved: bool | None = Query(default=None),
    search: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> list[FindingResponse]:
    stmt = select(Finding).order_by(desc(Finding.created_at))
    if project_id:
        stmt = stmt.where(Finding.project_id == project_id)
    if run_id:
        stmt = stmt.where(Finding.run_id == run_id)
    if gate_number is not None:
        stmt = stmt.where(Finding.gate_number == gate_number)
    if verdict:
        stmt = stmt.where(Finding.verdict == verdict)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if resolved is not None:
        stmt = stmt.where(Finding.resolved == resolved)

    rows = db.scalars(stmt).all()
    if search:
        q = search.lower().strip()
        rows = [
            r
            for r in rows
            if q in r.title.lower()
            or q in r.file_path.lower()
            or q in r.detector_or_class.lower()
            or q in r.description.lower()
        ]
    return [_serialize_finding(r) for r in rows]


@router.get("/export/sarif")
def export_findings_sarif(
    project_id: str | None = Query(default=None),
    run_id: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> JSONResponse:
    stmt = select(Finding).order_by(desc(Finding.created_at))
    if project_id:
        stmt = stmt.where(Finding.project_id == project_id)
    if run_id:
        stmt = stmt.where(Finding.run_id == run_id)
    rows = db.scalars(stmt).all()
    proj_name = "Bastion Target"
    if project_id:
        proj = db.get(Project, project_id)
        if proj:
            proj_name = proj.name
    sarif_doc = build_sarif_report(list(rows), project_name=proj_name)
    return JSONResponse(
        content=sarif_doc,
        media_type="application/sarif+json",
        headers={"Content-Disposition": 'attachment; filename="bastion-findings.sarif.json"'},
    )


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(finding_id: str, db: Session = Depends(get_db)) -> FindingResponse:
    row = db.get(Finding, finding_id)
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _serialize_finding(row)


@router.patch("/{finding_id}", response_model=FindingResponse)
def update_finding(
    finding_id: str,
    payload: FindingUpdate,
    db: Session = Depends(get_db),
) -> FindingResponse:
    row = db.get(Finding, finding_id)
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")
    if payload.resolved is not None:
        row.resolved = payload.resolved
        row.resolved_at = dt.datetime.now(dt.timezone.utc) if payload.resolved else None
    if payload.resolution_note is not None:
        row.resolution_note = payload.resolution_note
    db.commit()
    db.refresh(row)
    return _serialize_finding(row)


@router.get("/{finding_id}/context", response_model=FindingCodeContextResponse)
def get_finding_context(
    finding_id: str,
    radius: int = Query(default=8, ge=2, le=40),
    db: Session = Depends(get_db),
) -> FindingCodeContextResponse:
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    project = db.get(Project, finding.project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    base_dir = Path(project.path).resolve()
    candidate = (base_dir / finding.file_path).resolve()
    # Strict path traversal containment
    try:
        candidate.relative_to(base_dir)
    except ValueError:
        return FindingCodeContextResponse(
            finding_id=finding.id,
            file_path=finding.file_path,
            line_number=finding.line_number,
            language="text",
            exists=False,
            lines=[],
            fixed_code=finding.fixed_code,
            remediation=finding.remediation,
        )

    lang = EXT_TO_LANG.get(candidate.suffix.lower(), "text")
    if not candidate.exists() or not candidate.is_file():
        return FindingCodeContextResponse(
            finding_id=finding.id,
            file_path=finding.file_path,
            line_number=finding.line_number,
            language=lang,
            exists=False,
            lines=[],
            fixed_code=finding.fixed_code,
            remediation=finding.remediation,
        )

    raw_lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
    start_ln = max(1, finding.line_number - radius)
    end_ln = min(len(raw_lines), finding.line_number + radius)
    snippet: list[CodeContextLine] = []
    for ln in range(start_ln, end_ln + 1):
        text = raw_lines[ln - 1]
        # Never expose unredacted secret lines for Gate 1 findings
        if finding.gate_number == 1 and ln == finding.line_number and finding.redacted_secret:
            text = f"[REDACTED SECRET MATCH: {finding.redacted_secret}]"
        snippet.append(
            CodeContextLine(
                line_number=ln,
                content=text,
                highlight=(ln == finding.line_number),
            )
        )

    return FindingCodeContextResponse(
        finding_id=finding.id,
        file_path=finding.file_path,
        line_number=finding.line_number,
        language=lang,
        exists=True,
        lines=snippet,
        fixed_code=finding.fixed_code,
        remediation=finding.remediation,
    )
