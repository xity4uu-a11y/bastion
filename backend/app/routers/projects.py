from __future__ import annotations

import json
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import ArtifactRecord, CoverageLedgerEntry, GateExecution, Project, ReleaseRun
from app.schemas import (
    ArtifactResponse,
    BlaActionRequest,
    BlaActionResponse,
    CicdWorkflowResponse,
    CoverageLedgerResponse,
    ProjectCreate,
    ProjectResponse,
    ProjectUpdate,
    SmokeTestRequest,
    SmokeTestResultResponse,
)
from app.services.cicd import DEFAULT_CONTAINER_IMAGE, generate_github_actions_workflow
from app.services.gate3_bla import (
    discover_build_artifacts,
    run_bla_apply,
    run_bla_restore,
    run_post_bla_smoke_test,
)

router = APIRouter(prefix="/api/projects", tags=["projects"])


def _serialize_project(db: Session, project: Project) -> ProjectResponse:
    p = Path(project.path)
    exists = p.exists() and p.is_dir()
    is_git = exists and (p / ".git").exists()
    latest = db.scalar(
        select(ReleaseRun)
        .where(ReleaseRun.project_id == project.id)
        .order_by(desc(ReleaseRun.created_at))
        .limit(1)
    )
    latest_smoke: str | None = None
    if latest:
        g3 = db.scalar(
            select(GateExecution)
            .where(GateExecution.run_id == latest.id, GateExecution.gate_number == 3)
            .limit(1)
        )
        if g3:
            meta = json.loads(g3.metadata_json or "{}")
            smoke = meta.get("smoke_test")
            if isinstance(smoke, dict) and smoke.get("status"):
                latest_smoke = str(smoke["status"])

    return ProjectResponse(
        id=project.id,
        name=project.name,
        path=project.path,
        description=project.description,
        default_secret_scanner=project.default_secret_scanner or "auto",
        default_bla_intensity=project.default_bla_intensity,
        default_audit_profile=project.default_audit_profile,
        smoke_test_cmd=project.smoke_test_cmd or "",
        bla_applied=project.bla_applied,
        bla_backup_dir=project.bla_backup_dir,
        is_git_repo=is_git,
        path_exists=exists,
        latest_run_id=latest.id if latest else None,
        latest_run_status=latest.status if latest else None,
        latest_readiness_score=latest.readiness_score if latest else None,
        latest_smoke_status=latest_smoke,
        created_at=project.created_at,
        updated_at=project.updated_at,
    )


@router.get("", response_model=list[ProjectResponse])
def list_projects(db: Session = Depends(get_db)) -> list[ProjectResponse]:
    projects = db.scalars(select(Project).order_by(desc(Project.updated_at))).all()
    return [_serialize_project(db, p) for p in projects]


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db)) -> ProjectResponse:
    resolved = str(Path(payload.path).expanduser().resolve())
    if not Path(resolved).exists() or not Path(resolved).is_dir():
        raise HTTPException(status_code=400, detail=f"Directory does not exist: {resolved}")

    existing = db.scalar(select(Project).where(Project.path == resolved))
    if existing:
        raise HTTPException(status_code=409, detail="A project with this local directory is already registered.")

    project = Project(
        name=payload.name.strip(),
        path=resolved,
        description=payload.description.strip(),
        default_secret_scanner=payload.default_secret_scanner,
        default_bla_intensity=payload.default_bla_intensity,
        default_audit_profile=payload.default_audit_profile,
        smoke_test_cmd=payload.smoke_test_cmd.strip(),
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return _serialize_project(db, project)


@router.get("/{project_id}", response_model=ProjectResponse)
def get_project(project_id: str, db: Session = Depends(get_db)) -> ProjectResponse:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return _serialize_project(db, project)


@router.patch("/{project_id}", response_model=ProjectResponse)
def update_project(project_id: str, payload: ProjectUpdate, db: Session = Depends(get_db)) -> ProjectResponse:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if payload.name is not None:
        project.name = payload.name.strip()
    if payload.description is not None:
        project.description = payload.description.strip()
    if payload.default_secret_scanner is not None:
        project.default_secret_scanner = payload.default_secret_scanner
    if payload.default_bla_intensity is not None:
        project.default_bla_intensity = payload.default_bla_intensity
    if payload.default_audit_profile is not None:
        project.default_audit_profile = payload.default_audit_profile
    if payload.smoke_test_cmd is not None:
        project.smoke_test_cmd = payload.smoke_test_cmd.strip()
    db.commit()
    db.refresh(project)
    return _serialize_project(db, project)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(project_id: str, db: Session = Depends(get_db)) -> None:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    db.delete(project)
    db.commit()


@router.get("/{project_id}/cicd/github-actions", response_model=CicdWorkflowResponse)
def get_project_github_actions(
    project_id: str,
    mode: str = Query(default="container", pattern="^(container|self-built)$"),
    image: str = Query(default=DEFAULT_CONTAINER_IMAGE),
    db: Session = Depends(get_db),
) -> CicdWorkflowResponse:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    effective_image = image.strip() or DEFAULT_CONTAINER_IMAGE
    return CicdWorkflowResponse(
        project_id=project.id,
        project_name=project.name,
        mode=mode,
        image=effective_image,
        filename=".github/workflows/bastion-gate.yml",
        yaml_content=generate_github_actions_workflow(project, mode=mode, container_image=effective_image),
    )


@router.get("/{project_id}/ledger", response_model=list[CoverageLedgerResponse])
def get_project_ledger(project_id: str, db: Session = Depends(get_db)) -> list[CoverageLedgerResponse]:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    entries = db.scalars(
        select(CoverageLedgerEntry)
        .where(CoverageLedgerEntry.project_id == project_id)
        .order_by(CoverageLedgerEntry.coverage_id)
    ).all()
    return [
        CoverageLedgerResponse(
            id=e.id,
            project_id=e.project_id,
            last_run_id=e.last_run_id,
            coverage_id=e.coverage_id,
            surface=e.surface,
            boundary=e.boundary,
            subsystem=e.subsystem,
            attack_class=e.attack_class,
            status=e.status,
            prior_status=e.prior_status,
            wave=e.wave,
            hunter_agent_id=e.hunter_agent_id,
            verifier_agent_id=e.verifier_agent_id,
            source_hash=e.source_hash,
            updated_at=e.updated_at,
        )
        for e in entries
    ]


@router.get("/{project_id}/artifacts", response_model=list[ArtifactResponse])
def get_project_artifacts(project_id: str, db: Session = Depends(get_db)) -> list[ArtifactResponse]:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    latest_run = db.scalar(
        select(ReleaseRun)
        .where(ReleaseRun.project_id == project_id)
        .order_by(desc(ReleaseRun.created_at))
        .limit(1)
    )
    if latest_run:
        rows = db.scalars(
            select(ArtifactRecord)
            .where(ArtifactRecord.run_id == latest_run.id)
            .order_by(ArtifactRecord.relative_path)
        ).all()
        if rows:
            return [
                ArtifactResponse(
                    id=a.id,
                    run_id=a.run_id,
                    project_id=a.project_id,
                    relative_path=a.relative_path,
                    artifact_format=a.artifact_format,
                    category=a.category,
                    input_bytes=a.input_bytes,
                    output_bytes=a.output_bytes,
                    mirror_path=a.mirror_path,
                    intensity=a.intensity,
                    status="applied" if project.bla_applied and a.status == "hardened" else a.status,
                    defense_score=a.defense_score,
                    token_amplification=a.token_amplification,
                    cost_amplification=a.cost_amplification,
                    before_exposure_score=a.before_exposure_score,
                    verified=a.verified,
                    created_at=a.created_at,
                )
                for a in rows
            ]

    target = Path(project.path)
    if not target.exists():
        return []
    discovered = discover_build_artifacts(target)
    return [
        ArtifactResponse(
            id=f"preview-{idx}",
            run_id="",
            project_id=project.id,
            relative_path=a.relative_path,
            artifact_format=a.artifact_format,
            category=a.category,
            input_bytes=a.input_bytes,
            output_bytes=0,
            mirror_path=None,
            intensity=project.default_bla_intensity,
            status="discovered",
            defense_score=0.0,
            token_amplification=0.0,
            cost_amplification=0.0,
            before_exposure_score=a.before_exposure_score,
            verified=False,
            created_at=project.updated_at,
        )
        for idx, a in enumerate(discovered)
    ]


@router.post("/{project_id}/bla/smoke-test", response_model=SmokeTestResultResponse)
def run_project_smoke_test(
    project_id: str,
    payload: SmokeTestRequest,
    db: Session = Depends(get_db),
) -> SmokeTestResultResponse:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    target = Path(project.path)
    if not target.exists():
        raise HTTPException(status_code=400, detail="Target directory no longer exists")
    cmd = (payload.smoke_test_cmd if payload.smoke_test_cmd is not None else project.smoke_test_cmd or "").strip()
    if not cmd:
        raise HTTPException(status_code=400, detail="No smoke_test_cmd configured for this project.")
    res = run_post_bla_smoke_test(target, cmd, timeout_seconds=payload.timeout_seconds)

    # Persist latest smoke status onto most recent Gate 3 metadata if available
    latest_run = db.scalar(
        select(ReleaseRun).where(ReleaseRun.project_id == project_id).order_by(desc(ReleaseRun.created_at)).limit(1)
    )
    if latest_run:
        g3 = db.scalar(
            select(GateExecution)
            .where(GateExecution.run_id == latest_run.id, GateExecution.gate_number == 3)
            .limit(1)
        )
        if g3:
            meta = json.loads(g3.metadata_json or "{}")
            meta["smoke_test"] = res.to_dict()
            g3.metadata_json = json.dumps(meta)
            db.commit()

    return SmokeTestResultResponse(**res.to_dict())


@router.post("/{project_id}/bla/apply", response_model=BlaActionResponse)
def apply_bla_release(
    project_id: str,
    payload: BlaActionRequest,
    db: Session = Depends(get_db),
) -> BlaActionResponse:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    target = Path(project.path)
    if not target.exists():
        raise HTTPException(status_code=400, detail="Target directory no longer exists")
    try:
        res = run_bla_apply(target, intensity=payload.intensity, force_simulation=payload.force_simulation)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    project.bla_applied = True
    project.bla_backup_dir = res.get("backup_directory")
    project.default_bla_intensity = payload.intensity

    latest_run = db.scalar(
        select(ReleaseRun).where(ReleaseRun.project_id == project_id).order_by(desc(ReleaseRun.created_at)).limit(1)
    )
    if latest_run:
        rows = db.scalars(select(ArtifactRecord).where(ArtifactRecord.run_id == latest_run.id)).all()
        for row in rows:
            if row.relative_path in res.get("affected_files", []):
                row.status = "applied"
                row.intensity = payload.intensity
    db.commit()

    return BlaActionResponse(
        status=res["status"],
        mode=res["mode"],
        project_id=project.id,
        bla_applied=True,
        affected_files=res["affected_files"],
        backup_directory=res.get("backup_directory"),
        message=res["message"],
        artifacts=res.get("artifacts", []),
    )


@router.post("/{project_id}/bla/restore", response_model=BlaActionResponse)
def restore_bla_release(
    project_id: str,
    force_simulation: bool = False,
    db: Session = Depends(get_db),
) -> BlaActionResponse:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    target = Path(project.path)
    if not target.exists():
        raise HTTPException(status_code=400, detail="Target directory no longer exists")
    try:
        res = run_bla_restore(target, force_simulation=force_simulation)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    project.bla_applied = False
    project.bla_backup_dir = None

    latest_run = db.scalar(
        select(ReleaseRun).where(ReleaseRun.project_id == project_id).order_by(desc(ReleaseRun.created_at)).limit(1)
    )
    if latest_run:
        rows = db.scalars(select(ArtifactRecord).where(ArtifactRecord.run_id == latest_run.id)).all()
        for row in rows:
            if row.status == "applied":
                row.status = "restored"
    db.commit()

    return BlaActionResponse(
        status=res["status"],
        mode=res["mode"],
        project_id=project.id,
        bla_applied=False,
        affected_files=res["affected_files"],
        backup_directory=None,
        message=res["message"],
        artifacts=[],
    )
