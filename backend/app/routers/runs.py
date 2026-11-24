from __future__ import annotations

import asyncio
import json
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.database import SessionLocal, get_db
from app.models import (
    ArtifactRecord,
    AuditEvent,
    CoverageLedgerEntry,
    Finding,
    GateExecution,
    Project,
    ReleaseRun,
)
from app.schemas import AuditEventResponse, GateExecutionResponse, ReleaseRunResponse, RunCreate
from app.services.certificate import (
    build_certificate_payload,
    render_certificate_markdown,
    render_certificate_pdf,
)
from app.services.event_bus import event_bus, format_sse
from app.services.orchestrator import create_release_run, launch_release_run_async

router = APIRouter(prefix="/api/runs", tags=["runs"])


def _serialize_gate(g: GateExecution) -> GateExecutionResponse:
    return GateExecutionResponse(
        id=g.id,
        gate_number=g.gate_number,
        name=g.name,
        engine=g.engine,
        status=g.status,
        mode=g.mode,
        findings_count=g.findings_count,
        blocking_count=g.blocking_count,
        duration_ms=g.duration_ms,
        summary=g.summary,
        metadata=json.loads(g.metadata_json or "{}"),
        started_at=g.started_at,
        completed_at=g.completed_at,
    )


def _serialize_run(db: Session, run: ReleaseRun) -> ReleaseRunResponse:
    project = db.get(Project, run.project_id)
    gates = db.scalars(
        select(GateExecution).where(GateExecution.run_id == run.id).order_by(GateExecution.gate_number)
    ).all()
    return ReleaseRunResponse(
        id=run.id,
        project_id=run.project_id,
        project_name=project.name if project else "",
        run_number=run.run_number,
        status=run.status,
        current_gate=run.current_gate,
        readiness_score=run.readiness_score,
        git_commit=run.git_commit,
        git_branch=run.git_branch,
        git_dirty=run.git_dirty,
        secret_scanner=run.secret_scanner or "auto",
        bla_intensity=run.bla_intensity,
        audit_profile=run.audit_profile,
        audit_scope=run.audit_scope or "full",
        base_ref=run.base_ref or "",
        max_budget_usd=float(run.max_budget_usd if run.max_budget_usd is not None else 1.50),
        smoke_test_cmd=run.smoke_test_cmd or "",
        simulation_used=run.simulation_used,
        output_dir=run.output_dir,
        summary=json.loads(run.summary_json or "{}"),
        gates=[_serialize_gate(g) for g in gates],
        started_at=run.started_at,
        completed_at=run.completed_at,
        created_at=run.created_at,
    )


@router.get("", response_model=list[ReleaseRunResponse])
def list_runs(
    project_id: str | None = Query(default=None),
    limit: int = Query(default=30, ge=1, le=200),
    db: Session = Depends(get_db),
) -> list[ReleaseRunResponse]:
    stmt = select(ReleaseRun).order_by(desc(ReleaseRun.created_at)).limit(limit)
    if project_id:
        stmt = stmt.where(ReleaseRun.project_id == project_id)
    runs = db.scalars(stmt).all()
    return [_serialize_run(db, r) for r in runs]


@router.post("", response_model=ReleaseRunResponse, status_code=201)
def start_run(payload: RunCreate, db: Session = Depends(get_db)) -> ReleaseRunResponse:
    project = db.get(Project, payload.project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    run = create_release_run(
        db,
        project,
        bla_intensity=payload.bla_intensity,
        audit_profile=payload.audit_profile,
        secret_scanner=payload.secret_scanner,
        audit_scope=payload.audit_scope,
        base_ref=payload.base_ref,
        max_budget_usd=payload.max_budget_usd,
        smoke_test_cmd=payload.smoke_test_cmd,
    )
    launch_release_run_async(
        run.id,
        stop_on_gate1_fail=payload.stop_on_gate1_fail,
        force_simulation=payload.force_simulation,
    )
    return _serialize_run(db, run)


@router.get("/{run_id}", response_model=ReleaseRunResponse)
def get_run(run_id: str, db: Session = Depends(get_db)) -> ReleaseRunResponse:
    run = db.get(ReleaseRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return _serialize_run(db, run)


@router.get("/{run_id}/events", response_model=list[AuditEventResponse])
def get_run_events(run_id: str, db: Session = Depends(get_db)) -> list[AuditEventResponse]:
    run = db.get(ReleaseRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    events = db.scalars(select(AuditEvent).where(AuditEvent.run_id == run_id).order_by(AuditEvent.id)).all()
    return [
        AuditEventResponse(
            id=e.id,
            run_id=e.run_id,
            gate_number=e.gate_number,
            level=e.level,
            message=e.message,
            timestamp=e.timestamp,
        )
        for e in events
    ]


@router.post("/{run_id}/abort")
def abort_run(run_id: str, db: Session = Depends(get_db)) -> dict[str, object]:
    run = db.get(ReleaseRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    signalled = event_bus.cancel_run(run_id)
    if not signalled and run.status in ("queued", "running"):
        run.status = "aborted"
        db.commit()
    return {"run_id": run_id, "abort_requested": True}


@router.post("/{run_id}/retry", response_model=ReleaseRunResponse, status_code=201)
def retry_run(
    run_id: str,
    stop_on_gate1_fail: bool = True,
    db: Session = Depends(get_db),
) -> ReleaseRunResponse:
    prior = db.get(ReleaseRun, run_id)
    if not prior:
        raise HTTPException(status_code=404, detail="Run not found")
    project = db.get(Project, prior.project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    new_run = create_release_run(
        db,
        project,
        bla_intensity=prior.bla_intensity,
        audit_profile=prior.audit_profile,
        secret_scanner=prior.secret_scanner,
        audit_scope=prior.audit_scope,
        base_ref=prior.base_ref,
        max_budget_usd=prior.max_budget_usd,
        smoke_test_cmd=prior.smoke_test_cmd,
    )
    launch_release_run_async(new_run.id, stop_on_gate1_fail=stop_on_gate1_fail)
    return _serialize_run(db, new_run)


@router.get("/{run_id}/stream")
async def stream_run_logs(run_id: str) -> StreamingResponse:
    with SessionLocal() as db:
        run = db.get(ReleaseRun, run_id)
        if not run:
            raise HTTPException(status_code=404, detail="Run not found")

    async def event_generator():
        sub = event_bus.subscribe(run_id)
        _, queue = sub
        seen_ids: set[int] = set()
        try:
            with SessionLocal() as db:
                run_row = db.get(ReleaseRun, run_id)
                history = db.scalars(
                    select(AuditEvent).where(AuditEvent.run_id == run_id).order_by(AuditEvent.id)
                ).all()
                gates = db.scalars(
                    select(GateExecution).where(GateExecution.run_id == run_id).order_by(GateExecution.gate_number)
                ).all()
                for ev in history:
                    seen_ids.add(ev.id)
                    yield format_sse(
                        "log",
                        {
                            "id": ev.id,
                            "run_id": ev.run_id,
                            "gate_number": ev.gate_number,
                            "level": ev.level,
                            "message": ev.message,
                            "timestamp": ev.timestamp.isoformat(),
                        },
                    )
                for g in gates:
                    yield format_sse(
                        "gate_update",
                        {
                            "id": g.id,
                            "gate_number": g.gate_number,
                            "name": g.name,
                            "engine": g.engine,
                            "status": g.status,
                            "mode": g.mode,
                            "findings_count": g.findings_count,
                            "blocking_count": g.blocking_count,
                            "duration_ms": g.duration_ms,
                            "summary": g.summary,
                            "metadata": json.loads(g.metadata_json or "{}"),
                        },
                    )
                if run_row and run_row.status in ("passed", "failed", "aborted"):
                    yield format_sse(
                        "complete",
                        {
                            "run_id": run_id,
                            "status": run_row.status,
                            "readiness_score": run_row.readiness_score,
                        },
                    )
                    return

            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=12.0)
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
                    with SessionLocal() as db:
                        r = db.get(ReleaseRun, run_id)
                        if r and r.status in ("passed", "failed", "aborted"):
                            yield format_sse(
                                "complete",
                                {
                                    "run_id": run_id,
                                    "status": r.status,
                                    "readiness_score": r.readiness_score,
                                },
                            )
                            return
                    continue

                ev_name = msg["event"]
                ev_data = msg["data"]
                if ev_name == "log" and ev_data.get("id") in seen_ids:
                    continue
                if ev_name == "log" and ev_data.get("id"):
                    seen_ids.add(ev_data["id"])
                yield format_sse(ev_name, ev_data)
                if ev_name == "complete":
                    return
        finally:
            event_bus.unsubscribe(run_id, sub)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/{run_id}/certificate")
def export_release_certificate(
    run_id: str,
    format: str = Query(default="json", pattern="^(json|md|pdf)$"),
    db: Session = Depends(get_db),
) -> Response:
    run = db.get(ReleaseRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    project = db.get(Project, run.project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    gates = db.scalars(
        select(GateExecution).where(GateExecution.run_id == run_id).order_by(GateExecution.gate_number)
    ).all()
    findings = db.scalars(select(Finding).where(Finding.run_id == run_id)).all()
    artifacts = db.scalars(select(ArtifactRecord).where(ArtifactRecord.run_id == run_id)).all()
    ledger = db.scalars(select(CoverageLedgerEntry).where(CoverageLedgerEntry.project_id == project.id)).all()

    signed_cert = build_certificate_payload(project, run, list(gates), list(findings), list(artifacts), list(ledger))
    cert_id = signed_cert["certificate"]["certificate_id"]

    if format == "json":
        return JSONResponse(
            content=signed_cert,
            headers={"Content-Disposition": f'attachment; filename="{cert_id}.json"'},
        )
    if format == "md":
        md = render_certificate_markdown(signed_cert)
        return PlainTextResponse(
            content=md,
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{cert_id}.md"'},
        )
    pdf_bytes = render_certificate_pdf(signed_cert)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{cert_id}.pdf"'},
    )
