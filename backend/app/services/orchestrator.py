from __future__ import annotations

import datetime as dt
import json
import threading
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal
from app.models import (
    ArtifactRecord,
    CoverageLedgerEntry,
    Finding,
    GateExecution,
    Project,
    ReleaseRun,
)
from app.services.event_bus import event_bus
from app.services.gate1_trufflehog import run_gate1_secret_scan
from app.services.gate2_cloudflare import run_gate2_cloudflare
from app.services.gate3_bla import run_gate3_bla
from app.services.llm_providers import get_effective_llm_config
from app.services.toolchain import get_git_metadata
from app.services.vault import scrub_secrets


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _compute_readiness_score(gates: list[GateExecution], findings: list[Finding], artifacts: list[ArtifactRecord]) -> int:
    score = 100
    g_map = {g.gate_number: g for g in gates}
    g1 = g_map.get(1)
    g2 = g_map.get(2)
    g3 = g_map.get(3)

    if g1:
        if g1.status == "failed":
            score -= 55
        elif g1.status == "warn":
            score -= 8
        elif g1.status in ("skipped", "aborted", "pending"):
            score -= 35

    if g2:
        if g2.status == "failed":
            score -= 35
        elif g2.status == "warn":
            score -= 10
        elif g2.status in ("skipped", "aborted", "pending"):
            score -= 30

    if g3:
        if g3.status == "failed":
            score -= 25
        elif g3.status == "warn":
            score -= 8
        elif g3.status in ("skipped", "aborted", "pending"):
            score -= 20

    unresolved_med = sum(1 for f in findings if not f.resolved and f.severity == "medium")
    score -= min(12, unresolved_med * 3)
    if artifacts:
        avg_def = sum(a.defense_score for a in artifacts) / len(artifacts)
        if avg_def < 70:
            score -= 5

    return max(0, min(100, int(round(score))))


def _gate_to_dict(g: GateExecution) -> dict[str, Any]:
    return {
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
        "started_at": g.started_at.isoformat() if g.started_at else None,
        "completed_at": g.completed_at.isoformat() if g.completed_at else None,
    }


def create_release_run(
    db: Session,
    project: Project,
    bla_intensity: str | None = None,
    audit_profile: str | None = None,
    secret_scanner: str | None = None,
    audit_scope: str | None = None,
    base_ref: str | None = None,
    max_budget_usd: float | None = None,
    smoke_test_cmd: str | None = None,
) -> ReleaseRun:
    max_num = db.scalar(
        select(func.max(ReleaseRun.run_number)).where(ReleaseRun.project_id == project.id)
    ) or 0
    _, commit, branch, dirty = get_git_metadata(Path(project.path))
    llm_cfg = get_effective_llm_config(db)
    chosen_scanner = secret_scanner or project.default_secret_scanner or llm_cfg.default_secret_scanner or "auto"
    chosen_scope = audit_scope or llm_cfg.default_audit_scope or "full"
    chosen_budget = float(max_budget_usd if max_budget_usd is not None else llm_cfg.default_max_budget_usd)
    chosen_smoke = smoke_test_cmd if smoke_test_cmd is not None else (project.smoke_test_cmd or "")

    run = ReleaseRun(
        project_id=project.id,
        run_number=int(max_num) + 1,
        status="queued",
        current_gate=0,
        readiness_score=0,
        git_commit=commit,
        git_branch=branch,
        git_dirty=dirty,
        secret_scanner=chosen_scanner,
        bla_intensity=bla_intensity or project.default_bla_intensity,
        audit_profile=audit_profile or project.default_audit_profile,
        audit_scope=chosen_scope if chosen_scope in ("diff", "full") else "full",
        base_ref=(base_ref or "").strip(),
        max_budget_usd=chosen_budget,
        smoke_test_cmd=chosen_smoke.strip(),
        simulation_used=False,
    )
    db.add(run)
    db.flush()

    out_dir = settings.runs_output_dir / f"{project.id}_run_{run.run_number}_{run.id}"
    out_dir.mkdir(parents=True, exist_ok=True)
    run.output_dir = str(out_dir)

    gate_specs = [
        (1, "Secret Quarantine", chosen_scanner if chosen_scanner != "auto" else "trufflehog"),
        (2, "Adversarial Source Audit", "cloudflare-audit"),
        (3, "Anti-REA Build Hardening", "bla"),
    ]
    for num, name, engine in gate_specs:
        db.add(
            GateExecution(
                run_id=run.id,
                gate_number=num,
                name=name,
                engine=engine,
                status="pending",
                mode="live",
            )
        )
    db.commit()
    db.refresh(run)
    return run


def execute_release_run(
    run_id: str,
    stop_on_gate1_fail: bool = True,
    force_simulation: bool = False,
) -> None:
    """Runs all 3 gates sequentially in a worker thread, streaming SSE events and persisting to SQLite."""
    event_bus.create_cancel_token(run_id)
    try:
        with SessionLocal() as db:
            run = db.get(ReleaseRun, run_id)
            if not run:
                return
            project = db.get(Project, run.project_id)
            if not project:
                return
            target_path = Path(project.path)
            out_dir = Path(run.output_dir or (settings.runs_output_dir / run.id))
            out_dir.mkdir(parents=True, exist_ok=True)
            llm_cfg = get_effective_llm_config(db)

            run.status = "running"
            run.started_at = _utcnow()
            run.current_gate = 1
            db.commit()

            event_bus.emit_run_update(run_id, {"run_id": run_id, "status": "running", "current_gate": 1})
            event_bus.emit_log(
                run_id,
                0,
                f"Bastion v{settings.version} Release Gate Run #{run.run_number} initiated for '{project.name}' ({target_path})",
                "info",
            )

            if not target_path.exists() or not target_path.is_dir():
                run.status = "failed"
                run.completed_at = _utcnow()
                db.commit()
                event_bus.emit_log(run_id, 0, f"Target directory does not exist: {target_path}", "error")
                event_bus.emit_complete(run_id, "failed", 0)
                return

            gates = db.scalars(
                select(GateExecution).where(GateExecution.run_id == run_id).order_by(GateExecution.gate_number)
            ).all()
            g1, g2, g3 = gates[0], gates[1], gates[2]

            sim_used = False
            all_findings: list[Finding] = []
            all_artifacts: list[ArtifactRecord] = []

            # ================================================================
            # GATE 1: PLUGGABLE SECRET QUARANTINE
            # ================================================================
            g1.status = "running"
            g1.started_at = _utcnow()
            db.commit()
            event_bus.emit_gate_update(run_id, _gate_to_dict(g1))

            g1_res = run_gate1_secret_scan(
                run_id,
                target_path,
                scanner_preference=run.secret_scanner,
                force_simulation=force_simulation,
            )
            if g1_res.mode == "simulation":
                sim_used = True

            for item in g1_res.findings:
                row = Finding(
                    run_id=run_id,
                    project_id=project.id,
                    gate_number=1,
                    source_engine=item.scanner_engine,
                    fingerprint=item.fingerprint,
                    title=f"{item.detector_name} secret detected",
                    description=item.description,
                    detector_or_class=item.detector_name,
                    file_path=item.file_path,
                    line_number=item.line_number,
                    verified=item.verified,
                    redacted_secret=item.redacted_secret,
                    git_commit=item.git_commit,
                    verdict="confirmed" if item.verified else "needs_validation",
                    severity="critical" if item.verified else "medium",
                    confidence="high" if item.verified else "medium",
                    root_cause=f"Credential matching {item.detector_name} exposed in {item.source_kind} ({item.scanner_engine}).",
                    remediation=f"Revoke and rotate this credential immediately. {item.rotation_guide}".strip(),
                    evidence_json=json.dumps([
                        {
                            "file": item.file_path,
                            "line": item.line_number,
                            "description": f"Redacted match: {item.redacted_secret}",
                        }
                    ]),
                )
                db.add(row)
                all_findings.append(row)

            g1.engine = g1_res.engine_name
            g1.status = g1_res.status
            g1.mode = g1_res.mode
            g1.duration_ms = g1_res.duration_ms
            g1.summary = g1_res.summary
            g1.findings_count = len(g1_res.findings)
            g1.blocking_count = sum(1 for f in g1_res.findings if f.verified)
            g1.metadata_json = json.dumps(g1_res.metadata)
            g1.completed_at = _utcnow()
            db.commit()
            event_bus.emit_gate_update(run_id, _gate_to_dict(g1))

            if g1_res.status == "aborted" or event_bus.is_cancelled(run_id):
                for g in (g2, g3):
                    g.status = "aborted"
                    g.summary = "Skipped due to operator abort."
                    event_bus.emit_gate_update(run_id, _gate_to_dict(g))
                run.status = "aborted"
                run.completed_at = _utcnow()
                run.simulation_used = sim_used
                run.readiness_score = _compute_readiness_score(gates, all_findings, all_artifacts)
                db.commit()
                event_bus.emit_complete(run_id, "aborted", run.readiness_score)
                return

            if g1_res.status == "failed" and stop_on_gate1_fail:
                event_bus.emit_log(
                    run_id,
                    0,
                    "Gate 1 quarantined verified secret(s). Halting downstream gates until secret is revoked and removed.",
                    "error",
                )
                for g in (g2, g3):
                    g.status = "skipped"
                    g.summary = "Skipped because Gate 1 failed on verified secrets."
                    event_bus.emit_gate_update(run_id, _gate_to_dict(g))
                run.status = "failed"
                run.completed_at = _utcnow()
                run.simulation_used = sim_used
                run.readiness_score = _compute_readiness_score(gates, all_findings, all_artifacts)
                db.commit()
                event_bus.emit_complete(run_id, "failed", run.readiness_score)
                return

            # ================================================================
            # GATE 2: CLOUDFLARE SECURITY AUDIT (Diff/Full Scope + Budget + LLM)
            # ================================================================
            run.current_gate = 2
            g2.status = "running"
            g2.started_at = _utcnow()
            db.commit()
            event_bus.emit_run_update(run_id, {"run_id": run_id, "status": "running", "current_gate": 2})
            event_bus.emit_gate_update(run_id, _gate_to_dict(g2))

            prior_ledger = db.scalars(
                select(CoverageLedgerEntry).where(CoverageLedgerEntry.project_id == project.id)
            ).all()

            g2_res = run_gate2_cloudflare(
                run_id=run_id,
                target_path=target_path,
                run_output_dir=out_dir,
                prior_ledger=list(prior_ledger),
                audit_profile=run.audit_profile,
                force_simulation=force_simulation,
                llm_config=llm_cfg,
                audit_scope=run.audit_scope or "full",
                base_ref=run.base_ref or "",
                max_budget_usd=run.max_budget_usd,
            )
            if g2_res.mode == "simulation":
                sim_used = True

            for item in g2_res.findings:
                row = Finding(
                    run_id=run_id,
                    project_id=project.id,
                    gate_number=2,
                    source_engine="cloudflare-audit",
                    fingerprint=item.fingerprint,
                    title=item.title,
                    description=item.description,
                    detector_or_class=item.attack_class,
                    file_path=item.file_path,
                    line_number=item.line_number,
                    verified=True if item.verdict == "confirmed" else None,
                    verdict=item.verdict,
                    severity=item.severity,
                    confidence=item.confidence,
                    hunter_agent_id=item.hunter_agent_id,
                    verifier_agent_id=item.verifier_agent_id,
                    root_cause=item.root_cause,
                    remediation=item.remediation,
                    fixed_code=item.fixed_code,
                    trace_json=json.dumps(item.trace),
                    evidence_json=json.dumps(item.evidence),
                    blockers_json=json.dumps(item.blockers),
                )
                db.add(row)
                all_findings.append(row)

            existing_map = {e.coverage_id: e for e in prior_ledger}
            for unit in g2_res.ledger_units:
                cid = unit["coverage_id"]
                checks = unit.get("local_checks") or []
                verifier_id = next(
                    (
                        c.get("agent_id")
                        for c in checks
                        if "verifier" in str(c.get("agent_id", "")).lower()
                    ),
                    None,
                )
                if cid in existing_map:
                    entry = existing_map[cid]
                    entry.last_run_id = run_id
                    entry.status = unit["status"]
                    entry.prior_status = unit["prior_status"]
                    entry.wave = unit["wave"]
                    entry.hunter_agent_id = unit["agent_id"]
                    entry.verifier_agent_id = verifier_id
                    entry.source_hash = g2_res.ledger_hashes.get(cid, "")
                    entry.unit_json = json.dumps(unit)
                else:
                    db.add(
                        CoverageLedgerEntry(
                            project_id=project.id,
                            last_run_id=run_id,
                            coverage_id=cid,
                            surface=unit["surface"],
                            boundary=unit["boundary"],
                            subsystem=unit["subsystem"],
                            attack_class=unit["attack_class"],
                            status=unit["status"],
                            prior_status=unit["prior_status"],
                            wave=unit["wave"],
                            hunter_agent_id=unit["agent_id"],
                            verifier_agent_id=verifier_id,
                            source_hash=g2_res.ledger_hashes.get(cid, ""),
                            unit_json=json.dumps(unit),
                        )
                    )

            g2.status = g2_res.status
            g2.mode = g2_res.mode
            g2.duration_ms = g2_res.duration_ms
            g2.summary = g2_res.summary
            g2.findings_count = len(g2_res.findings)
            g2.blocking_count = int(g2_res.metadata.get("confirmed_blocking", 0))
            g2.metadata_json = json.dumps(g2_res.metadata)
            g2.completed_at = _utcnow()
            db.commit()
            event_bus.emit_gate_update(run_id, _gate_to_dict(g2))

            if g2_res.status == "aborted" or event_bus.is_cancelled(run_id):
                g3.status = "aborted"
                g3.summary = "Skipped due to operator abort."
                event_bus.emit_gate_update(run_id, _gate_to_dict(g3))
                run.status = "aborted"
                run.completed_at = _utcnow()
                run.simulation_used = sim_used
                run.readiness_score = _compute_readiness_score(gates, all_findings, all_artifacts)
                db.commit()
                event_bus.emit_complete(run_id, "aborted", run.readiness_score)
                return

            # ================================================================
            # GATE 3: BLA ANTI-REA BUILD HARDENING + POST-BLA SMOKE TEST
            # ================================================================
            run.current_gate = 3
            g3.status = "running"
            g3.started_at = _utcnow()
            db.commit()
            event_bus.emit_run_update(run_id, {"run_id": run_id, "status": "running", "current_gate": 3})
            event_bus.emit_gate_update(run_id, _gate_to_dict(g3))

            g3_res = run_gate3_bla(
                run_id=run_id,
                target_path=target_path,
                intensity=run.bla_intensity,
                force_simulation=force_simulation,
                smoke_test_cmd=run.smoke_test_cmd or "",
            )
            if g3_res.mode == "simulation":
                sim_used = True

            for art in g3_res.artifacts:
                a_row = ArtifactRecord(
                    run_id=run_id,
                    project_id=project.id,
                    relative_path=art.relative_path,
                    artifact_format=art.artifact_format,
                    category=art.category,
                    input_bytes=art.input_bytes,
                    output_bytes=art.output_bytes,
                    mirror_path=art.mirror_path,
                    intensity=art.intensity,
                    status=art.status,
                    defense_score=art.defense_score,
                    token_amplification=art.token_amplification,
                    cost_amplification=art.cost_amplification,
                    before_exposure_score=art.before_exposure_score,
                    verified=art.verified,
                )
                db.add(a_row)
                all_artifacts.append(a_row)

            smoke_failed = bool(g3_res.smoke_test and g3_res.smoke_test.status in ("failed", "timeout"))
            g3.status = g3_res.status
            g3.mode = g3_res.mode
            g3.duration_ms = g3_res.duration_ms
            g3.summary = g3_res.summary
            g3.findings_count = len(g3_res.artifacts)
            g3.blocking_count = sum(1 for a in g3_res.artifacts if a.status == "failed") + (1 if smoke_failed else 0)
            g3.metadata_json = json.dumps(g3_res.metadata)
            g3.completed_at = _utcnow()

            if g3_res.status == "aborted" or event_bus.is_cancelled(run_id):
                final_status = "aborted"
            elif any(g.status == "failed" for g in gates):
                final_status = "failed"
            else:
                final_status = "passed"

            readiness = _compute_readiness_score(gates, all_findings, all_artifacts)
            run.status = final_status
            run.readiness_score = readiness
            run.simulation_used = sim_used
            run.completed_at = _utcnow()
            run.summary_json = json.dumps({
                "gate1": g1.status,
                "gate1_engine": g1.engine,
                "gate2": g2.status,
                "gate2_mode": g2.mode,
                "gate2_scope": run.audit_scope,
                "gate2_engine_badge": g2_res.engine_badge,
                "gate2_estimated_cost_usd": g2_res.metadata.get("estimated_cost_usd", 0.0),
                "gate3": g3.status,
                "gate3_smoke_status": g3_res.smoke_test.status if g3_res.smoke_test else "skipped",
                "total_findings": len(all_findings),
                "total_artifacts": len(all_artifacts),
            })
            db.commit()

            event_bus.emit_gate_update(run_id, _gate_to_dict(g3))
            event_bus.emit_log(
                run_id,
                0,
                f"Release Gate Run #{run.run_number} completed: status={final_status.upper()}, readiness={readiness}/100",
                "success" if final_status == "passed" else "error",
            )
            event_bus.emit_run_update(
                run_id,
                {"run_id": run_id, "status": final_status, "current_gate": 3, "readiness_score": readiness},
            )
            event_bus.emit_complete(run_id, final_status, readiness)
    except Exception as exc:
        safe_err = scrub_secrets(str(exc))
        with SessionLocal() as db:
            run = db.get(ReleaseRun, run_id)
            if run:
                run.status = "failed"
                run.completed_at = _utcnow()
                db.commit()
        event_bus.emit_log(run_id, 0, f"Unexpected pipeline error: {safe_err}", "error")
        event_bus.emit_complete(run_id, "failed", 0)
    finally:
        event_bus.cleanup_run(run_id)


def launch_release_run_async(
    run_id: str,
    stop_on_gate1_fail: bool = True,
    force_simulation: bool = False,
) -> threading.Thread:
    thread = threading.Thread(
        target=execute_release_run,
        args=(run_id, stop_on_gate1_fail, force_simulation),
        daemon=True,
        name=f"bastion-run-{run_id}",
    )
    thread.start()
    return thread
