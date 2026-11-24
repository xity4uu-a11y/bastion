from __future__ import annotations

import json
from pathlib import Path
import typer
from sqlalchemy import desc, select

from app.config import settings
from app.database import SessionLocal, init_db
from app.models import ArtifactRecord, CoverageLedgerEntry, Finding, GateExecution, Project, ReleaseRun
from app.services.certificate import (
    build_certificate_payload,
    render_certificate_markdown,
    render_certificate_pdf,
    verify_certificate_document,
)
from app.services.gate3_bla import run_bla_apply, run_bla_restore
from app.services.orchestrator import create_release_run, execute_release_run
from app.services.sarif import build_sarif_report
from app.services.toolchain import inspect_toolchain

EXIT_PASSED = 0
EXIT_GATE1_BLOCKED = 10
EXIT_GATE2_BLOCKED = 20
EXIT_GATE3_BLOCKED = 30

cli = typer.Typer(
    name="bastion",
    help=f"Bastion v{settings.version} CLI — 3-Stage Pre-Ship Security & Anti-AI-Reverse-Engineering Release Gate",
    add_completion=False,
)


def compute_gate_exit_code(gates: list[GateExecution], run_status: str) -> int:
    by_num = {g.gate_number: g for g in gates}
    if by_num.get(1) and by_num[1].status == "failed":
        return EXIT_GATE1_BLOCKED
    if by_num.get(2) and by_num[2].status == "failed":
        return EXIT_GATE2_BLOCKED
    if by_num.get(3) and by_num[3].status == "failed":
        return EXIT_GATE3_BLOCKED
    if run_status == "passed":
        return EXIT_PASSED
    return 1


@cli.command()
def doctor(as_json: bool = typer.Option(False, "--json", help="Emit JSON output")) -> None:
    """Check installation status of external scanners, Cloudflare Skill, BLA, and Ed25519 keys."""
    status = inspect_toolchain()
    if as_json:
        typer.echo(status.model_dump_json(indent=2))
        return
    typer.echo(f"Bastion v{settings.version} Toolchain Status")
    typer.echo("-" * 68)
    for tool in (status.trufflehog, status.gitleaks, status.cloudflare_skill, status.bla, status.node, status.git):
        state = "LIVE" if tool.mode == "live" else "FALLBACK"
        typer.echo(f"{tool.name:<34} [{state:<8}] {tool.version or 'not installed'}")
    typer.echo("-" * 68)
    typer.echo(f"Ed25519 Signing Key Fingerprint : {status.ed25519_key_fingerprint}")
    typer.echo(f"Ed25519 Public Key Path         : {status.ed25519_public_key_path}")


@cli.command()
def run(
    target: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True, help="Target local repository or build directory"),
    name: str | None = typer.Option(None, "--name", help="Project name override"),
    scanner: str = typer.Option("auto", "--scanner", help="Gate 1 secret scanner: auto|trufflehog|gitleaks"),
    intensity: str = typer.Option("balanced", "--intensity", help="BLA intensity: stealth|balanced|maximum|bankrupt"),
    profile: str = typer.Option("standard", "--profile", help="Cloudflare audit profile: quick|standard|deep"),
    scope: str = typer.Option("diff", "--scope", help="Gate 2 audit scope: diff (default for PR/CI) | full"),
    base: str = typer.Option("", "--base", help="Git base ref for diff scope (e.g. origin/main)"),
    max_budget_usd: float = typer.Option(1.50, "--max-budget-usd", help="Max estimated USD spend cap for Gate 2 LLM calls"),
    smoke_cmd: str = typer.Option("", "--smoke-cmd", help="Optional post-BLA smoke test command run against .bla-hardened/"),
    continue_on_gate1: bool = typer.Option(False, "--continue-on-gate1", help="Continue to Gates 2-3 even if Gate 1 fails"),
    simulate: bool = typer.Option(False, "--simulate", help="Force fallback simulation mode"),
    cert_out: Path | None = typer.Option(None, "--cert-out", help="Optional path to export Ed25519-signed certificate (.json|.md|.pdf)"),
    sarif_out: Path | None = typer.Option(None, "--sarif-out", help="Optional path to export SARIF v2.1.0 report"),
) -> None:
    """Run all 3 Bastion release gates sequentially with strict CI/CD exit codes (0/10/20/30)."""
    init_db()
    resolved = str(target.resolve())
    with SessionLocal() as db:
        project = db.scalar(select(Project).where(Project.path == resolved))
        if not project:
            project = Project(
                name=name or target.name,
                path=resolved,
                default_secret_scanner=scanner,
                default_bla_intensity=intensity,
                default_audit_profile=profile,
                smoke_test_cmd=smoke_cmd.strip(),
            )
            db.add(project)
            db.commit()
            db.refresh(project)
        release_run = create_release_run(
            db,
            project,
            bla_intensity=intensity,
            audit_profile=profile,
            secret_scanner=scanner,
            audit_scope=scope,
            base_ref=base,
            max_budget_usd=max_budget_usd,
            smoke_test_cmd=smoke_cmd if smoke_cmd.strip() else project.smoke_test_cmd,
        )
        run_id = release_run.id

    typer.echo(
        f"Running Bastion v{settings.version} Release Gate on {resolved} "
        f"(run_id={run_id}, scope={scope}, budget=${max_budget_usd:.2f})..."
    )
    execute_release_run(run_id, stop_on_gate1_fail=not continue_on_gate1, force_simulation=simulate)

    with SessionLocal() as db:
        final_run = db.get(ReleaseRun, run_id)
        project = db.get(Project, final_run.project_id) if final_run else None
        gates = list(
            db.scalars(select(GateExecution).where(GateExecution.run_id == run_id).order_by(GateExecution.gate_number)).all()
        )
        findings = list(db.scalars(select(Finding).where(Finding.run_id == run_id)).all())
        artifacts = list(db.scalars(select(ArtifactRecord).where(ArtifactRecord.run_id == run_id)).all())
        ledger = list(
            db.scalars(select(CoverageLedgerEntry).where(CoverageLedgerEntry.project_id == project.id)).all()
        ) if project else []

        exit_code = compute_gate_exit_code(gates, final_run.status if final_run else "failed")
        typer.echo("")
        typer.echo(
            f"Result: {(final_run.status if final_run else 'failed').upper()} | "
            f"Readiness Score: {(final_run.readiness_score if final_run else 0)}/100 | "
            f"Exit Code: {exit_code}"
        )
        for g in gates:
            typer.echo(f"  Gate {g.gate_number} ({g.name:<24}) [{g.status.upper():<7}] ({g.engine}/{g.mode}) - {g.summary}")

        if sarif_out and project:
            sarif_doc = build_sarif_report(findings, project_name=project.name)
            sarif_out.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")
            typer.echo(f"Exported SARIF v2.1.0 report -> {sarif_out}")

        if cert_out and final_run and project:
            cert = build_certificate_payload(project, final_run, gates, findings, artifacts, ledger)
            if cert_out.suffix.lower() == ".md":
                cert_out.write_text(render_certificate_markdown(cert), encoding="utf-8")
            elif cert_out.suffix.lower() == ".pdf":
                cert_out.write_bytes(render_certificate_pdf(cert))
            else:
                cert_out.write_text(json.dumps(cert, indent=2), encoding="utf-8")
            typer.echo(f"Exported Ed25519-signed Release Certificate -> {cert_out} (key={cert['integrity']['key_fingerprint']})")

        if exit_code != 0:
            raise typer.Exit(code=exit_code)


@cli.command("verify")
def verify_cmd(
    certificate: Path = typer.Argument(..., exists=True, dir_okay=False, resolve_path=True, help="Path to signed certificate JSON file"),
    pubkey: Path | None = typer.Option(None, "--pubkey", exists=True, dir_okay=False, resolve_path=True, help="Path to trusted Ed25519 public key PEM"),
    as_json: bool = typer.Option(False, "--json", help="Emit structured JSON verification output"),
) -> None:
    """Cryptographically verify an Ed25519-signed Bastion Release Certificate for tampering or expiry."""
    try:
        doc = json.loads(certificate.read_text(encoding="utf-8"))
    except Exception as exc:
        typer.echo(f"INVALID: Could not parse certificate JSON: {exc}", err=True)
        raise typer.Exit(code=1)

    pub_pem = pubkey.read_text(encoding="utf-8") if pubkey else None
    result = verify_certificate_document(doc, public_key_pem=pub_pem)

    if as_json:
        typer.echo(json.dumps(result, indent=2))
    else:
        state = "VALID" if result["valid"] else result["status"].upper()
        typer.echo(f"Certificate Verification : {state}")
        typer.echo(f"Certificate ID           : {result.get('certificate_id') or 'N/A'}")
        typer.echo(f"Release Decision         : {result.get('release_decision') or 'N/A'}")
        typer.echo(f"Algorithm                : {result.get('algorithm')}")
        typer.echo(f"Key Fingerprint          : {result.get('key_fingerprint') or 'N/A'}")
        typer.echo(f"Expires At               : {result.get('expires_at') or 'N/A'}")
        for err in result.get("errors", []):
            typer.echo(f"  ERROR: {err}", err=True)
        for warn in result.get("warnings", []):
            typer.echo(f"  NOTE : {warn}")

    if not result["valid"]:
        raise typer.Exit(code=1)


@cli.command("bla-apply")
def bla_apply_cmd(
    target: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True),
    intensity: str = typer.Option("balanced", "--intensity"),
) -> None:
    """Promote hardened BLA mirror artifacts into release output (--apply)."""
    res = run_bla_apply(target, intensity=intensity)
    typer.echo(json.dumps(res, indent=2))


@cli.command("bla-restore")
def bla_restore_cmd(
    target: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True),
) -> None:
    """Roll back promoted BLA artifacts to saved originals (--restore)."""
    res = run_bla_restore(target)
    typer.echo(json.dumps(res, indent=2))


@cli.command("history")
def history_cmd(limit: int = typer.Option(10, "--limit")) -> None:
    """Show recent Bastion release gate runs from SQLite."""
    init_db()
    with SessionLocal() as db:
        runs = db.scalars(select(ReleaseRun).order_by(desc(ReleaseRun.created_at)).limit(limit)).all()
        if not runs:
            typer.echo("No runs recorded yet.")
            return
        for r in runs:
            proj = db.get(Project, r.project_id)
            typer.echo(
                f"#{r.run_number:<3} {r.id}  {(proj.name if proj else 'unknown'):<28}  "
                f"{r.status.upper():<8}  scope={r.audit_scope:<4}  score={r.readiness_score}/100"
            )


def cli_main() -> None:
    cli()


if __name__ == "__main__":
    cli_main()
