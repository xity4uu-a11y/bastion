from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.config import settings
from app.models import ArtifactRecord, CoverageLedgerEntry, Finding, GateExecution, Project, ReleaseRun
from app.services.keys import ensure_ed25519_keypair, sign_ed25519, verify_ed25519
from app.services.vault import scrub_secrets


def _canonical_bytes(body: dict[str, Any]) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _scrub_obj(value: Any) -> Any:
    if isinstance(value, str):
        return scrub_secrets(value)
    if isinstance(value, list):
        return [_scrub_obj(item) for item in value]
    if isinstance(value, dict):
        return {k: _scrub_obj(v) for k, v in value.items()}
    return value


def _extract_gate_meta(gates: list[GateExecution], gate_number: int) -> dict[str, Any]:
    g = next((item for item in gates if item.gate_number == gate_number), None)
    if not g:
        return {}
    try:
        data = json.loads(g.metadata_json or "{}")
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}


def _extract_gate2_badge(gates: list[GateExecution]) -> tuple[str, str]:
    g2 = next((g for g in gates if g.gate_number == 2), None)
    if not g2:
        return "not_run", "Gate 2 Not Executed"
    meta = json.loads(g2.metadata_json or "{}")
    badge = str(meta.get("engine_badge") or "")
    if badge:
        return g2.mode, badge
    if g2.mode == "live_llm":
        return "live_llm", "Multi-Agent LLM (Hunter + Verifier)"
    return "static_heuristic", "Static Heuristic Fallback (No LLM)"


def build_certificate_payload(
    project: Project,
    run: ReleaseRun,
    gates: list[GateExecution],
    findings: list[Finding],
    artifacts: list[ArtifactRecord],
    ledger_entries: list[CoverageLedgerEntry],
    keys_dir: Path | None = None,
    ttl_days: int | None = None,
) -> dict[str, Any]:
    all_passed = (
        run.status == "passed"
        and all(g.status in ("passed", "warn") for g in gates)
        and len(gates) == 3
    )
    now = dt.datetime.now(dt.timezone.utc)
    expires = now + dt.timedelta(days=ttl_days if ttl_days is not None else settings.certificate_ttl_days)

    unresolved_findings = [f for f in findings if not f.resolved]
    verified_secrets = [f for f in unresolved_findings if f.gate_number == 1 and f.verified]
    confirmed_vulns = [f for f in unresolved_findings if f.gate_number == 2 and f.verdict == "confirmed"]
    needs_val = [f for f in unresolved_findings if f.gate_number == 2 and f.verdict == "needs_validation"]
    hardening_notes = [f for f in unresolved_findings if f.gate_number == 2 and f.verdict == "hardening_note"]
    g2_mode, g2_badge = _extract_gate2_badge(gates)
    g2_meta = _extract_gate_meta(gates, 2)
    g3_meta = _extract_gate_meta(gates, 3)
    smoke_meta = g3_meta.get("smoke_test") if isinstance(g3_meta.get("smoke_test"), dict) else {}

    body: dict[str, Any] = _scrub_obj({
        "certificate_version": "2.1",
        "certificate_id": f"BST-{run.id.upper()}-R{run.run_number:03d}",
        "issuer": f"Bastion Local-First Release Gate v{settings.version}",
        "issued_at": now.isoformat(),
        "expires_at": expires.isoformat(),
        "release_decision": "APPROVED" if all_passed else "HOLD",
        "project": {
            "id": project.id,
            "name": project.name,
            "path": project.path,
            "git_branch": run.git_branch,
            "git_commit": run.git_commit,
            "git_dirty": run.git_dirty,
        },
        "run": {
            "id": run.id,
            "run_number": run.run_number,
            "status": run.status,
            "readiness_score": run.readiness_score,
            "secret_scanner": run.secret_scanner,
            "audit_profile": run.audit_profile,
            "audit_scope": getattr(run, "audit_scope", "full"),
            "base_ref": getattr(run, "base_ref", "") or None,
            "max_budget_usd": getattr(run, "max_budget_usd", settings.default_max_budget_usd),
            "gate2_audit_mode": g2_mode,
            "gate2_engine_badge": g2_badge,
            "gate2_estimated_cost_usd": g2_meta.get("estimated_cost_usd", 0.0),
            "bla_intensity": run.bla_intensity,
            "gate3_smoke_status": smoke_meta.get("status", "skipped"),
            "simulation_used": run.simulation_used,
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        },
        "gates": [
            {
                "gate_number": g.gate_number,
                "name": g.name,
                "engine": g.engine,
                "status": g.status,
                "mode": g.mode,
                "engine_badge": json.loads(g.metadata_json or "{}").get("engine_badge", ""),
                "findings_count": g.findings_count,
                "blocking_count": g.blocking_count,
                "duration_ms": g.duration_ms,
                "summary": g.summary,
            }
            for g in sorted(gates, key=lambda x: x.gate_number)
        ],
        "security_summary": {
            "verified_live_secrets": len(verified_secrets),
            "total_secret_findings": len([f for f in findings if f.gate_number == 1]),
            "confirmed_vulnerabilities": len(confirmed_vulns),
            "needs_validation": len(needs_val),
            "hardening_notes": len(hardening_notes),
            "resolved_findings": len([f for f in findings if f.resolved]),
            "coverage_ledger_units": len(ledger_entries),
            "covered_units": len([e for e in ledger_entries if e.status in ("covered", "candidate")]),
            "deferred_units": len([e for e in ledger_entries if e.status == "deferred"]),
        },
        "artifact_hardening": {
            "total_artifacts": len(artifacts),
            "verified_artifacts": len([a for a in artifacts if a.verified]),
            "bla_applied_to_release": project.bla_applied,
            "smoke_test_status": smoke_meta.get("status", "skipped"),
            "average_defense_score": round(
                sum(a.defense_score for a in artifacts) / len(artifacts), 1
            ) if artifacts else 0.0,
            "artifacts": [
                {
                    "relative_path": a.relative_path,
                    "format": a.artifact_format,
                    "status": a.status,
                    "intensity": a.intensity,
                    "defense_score": a.defense_score,
                    "token_amplification": a.token_amplification,
                    "verified": a.verified,
                }
                for a in artifacts
            ],
        },
    })

    canonical = _canonical_bytes(body)
    digest_sha256 = hashlib.sha256(canonical).hexdigest()
    signature_b64, key_info = sign_ed25519(canonical, keys_dir=keys_dir)

    return {
        "certificate": body,
        "integrity": {
            "algorithm": "Ed25519",
            "key_fingerprint": key_info.key_fingerprint,
            "digest_sha256": digest_sha256,
            "signature": signature_b64,
            "public_key_pem": key_info.public_key_pem,
        },
    }


def verify_certificate_document(
    doc: dict[str, Any],
    public_key_pem: str | None = None,
    keys_dir: Path | None = None,
    now_utc: dt.datetime | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []

    if not isinstance(doc, dict) or "certificate" not in doc or "integrity" not in doc:
        return {
            "valid": False,
            "status": "invalid_format",
            "tampered": True,
            "expired": False,
            "signature_valid": False,
            "signer_matched": False,
            "algorithm": "unknown",
            "errors": ["Certificate JSON must contain top-level 'certificate' and 'integrity' objects."],
            "warnings": [],
        }

    body = doc.get("certificate")
    integrity = doc.get("integrity")
    if not isinstance(body, dict) or not isinstance(integrity, dict):
        return {
            "valid": False,
            "status": "invalid_format",
            "tampered": True,
            "expired": False,
            "signature_valid": False,
            "signer_matched": False,
            "algorithm": "unknown",
            "errors": ["Malformed 'certificate' or 'integrity' payload."],
            "warnings": [],
        }

    algorithm = str(integrity.get("algorithm") or "")
    claimed_digest = str(integrity.get("digest_sha256") or "")
    claimed_fp = str(integrity.get("key_fingerprint") or "")
    signature_b64 = str(integrity.get("signature") or "")

    if algorithm != "Ed25519":
        errors.append(f"Unsupported or legacy signing algorithm '{algorithm}'; expected 'Ed25519'.")

    # 1. Recompute canonical SHA-256 digest to detect payload tampering
    canonical = _canonical_bytes(body)
    actual_digest = hashlib.sha256(canonical).hexdigest()
    tampered = actual_digest != claimed_digest
    if tampered:
        errors.append("SHA-256 digest mismatch: certificate payload has been modified after signing.")

    # 2. Resolve verification public key (explicit pubkey -> local host pubkey -> embedded pubkey with warning)
    effective_pubkey = (public_key_pem or "").strip()
    if not effective_pubkey:
        try:
            local_info = ensure_ed25519_keypair(keys_dir=keys_dir)
            effective_pubkey = local_info.public_key_pem
            warnings.append(f"Verified using local host key ({local_info.key_fingerprint}).")
        except Exception:
            effective_pubkey = str(integrity.get("public_key_pem") or "").strip()
            warnings.append("No external public key supplied; verified against embedded public key.")

    sig_valid, actual_fp, sig_msg = verify_ed25519(canonical, signature_b64, effective_pubkey)
    if not sig_valid:
        errors.append(sig_msg)
        tampered = True

    signer_matched = bool(actual_fp) and (not claimed_fp or actual_fp == claimed_fp)
    if claimed_fp and actual_fp and actual_fp != claimed_fp:
        errors.append(
            f"Signer key fingerprint mismatch: certificate claims {claimed_fp}, trusted key is {actual_fp}."
        )

    # 3. Check expiry window
    expired = False
    expires_raw = body.get("expires_at")
    check_now = now_utc or dt.datetime.now(dt.timezone.utc)
    if isinstance(expires_raw, str) and expires_raw.strip():
        try:
            exp_dt = dt.datetime.fromisoformat(expires_raw.replace("Z", "+00:00"))
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=dt.timezone.utc)
            if check_now > exp_dt:
                expired = True
                errors.append(f"Certificate expired at {exp_dt.isoformat()}.")
        except ValueError:
            errors.append(f"Invalid expires_at timestamp: {expires_raw}")
    else:
        warnings.append("Certificate does not include an expires_at timestamp.")

    valid = len(errors) == 0 and sig_valid and signer_matched and not tampered and not expired
    if valid:
        status = "valid"
    elif tampered and not sig_valid:
        status = "tampered"
    elif not sig_valid or not signer_matched:
        status = "invalid_signature"
    elif expired:
        status = "expired"
    else:
        status = "tampered"

    return {
        "valid": valid,
        "status": status,
        "tampered": tampered,
        "expired": expired,
        "signature_valid": sig_valid,
        "signer_matched": signer_matched,
        "algorithm": algorithm or "Ed25519",
        "key_fingerprint": claimed_fp or None,
        "expected_key_fingerprint": actual_fp or None,
        "certificate_id": body.get("certificate_id"),
        "release_decision": body.get("release_decision"),
        "issued_at": body.get("issued_at"),
        "expires_at": body.get("expires_at"),
        "errors": errors,
        "warnings": warnings,
    }


def render_certificate_markdown(signed_cert: dict[str, Any]) -> str:
    cert = signed_cert["certificate"]
    integrity = signed_cert["integrity"]
    proj = cert["project"]
    run = cert["run"]
    sec = cert["security_summary"]
    art = cert["artifact_hardening"]

    lines = [
        "# Bastion Pre-Ship Release Certificate",
        "",
        f"- **Certificate ID:** `{cert['certificate_id']}`",
        f"- **Release Decision:** `{cert['release_decision']}`",
        f"- **Readiness Score:** `{run['readiness_score']} / 100`",
        f"- **Issued At:** `{cert['issued_at']}`",
        f"- **Expires At:** `{cert.get('expires_at', 'N/A')}`",
        f"- **Project:** {proj['name']} (`{proj['path']}`)",
        f"- **Git Ref:** `{proj['git_branch'] or 'N/A'}` @ `{proj['git_commit'] or 'uncommitted'}` (dirty: `{proj['git_dirty']}`)",
        f"- **Gate 2 Analysis Engine:** `{run.get('gate2_engine_badge', 'Static Heuristic Fallback (No LLM)')}`",
        f"- **Gate 2 Scope / Budget:** `{run.get('audit_scope', 'full')}` (cap `${run.get('max_budget_usd', 1.50):.2f}`, est. spend `${run.get('gate2_estimated_cost_usd', 0.0):.4f}`)",
        f"- **Gate 3 Post-BLA Smoke Verification:** `{run.get('gate3_smoke_status', 'skipped')}`",
        "",
        "## 3-Stage Release Gate Results",
        "",
        "| Gate | Stage | Engine | Mode | Status | Findings | Blocking | Duration |",
        "| --- | --- | --- | --- | --- | ---: | ---: | ---: |",
    ]
    for g in cert["gates"]:
        lines.append(
            f"| {g['gate_number']} | {g['name']} | `{g['engine']}` | `{g['mode']}` | **{g['status'].upper()}** | "
            f"{g['findings_count']} | {g['blocking_count']} | {g['duration_ms']} ms |"
        )

    lines.extend([
        "",
        "## Security Posture Summary",
        "",
        f"- Verified live secrets (Gate 1): **{sec['verified_live_secrets']}**",
        f"- Confirmed vulnerabilities (Gate 2): **{sec['confirmed_vulnerabilities']}**",
        f"- Needs Validation leads (Gate 2): **{sec['needs_validation']}**",
        f"- Hardening notes (Gate 2): **{sec['hardening_notes']}**",
        f"- Resolved in triage: **{sec['resolved_findings']}**",
        f"- Additive coverage ledger units: **{sec['covered_units']} / {sec['coverage_ledger_units']}**",
        "",
        "## Anti-REA Artifact Hardening (BLA)",
        "",
        f"- Discovered build artifacts: **{art['total_artifacts']}**",
        f"- Verified hardened mirrors: **{art['verified_artifacts']}**",
        f"- Average defense score: **{art['average_defense_score']} / 100**",
        f"- Promoted to release (`--apply`): **{art['bla_applied_to_release']}**",
        "",
    ])

    if art["artifacts"]:
        lines.extend([
            "| Artifact | Format | Status | Defense Score | Token Amplification | Verified |",
            "| --- | --- | --- | ---: | ---: | --- |",
        ])
        for item in art["artifacts"]:
            lines.append(
                f"| `{item['relative_path']}` | `{item['format']}` | `{item['status']}` | "
                f"{item['defense_score']} | {item['token_amplification']}x | {item['verified']} |"
            )
        lines.append("")

    lines.extend([
        "## Asymmetric Cryptographic Attestation",
        "",
        f"- **Algorithm:** `{integrity['algorithm']}`",
        f"- **Key Fingerprint:** `{integrity['key_fingerprint']}`",
        f"- **SHA-256 Digest:** `{integrity['digest_sha256']}`",
        f"- **Ed25519 Signature (Base64):** `{integrity['signature']}`",
        "",
        f"_Verify offline with: `bastion verify {cert['certificate_id']}.json --pubkey ~/.bastion/keys/ed25519_public.pem`_",
    ])
    return scrub_secrets("\n".join(lines))


def render_certificate_pdf(signed_cert: dict[str, Any]) -> bytes:
    cert = signed_cert["certificate"]
    integrity = signed_cert["integrity"]
    proj = cert["project"]
    run = cert["run"]
    sec = cert["security_summary"]
    art = cert["artifact_hardening"]

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        title=f"Bastion Release Certificate {cert['certificate_id']}",
    )

    styles = getSampleStyleSheet()
    ink = colors.HexColor("#1D1D1F")
    muted = colors.HexColor("#6E6E73")
    hairline = colors.HexColor("#E5E5EA")
    surface = colors.HexColor("#F5F5F7")
    decision_color = colors.HexColor("#1F8A4C") if cert["release_decision"] == "APPROVED" else colors.HexColor("#C9342D")

    title_style = ParagraphStyle("BastionTitle", parent=styles["Heading1"], fontName="Helvetica-Bold", fontSize=18, textColor=ink, spaceAfter=4)
    subtitle_style = ParagraphStyle("BastionSub", parent=styles["Normal"], fontName="Helvetica", fontSize=9.2, textColor=muted, spaceAfter=12)
    h2_style = ParagraphStyle("BastionH2", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=11.5, textColor=ink, spaceBefore=13, spaceAfter=6)
    body_style = ParagraphStyle("BastionBody", parent=styles["Normal"], fontName="Helvetica", fontSize=8.8, textColor=ink, leading=13)
    mono_style = ParagraphStyle("BastionMono", parent=styles["Normal"], fontName="Courier", fontSize=7.8, textColor=muted, leading=10.5)

    elements: list[Any] = [
        Paragraph("BASTION RELEASE CERTIFICATE", title_style),
        Paragraph(
            f"Certificate ID: {cert['certificate_id']}  |  Issued: {cert['issued_at']}  |  "
            f"Expires: {cert.get('expires_at', 'N/A')}  |  Decision: "
            f"<font color='{decision_color.hexval()}'><b>{cert['release_decision']}</b></font>",
            subtitle_style,
        ),
        HRFlowable(width="100%", thickness=0.75, color=hairline),
        Spacer(1, 10),
    ]

    meta_rows = [
        ["Project", proj["name"], "Readiness Score", f"{run['readiness_score']} / 100"],
        ["Repository Path", proj["path"][-54:], "Run Number", f"#{run['run_number']} ({run['status'].upper()})"],
        ["Git Branch / Commit", f"{proj['git_branch'] or 'N/A'} @ {proj['git_commit'] or 'N/A'}", "Audit Profile / BLA", f"{run['audit_profile']} / {run['bla_intensity']}"],
        ["Gate 2 Engine", str(run.get("gate2_engine_badge", "Static Heuristic Fallback (No LLM)"))[:42], "Signing Key", str(integrity["key_fingerprint"])],
    ]
    meta_table = Table(meta_rows, colWidths=[1.35 * inch, 2.45 * inch, 1.25 * inch, 1.95 * inch])
    meta_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), surface),
            ("BACKGROUND", (2, 0), (2, -1), surface),
            ("TEXTCOLOR", (0, 0), (-1, -1), ink),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
            ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
            ("FONTNAME", (3, 0), (3, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.2),
            ("GRID", (0, 0), (-1, -1), 0.5, hairline),
            ("PADDING", (0, 0), (-1, -1), 5.5),
        ])
    )
    elements.append(meta_table)

    elements.append(Paragraph("Three-Stage Gate Evaluation", h2_style))
    gate_rows = [["Gate", "Stage", "Engine", "Mode", "Status", "Findings", "Blocking", "Duration"]]
    for g in cert["gates"]:
        gate_rows.append([
            str(g["gate_number"]),
            g["name"],
            g["engine"],
            g["mode"],
            g["status"].upper(),
            str(g["findings_count"]),
            str(g["blocking_count"]),
            f"{g['duration_ms']} ms",
        ])
    gate_table = Table(gate_rows, colWidths=[0.42 * inch, 1.52 * inch, 1.12 * inch, 0.92 * inch, 0.72 * inch, 0.72 * inch, 0.72 * inch, 0.86 * inch])
    gate_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), surface),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.8),
            ("TEXTCOLOR", (0, 0), (-1, -1), ink),
            ("GRID", (0, 0), (-1, -1), 0.5, hairline),
            ("PADDING", (0, 0), (-1, -1), 4.8),
        ])
    )
    elements.append(gate_table)

    elements.append(Paragraph("Security & Coverage Summary", h2_style))
    elements.append(
        Paragraph(
            f"Verified Live Secrets: <b>{sec['verified_live_secrets']}</b>  |  "
            f"Confirmed Vulnerabilities: <b>{sec['confirmed_vulnerabilities']}</b>  |  "
            f"Needs Validation: <b>{sec['needs_validation']}</b>  |  "
            f"Hardening Notes: <b>{sec['hardening_notes']}</b>  |  "
            f"Coverage Ledger Units: <b>{sec['covered_units']}/{sec['coverage_ledger_units']}</b>",
            body_style,
        )
    )

    elements.append(Paragraph("Anti-REA Artifact Shield (BLA)", h2_style))
    elements.append(
        Paragraph(
            f"Discovered Artifacts: <b>{art['total_artifacts']}</b>  |  "
            f"Verified Mirrors: <b>{art['verified_artifacts']}</b>  |  "
            f"Average Defense Score: <b>{art['average_defense_score']}/100</b>  |  "
            f"Applied to Release: <b>{'YES' if art['bla_applied_to_release'] else 'NO (staged in .bla-hardened)'}</b>",
            body_style,
        )
    )

    if art["artifacts"]:
        elements.append(Spacer(1, 6))
        art_rows = [["Artifact", "Format", "Status", "Defense Score", "Token Amp.", "Verified"]]
        for item in art["artifacts"][:15]:
            art_rows.append([
                item["relative_path"][-45:],
                item["format"],
                item["status"],
                f"{item['defense_score']}/100",
                f"{item['token_amplification']}x",
                "Yes" if item["verified"] else "No",
            ])
        art_table = Table(art_rows, colWidths=[2.6 * inch, 1.0 * inch, 0.85 * inch, 0.95 * inch, 0.85 * inch, 0.75 * inch])
        art_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), surface),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 7.8),
                ("GRID", (0, 0), (-1, -1), 0.5, hairline),
                ("PADDING", (0, 0), (-1, -1), 4.5),
            ])
        )
        elements.append(art_table)

    elements.append(Paragraph("Asymmetric Cryptographic Attestation (Ed25519)", h2_style))
    elements.append(Paragraph(f"Algorithm: {integrity['algorithm']}", mono_style))
    elements.append(Paragraph(f"Key Fingerprint: {integrity['key_fingerprint']}", mono_style))
    elements.append(Paragraph(f"SHA-256 Digest: {integrity['digest_sha256']}", mono_style))
    elements.append(Paragraph(f"Signature (Base64): {integrity['signature']}", mono_style))

    doc.build(elements)
    return buffer.getvalue()
