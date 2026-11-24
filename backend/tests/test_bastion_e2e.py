from __future__ import annotations

import copy
import datetime as dt
import json
import os
import subprocess
import time
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from app.cli import cli, compute_gate_exit_code
from app.config import PROJECT_ROOT, settings
from app.database import SessionLocal
from app.main import app
from app.models import AppSetting, GateExecution, Project
from app.services.certificate import verify_certificate_document
from app.services.gate2_cloudflare import STATIC_FALLBACK_BADGE, run_gate2_cloudflare
from app.services.gate3_bla import Gate3Result, run_gate3_bla
from app.services.keys import ensure_ed25519_keypair
from app.services.llm_providers import EffectiveLLMConfig, TokenUsage
from app.services.scanners import (
    GitleaksScanner,
    SecretScanner,
    SimulationSecretScanner,
    TruffleHogScanner,
    resolve_secret_scanner,
)
from app.services.vault import (
    ENCRYPTED_PREFIX,
    ensure_vault_master_key,
    migrate_plaintext_app_settings,
    scrub_secrets,
)

cli_runner = CliRunner()


def test_bastion_end_to_end_live_pipeline() -> None:
    with TestClient(app) as client:
        # 1. Health & Toolchain Check
        health = client.get("/api/health")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"
        assert health.json()["version"] == "2.1.0"

        tools = client.get("/api/system/tools")
        assert tools.status_code == 200
        tdata = tools.json()
        assert tdata["trufflehog"]["mode"] == "live", f"TruffleHog not live: {tdata['trufflehog']}"
        assert tdata["cloudflare_skill"]["mode"] == "live", f"Cloudflare skill not live: {tdata['cloudflare_skill']}"
        assert tdata["bla"]["mode"] == "live", f"BLA not live: {tdata['bla']}"
        assert tdata["ed25519_key_fingerprint"].startswith("ed25519:")

        # Ensure LLM is set to none so fallback badge is verified cleanly
        reset_llm = client.put(
            "/api/settings/llm",
            json={"provider": "none", "model": "", "ollama_url": "http://localhost:11434", "default_secret_scanner": "auto"},
        )
        assert reset_llm.status_code == 200
        assert reset_llm.json()["active_badge"] == STATIC_FALLBACK_BADGE

        # 2. Seeded sample project exists + GitHub Actions generator
        projects = client.get("/api/projects")
        assert projects.status_code == 200
        plist = projects.json()
        assert len(plist) >= 1
        project = next((p for p in plist if "sample-target" in p["path"]), plist[0])
        project_id = project["id"]

        cicd = client.get(f"/api/projects/{project_id}/cicd/github-actions")
        assert cicd.status_code == 200
        yml = cicd.json()["yaml_content"]
        assert "github/codeql-action/upload-sarif@v3" in yml
        assert "actions/upload-artifact@v4" in yml
        assert "exit 10" in yml and "exit 20" in yml and "exit 30" in yml

        # 3. Trigger Run #1 (Live 3-Stage Gate)
        run_resp = client.post(
            "/api/runs",
            json={
                "project_id": project_id,
                "secret_scanner": "auto",
                "bla_intensity": "balanced",
                "audit_profile": "standard",
                "audit_scope": "full",
                "stop_on_gate1_fail": True,
                "force_simulation": False,
            },
        )
        assert run_resp.status_code == 201
        run_id = run_resp.json()["id"]

        final_run = None
        for _ in range(90):
            r = client.get(f"/api/runs/{run_id}")
            assert r.status_code == 200
            final_run = r.json()
            if final_run["status"] in ("passed", "failed", "aborted"):
                break
            time.sleep(0.5)

        assert final_run is not None
        assert final_run["status"] in ("passed", "failed")
        assert len(final_run["gates"]) == 3

        g1, g2, g3 = final_run["gates"]
        assert g1["mode"] == "live"
        assert g1["status"] == "passed"
        assert g2["mode"] == "static_heuristic"
        assert g2["metadata"]["engine_badge"] == STATIC_FALLBACK_BADGE
        assert g2["metadata"]["validators"]["findings_valid"] is True, g2["metadata"]
        assert g2["metadata"]["validators"]["ledger_valid"] is True, g2["metadata"]
        assert g3["mode"] == "live"
        assert g3["status"] == "passed"

        # 4. SSE Stream returns valid SSE frames with replay + complete
        with client.stream("GET", f"/api/runs/{run_id}/stream") as sse:
            assert sse.status_code == 200
            assert "text/event-stream" in sse.headers["content-type"]
            body = "".join(sse.iter_text())
            assert "event: log" in body
            assert "event: gate_update" in body
            assert "event: complete" in body

        # 5. Findings, Verifier Separation, Code Context, Triage & SARIF
        findings = client.get(f"/api/findings?run_id={run_id}").json()
        assert len(findings) >= 2
        for f in findings:
            if f["gate_number"] == 2:
                assert f["hunter_agent_id"] != f["verifier_agent_id"]

        first_finding = findings[0]
        ctx = client.get(f"/api/findings/{first_finding['id']}/context")
        assert ctx.status_code == 200
        assert ctx.json()["exists"] is True

        patched = client.patch(
            f"/api/findings/{first_finding['id']}",
            json={"resolved": True, "resolution_note": "Verified in v2 E2E test"},
        )
        assert patched.status_code == 200
        assert patched.json()["resolved"] is True

        sarif = client.get(f"/api/findings/export/sarif?run_id={run_id}")
        assert sarif.status_code == 200
        assert sarif.json()["version"] == "2.1.0"
        assert len(sarif.json()["runs"][0]["results"]) == len(findings)

        # 6. Additive Coverage Ledger carry-forward
        ledger = client.get(f"/api/projects/{project_id}/ledger").json()
        assert len(ledger) >= 5

        run2_resp = client.post(
            "/api/runs",
            json={
                "project_id": project_id,
                "bla_intensity": "stealth",
                "audit_profile": "standard",
                "audit_scope": "full",
            },
        )
        assert run2_resp.status_code == 201
        run2_id = run2_resp.json()["id"]
        for _ in range(90):
            r2 = client.get(f"/api/runs/{run2_id}").json()
            if r2["status"] in ("passed", "failed", "aborted"):
                assert r2["gates"][1]["metadata"]["prior_units_reused"] > 0
                break
            time.sleep(0.5)

        # 7. BLA Artifacts + Apply + Restore lifecycle
        artifacts = client.get(f"/api/projects/{project_id}/artifacts").json()
        assert len(artifacts) >= 2
        assert all(a["verified"] for a in artifacts)

        applied = client.post(f"/api/projects/{project_id}/bla/apply", json={"intensity": "balanced"})
        assert applied.status_code == 200
        assert applied.json()["bla_applied"] is True

        restored = client.post(f"/api/projects/{project_id}/bla/restore")
        assert restored.status_code == 200
        assert restored.json()["bla_applied"] is False

        # 8. Asymmetric Ed25519 Release Certificates (JSON, Markdown, PDF)
        cert_json = client.get(f"/api/runs/{run_id}/certificate?format=json")
        assert cert_json.status_code == 200
        cj = cert_json.json()
        assert cj["integrity"]["algorithm"] == "Ed25519"
        assert cj["integrity"]["key_fingerprint"].startswith("ed25519:")
        assert cj["certificate"]["run"]["gate2_engine_badge"] == STATIC_FALLBACK_BADGE
        assert "expires_at" in cj["certificate"]

        cert_md = client.get(f"/api/runs/{run_id}/certificate?format=md")
        assert cert_md.status_code == 200
        assert "Ed25519" in cert_md.text
        assert STATIC_FALLBACK_BADGE in cert_md.text

        cert_pdf = client.get(f"/api/runs/{run_id}/certificate?format=pdf")
        assert cert_pdf.status_code == 200
        assert cert_pdf.content.startswith(b"%PDF-")


def test_ed25519_tamper_and_expiry_detection_and_cli_verify(tmp_path: Path) -> None:
    with TestClient(app) as client:
        runs = client.get("/api/runs").json()
        assert len(runs) >= 1
        run_id = runs[0]["id"]

        pub = client.get("/api/system/public-key").json()
        assert pub["algorithm"] == "Ed25519"
        assert pub["key_fingerprint"].startswith("ed25519:")

        cert_doc = client.get(f"/api/runs/{run_id}/certificate?format=json").json()

        # 1. Valid certificate passes API verification
        ok_resp = client.post(
            "/api/certificates/verify",
            json={"certificate": cert_doc, "public_key_pem": pub["public_key_pem"]},
        )
        assert ok_resp.status_code == 200
        assert ok_resp.json()["valid"] is True
        assert ok_resp.json()["status"] == "valid"
        assert ok_resp.json()["tampered"] is False
        assert ok_resp.json()["expired"] is False

        # 2. Tampering with a single field MUST fail verification
        tampered = copy.deepcopy(cert_doc)
        tampered["certificate"]["release_decision"] = "APPROVED"
        tampered["certificate"]["run"]["readiness_score"] = 100
        bad_resp = client.post(
            "/api/certificates/verify",
            json={"certificate": tampered, "public_key_pem": pub["public_key_pem"]},
        )
        assert bad_resp.status_code == 200
        assert bad_resp.json()["valid"] is False
        assert bad_resp.json()["tampered"] is True
        assert bad_resp.json()["signature_valid"] is False

        # 3. Expiry check detects expired certificates
        future_time = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=45)
        exp_check = verify_certificate_document(
            cert_doc,
            public_key_pem=pub["public_key_pem"],
            now_utc=future_time,
        )
        assert exp_check["valid"] is False
        assert exp_check["expired"] is True
        assert exp_check["status"] == "expired"

        # 4. CLI `bastion verify` validates untouched cert (exit 0) and rejects tampered cert (exit 1)
        key_info = ensure_ed25519_keypair()
        valid_file = tmp_path / "valid-cert.json"
        tampered_file = tmp_path / "tampered-cert.json"
        valid_file.write_text(json.dumps(cert_doc, indent=2), encoding="utf-8")
        tampered_file.write_text(json.dumps(tampered, indent=2), encoding="utf-8")

        res_ok = cli_runner.invoke(cli, ["verify", str(valid_file), "--pubkey", str(key_info.public_key_path)])
        assert res_ok.exit_code == 0, res_ok.output
        assert "VALID" in res_ok.output

        res_bad = cli_runner.invoke(cli, ["verify", str(tampered_file), "--pubkey", str(key_info.public_key_path)])
        assert res_bad.exit_code == 1
        assert "TAMPERED" in res_bad.output or "ERROR" in res_bad.output


def test_gate2_dual_session_llm_isolation_and_validators(tmp_path: Path) -> None:
    repo = tmp_path / "llm-target"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "auth.js").write_text(
        "function checkToken(input, expected) {\n  return input === expected;\n}\nmodule.exports = { checkToken };\n",
        encoding="utf-8",
    )

    captured_calls: list[dict[str, str]] = []
    secret_hunter_cot = "SECRET_SESSION_A_CHAIN_OF_THOUGHT_MUST_NOT_LEAK"

    def fake_complete_json_with_usage(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 3000,
        schema_hint: str = "a single valid JSON object",
    ):
        captured_calls.append({"system": system_prompt, "user": user_prompt})
        if "Session A (Hunter)" in system_prompt:
            return (
                {
                    "reasoning": secret_hunter_cot,
                    "candidates": [
                        {
                            "rule_id": "timing-token-check",
                            "title": "Non-constant-time token equality check",
                            "surface": "auth-check",
                            "boundary": "caller-to-token-verifier",
                            "attack_class": "timing-side-channel",
                            "file": "src/auth.js",
                            "line": 2,
                            "scope": "checkToken",
                            "claimed_root_cause": "Secret token compared using === instead of timingSafeEqual.",
                            "intended_behavior": "Compare cryptographic tokens in constant time.",
                            "trace": [
                                {"file": "src/auth.js", "line": 1, "scope": "checkToken", "description": "Caller input enters checkToken."},
                                {"file": "src/auth.js", "line": 2, "scope": "checkToken", "description": "Non-constant-time === comparison."},
                            ],
                            "attacker_perspective": "Remote caller measuring response latency.",
                            "payloads": ["aaaa", "aaab"],
                            "remediation_hint": "Use crypto.timingSafeEqual on equal-length buffers.",
                            "fixed_code": "return crypto.timingSafeEqual(Buffer.from(input), Buffer.from(expected));",
                        }
                    ],
                },
                TokenUsage(prompt_tokens=220, completion_tokens=110, estimated_cost_usd=0.0001),
            )
        # Session B (Independent Verifier)
        return (
            {
                "decision": "confirmed",
                "title": "Non-constant-time token equality check",
                "description": "Direct === comparison on expected token leaks prefix match timing.",
                "root_cause": "checkToken uses standard === string comparison instead of constant-time comparison.",
                "intended_behavior": "Token comparison must run in constant time.",
                "likelihood": "low",
                "likelihood_reason": "Requires statistical timing measurements.",
                "impact": "medium",
                "impact_reason": "Allows gradual secret recovery.",
                "overall_severity": "medium",
                "confidence": "high",
                "confidence_reason": "Observed directly in raw slice of src/auth.js line 2.",
                "observed_result": "Line 2 returns input === expected with no timingSafeEqual guard.",
                "remediation_strategy": "Use crypto.timingSafeEqual over fixed-length buffers.",
                "fixed_code": "return crypto.timingSafeEqual(Buffer.from(input), Buffer.from(expected));",
            },
            TokenUsage(prompt_tokens=150, completion_tokens=95, estimated_cost_usd=0.00008),
        )

    cfg = EffectiveLLMConfig(
        provider="openai",
        model="gpt-4o-mini",
        gemini_api_key="",
        gemini_source="none",
        anthropic_api_key="",
        anthropic_source="none",
        openai_api_key="sk-test-byok-key",
        openai_source="vault",
        ollama_url="http://localhost:11434",
        ollama_source="none",
        default_secret_scanner="auto",
        default_audit_scope="full",
        default_max_budget_usd=1.50,
    )

    out_dir = tmp_path / "run-out"
    with patch(
        "app.services.llm_providers.IsolatedLLMSession.complete_json_with_usage",
        new=fake_complete_json_with_usage,
    ):
        res = run_gate2_cloudflare(
            run_id="llm-test-run",
            target_path=repo,
            run_output_dir=out_dir,
            prior_ledger=[],
            audit_profile="standard",
            force_simulation=False,
            llm_config=cfg,
            audit_scope="full",
        )

    assert res.mode == "live_llm"
    assert res.engine_badge == "Multi-Agent LLM (openai/gpt-4o-mini)"
    assert len(captured_calls) == 2, "Expected exactly 1 Hunter call + 1 isolated Verifier call"
    # Verify Session B NEVER received Session A's chain-of-thought
    assert secret_hunter_cot not in captured_calls[1]["user"]
    assert secret_hunter_cot not in captured_calls[1]["system"]
    assert "RAW SOURCE SLICE" in captured_calls[1]["user"]
    assert "return input === expected;" in captured_calls[1]["user"]
    # Verify Cloudflare's REAL validators passed on LLM output!
    assert res.metadata["validators"]["findings_valid"] is True, res.metadata
    assert res.metadata["validators"]["ledger_valid"] is True, res.metadata
    assert len(res.findings) == 1
    assert res.findings[0].hunter_agent_id != res.findings[0].verifier_agent_id


def test_pluggable_gate1_secret_scanners_trufflehog_and_gitleaks(tmp_path: Path) -> None:
    assert isinstance(TruffleHogScanner(), SecretScanner)
    assert isinstance(GitleaksScanner(), SecretScanner)
    assert isinstance(SimulationSecretScanner(), SecretScanner)

    # Both TruffleHog and Gitleaks normalize into identical SecretFindingData schema
    th_line = json.dumps({
        "DetectorName": "AWS",
        "DetectorDescription": "AWS Access Key",
        "Verified": True,
        "Raw": "AKIAIOSFODNN7EXAMPLE",
        "Redacted": "",
        "SourceMetadata": {"Data": {"Filesystem": {"file": "src/config.py", "line": 4}}},
    })
    th_finding = TruffleHogScanner.parse_json_line(th_line, tmp_path, "filesystem")
    assert th_finding is not None
    assert th_finding.scanner_engine == "trufflehog"
    assert th_finding.file_path == "src/config.py"
    assert th_finding.line_number == 4
    assert th_finding.verified is True
    assert "AKIAIOSFODNN7EXAMPLE" not in th_finding.redacted_secret

    gl_items = [
        {
            "RuleID": "aws-access-token",
            "Description": "AWS Access Key ID",
            "File": "src/config.py",
            "StartLine": 4,
            "Secret": "AKIAIOSFODNN7EXAMPLE",
            "Commit": "abc123def456",
        }
    ]
    gl_findings = GitleaksScanner.parse_report_items(gl_items, tmp_path, "gitleaks-git")
    assert len(gl_findings) == 1
    gl_finding = gl_findings[0]
    assert gl_finding.scanner_engine == "gitleaks"
    assert gl_finding.file_path == "src/config.py"
    assert gl_finding.line_number == 4
    assert gl_finding.verified is True
    assert "AKIAIOSFODNN7EXAMPLE" not in gl_finding.redacted_secret

    # Fallback resolution check
    sim_scanner = resolve_secret_scanner("auto", force_simulation=True)
    assert sim_scanner.name == "simulation-regex"


def _cleanup_pytest_projects() -> None:
    with SessionLocal() as db:
        rows = db.query(Project).all()
        removed = False
        for row in rows:
            if "pytest-of-" in row.path or not Path(row.path).exists():
                db.delete(row)
                removed = True
        if removed:
            db.commit()


def test_cli_strict_exit_codes_0_10_20_30(tmp_path: Path) -> None:
    try:
        # 1. Unit check on strict exit code precedence helper
        def _g(num: int, st: str) -> GateExecution:
            return GateExecution(run_id="r", gate_number=num, name=f"G{num}", engine="e", status=st)

        assert compute_gate_exit_code([_g(1, "passed"), _g(2, "passed"), _g(3, "passed")], "passed") == 0
        assert compute_gate_exit_code([_g(1, "failed"), _g(2, "skipped"), _g(3, "skipped")], "failed") == 10
        assert compute_gate_exit_code([_g(1, "passed"), _g(2, "failed"), _g(3, "passed")], "failed") == 20
        assert compute_gate_exit_code([_g(1, "passed"), _g(2, "passed"), _g(3, "failed")], "failed") == 30

        # 2. Exit 0: Clean repo with safe code + dist artifact
        clean_repo = tmp_path / "clean-repo"
        (clean_repo / "src").mkdir(parents=True)
        (clean_repo / "dist").mkdir(parents=True)
        (clean_repo / "src" / "math.js").write_text("function add(a, b) { return a + b; }\nmodule.exports = { add };\n", encoding="utf-8")
        (clean_repo / "dist" / "math.js").write_text("function add(a, b) { return a + b; }\nmodule.exports = { add };\n", encoding="utf-8")
        cert_path = tmp_path / "clean-cert.json"
        sarif_path = tmp_path / "clean.sarif"

        r0 = cli_runner.invoke(
            cli,
            ["run", str(clean_repo), "--simulate", "--cert-out", str(cert_path), "--sarif-out", str(sarif_path)],
        )
        assert r0.exit_code == 0, r0.output
        assert cert_path.exists() and sarif_path.exists()

        # 3. Exit 10: Blocked at Gate 1 (verified/live-pattern AWS key)
        secret_repo = tmp_path / "secret-repo"
        secret_repo.mkdir()
        # Non-placeholder AWS key pattern (no 'example'/'dummy' tokens)
        (secret_repo / "env.txt").write_text("AWS_KEY=" + "AKIA" + "9876543210ABCDEF" + "\n", encoding="utf-8")
        r10 = cli_runner.invoke(cli, ["run", str(secret_repo), "--simulate"])
        assert r10.exit_code == 10, r10.output

        # 4. Exit 20: Blocked at Gate 2 (confirmed high-severity SQL injection)
        vuln_repo = tmp_path / "vuln-repo"
        (vuln_repo / "src").mkdir(parents=True)
        (vuln_repo / "src" / "db.js").write_text(
            "function findUser(id) { return `SELECT * FROM users WHERE id = '${id}'`; }\n",
            encoding="utf-8",
        )
        r20 = cli_runner.invoke(cli, ["run", str(vuln_repo), "--simulate"])
        assert r20.exit_code == 20, r20.output

        # 5. Exit 30: Blocked at Gate 3 (BLA verification failure)
        failed_g3 = Gate3Result(
            status="failed",
            mode="live",
            duration_ms=10,
            summary="Simulated Gate 3 BLA verification failure.",
            artifacts=[],
        )
        with patch("app.services.orchestrator.run_gate3_bla", return_value=failed_g3):
            r30 = cli_runner.invoke(cli, ["run", str(clean_repo), "--simulate"])
        assert r30.exit_code == 30, r30.output
    finally:
        _cleanup_pytest_projects()



def _read_sqlite_all_bytes(db_path: Path) -> bytes:
    buf = bytearray()
    for suffix in ("", "-wal", "-shm"):
        p = Path(f"{db_path}{suffix}")
        if p.exists():
            buf.extend(p.read_bytes())
    return bytes(buf)


def test_encrypted_vault_env_precedence_migration_and_scrubbing(monkeypatch: pytest.MonkeyPatch) -> None:
    vault_secret = "sk-vault-test-key-998877664f2a"
    env_secret = "sk-env-override-11223344aabb"
    legacy_secret = "sk-ant-legacy-plain-7766554499ee"

    # Ensure clean env before testing vault persistence
    for k in (
        "OPENAI_API_KEY",
        "BASTION_OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "BASTION_GEMINI_API_KEY",
        "ANTHROPIC_API_KEY",
        "BASTION_ANTHROPIC_API_KEY",
    ):
        monkeypatch.delenv(k, raising=False)

    with TestClient(app) as client:
        try:
            # 1. Save OpenAI key via API -> encrypted with Fernet vault
            put_resp = client.put(
                "/api/settings/llm",
                json={
                    "provider": "openai",
                    "model": "gpt-4o-mini",
                    "ollama_url": "http://localhost:11434",
                    "default_secret_scanner": "auto",
                    "default_audit_scope": "diff",
                    "default_max_budget_usd": 1.50,
                    "openai_api_key": vault_secret,
                },
            )
            assert put_resp.status_code == 200, put_resp.text
            put_data = put_resp.json()
            assert put_data["configured"] is True
            assert put_data["source"] == "vault"
            assert put_data["masked_key"] == "sk-••••4f2a"
            assert put_data["vault_encrypted"] is True
            assert vault_secret not in json.dumps(put_data)

            # 2. GET /api/settings/llm exposes ONLY configured/source/masked_key
            get_resp = client.get("/api/settings/llm")
            assert get_resp.status_code == 200
            get_data = get_resp.json()
            assert get_data["configured"] is True
            assert get_data["source"] == "vault"
            assert get_data["masked_key"] == "sk-••••4f2a"
            assert get_data["providers"]["openai"]["source"] == "vault"
            assert get_data["providers"]["openai"]["masked_key"] == "sk-••••4f2a"
            assert vault_secret not in json.dumps(get_data)

            # 3. Verify master key exists outside project & ZERO plaintext key bytes exist in SQLite DB/WAL
            _, key_path = ensure_vault_master_key()
            assert key_path.exists()
            sqlite_file = settings.resolved_data_dir / "bastion.db"
            raw_db_bytes = _read_sqlite_all_bytes(sqlite_file)
            assert vault_secret.encode("utf-8") not in raw_db_bytes, "Plaintext API key leaked into SQLite file!"

            # 4. Verify strict environment variable precedence over stored vault entries
            monkeypatch.setenv("OPENAI_API_KEY", env_secret)
            env_resp = client.get("/api/settings/llm")
            assert env_resp.status_code == 200
            env_data = env_resp.json()
            assert env_data["configured"] is True
            assert env_data["source"] == "env"
            assert env_data["masked_key"] == "sk-••••aabb"
            assert env_data["providers"]["openai"]["source"] == "env"
            assert env_secret not in json.dumps(env_data)
            monkeypatch.delenv("OPENAI_API_KEY", raising=False)

            # 5. Simulate legacy plaintext row in AppSetting and verify automatic startup migration
            db = SessionLocal()
            try:
                row = db.get(AppSetting, "anthropic_api_key")
                if row:
                    row.value = legacy_secret
                else:
                    db.add(AppSetting(key="anthropic_api_key", value=legacy_secret))
                db.commit()

                migrated_count = migrate_plaintext_app_settings(db)
                assert migrated_count >= 1
                refreshed = db.get(AppSetting, "anthropic_api_key")
                assert refreshed is not None
                assert refreshed.value.startswith(ENCRYPTED_PREFIX)
            finally:
                db.close()

            raw_after_mig = _read_sqlite_all_bytes(sqlite_file)
            assert legacy_secret.encode("utf-8") not in raw_after_mig, "Legacy plaintext key remained in SQLite bytes!"

            # 6. Verify log/error/report secret scrubbing redacts loaded keys
            noisy_log = f"Upstream error with key={vault_secret} and env={env_secret} and legacy={legacy_secret}"
            scrubbed = scrub_secrets(noisy_log)
            assert vault_secret not in scrubbed
            assert env_secret not in scrubbed
            assert legacy_secret not in scrubbed
            assert "[REDACTED_API_KEY]" in scrubbed
        finally:
            # Cleanly reset stored keys back to default no-LLM state
            client.put(
                "/api/settings/llm",
                json={
                    "provider": "none",
                    "model": "",
                    "ollama_url": "http://localhost:11434",
                    "default_secret_scanner": "auto",
                    "default_audit_scope": "diff",
                    "default_max_budget_usd": 1.50,
                    "clear_keys": True,
                },
            )


def test_gate2_diff_scoping_and_budget_capping(tmp_path: Path) -> None:
    # Part A: Git-diff scoping + 1-hop direct local import inclusion
    diff_repo = tmp_path / "diff-repo"
    (diff_repo / "src").mkdir(parents=True)
    (diff_repo / "src" / "auth.js").write_text(
        "function login(user) { return Boolean(user); }\nmodule.exports = { login };\n",
        encoding="utf-8",
    )
    (diff_repo / "src" / "helper.js").write_text(
        "function lookup(db, id) {\n  const q = `SELECT * FROM sessions WHERE id = '${id}'`;\n  return db.query(q);\n}\nmodule.exports = { lookup };\n",
        encoding="utf-8",
    )
    (diff_repo / "src" / "unchanged.js").write_text(
        "function legacyReport(db, name) {\n  const q = `SELECT * FROM reports WHERE name = '${name}'`;\n  return db.query(q);\n}\nmodule.exports = { legacyReport };\n",
        encoding="utf-8",
    )

    def _git(*args: str) -> None:
        subprocess.run(
            ["git", *args],
            cwd=str(diff_repo),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=True,
        )

    _git("init")
    _git("config", "user.email", "bastion@example.test")
    _git("config", "user.name", "Bastion Test")
    _git("add", ".")
    _git("commit", "-m", "initial commit")

    # Commit 2: Modify ONLY src/auth.js so it directly imports ./helper; leave src/unchanged.js untouched
    (diff_repo / "src" / "auth.js").write_text(
        "const { lookup } = require('./helper');\nfunction login(db, id) { return lookup(db, id); }\nmodule.exports = { login };\n",
        encoding="utf-8",
    )
    _git("add", "src/auth.js")
    _git("commit", "-m", "wire helper into auth")

    diff_out = tmp_path / "diff-out"
    diff_res = run_gate2_cloudflare(
        run_id="diff-scope-run",
        target_path=diff_repo,
        run_output_dir=diff_out,
        prior_ledger=[],
        audit_profile="standard",
        force_simulation=False,
        llm_config=None,
        audit_scope="diff",
        base_ref="HEAD~1",
        max_budget_usd=1.50,
    )

    assert diff_res.metadata["scope"] == "diff"
    assert "src/auth.js" in diff_res.metadata["files_audited"]
    assert "src/helper.js" in diff_res.metadata["files_audited"], (
        f"Expected direct 1-hop local import src/helper.js in files_audited: {diff_res.metadata}"
    )
    assert "src/unchanged.js" in diff_res.metadata["files_out_of_scope"]
    assert "src/unchanged.js" not in diff_res.metadata["files_audited"]
    # Finding should come from src/helper.js, NOT src/unchanged.js
    finding_files = {f.file_path for f in diff_res.findings}
    assert "src/helper.js" in finding_files
    assert "src/unchanged.js" not in finding_files
    assert diff_res.metadata["validators"]["findings_valid"] is True, diff_res.metadata
    assert diff_res.metadata["validators"]["ledger_valid"] is True, diff_res.metadata

    ledger_doc = json.loads((diff_out / "cloudflare" / "coverage-ledger.json").read_text(encoding="utf-8"))
    oos_units = [u for u in ledger_doc if u["status"] == "out_of_scope"]
    assert len(oos_units) >= 1
    assert any("unchanged.js" in " ".join(u.get("starting_paths", [])) for u in oos_units)

    # Part B: Token/cost budget capping prioritizes security-critical files and records deferred low-risk files
    budget_repo = tmp_path / "budget-repo"
    (budget_repo / "src").mkdir(parents=True)
    (budget_repo / "docs").mkdir(parents=True)
    (budget_repo / "src" / "auth_sql_handler.js").write_text(
        "function fetchAccount(db, id) {\n  return db.query(`SELECT * FROM accounts WHERE id = '${id}'`);\n}\n",
        encoding="utf-8",
    )
    # Large low-risk file (~4,000+ tokens) that exceeds tight budget cap
    (budget_repo / "docs" / "marketing_notes.py").write_text(
        "\n".join(f"NOTE_{i} = 'release documentation note entry number {i} for changelog archive'" for i in range(260)),
        encoding="utf-8",
    )

    anthropic_cfg = EffectiveLLMConfig(
        provider="anthropic",
        model="claude-3-5-sonnet-latest",
        gemini_api_key="",
        gemini_source="none",
        anthropic_api_key="sk-ant-budget-test-key-1234",
        anthropic_source="vault",
        openai_api_key="",
        openai_source="none",
        ollama_url="http://localhost:11434",
        ollama_source="none",
        default_secret_scanner="auto",
        default_audit_scope="full",
        default_max_budget_usd=0.002,
    )

    def _empty_hunter(self, system_prompt: str, user_prompt: str, max_tokens: int = 3000):
        return (
            json.dumps({"candidates": []}),
            TokenUsage(prompt_tokens=180, completion_tokens=20, estimated_cost_usd=0.00084),
        )

    budget_out = tmp_path / "budget-out"
    with patch("app.services.llm_providers.IsolatedLLMSession.complete_text_with_usage", new=_empty_hunter):
        budget_res = run_gate2_cloudflare(
            run_id="budget-cap-run",
            target_path=budget_repo,
            run_output_dir=budget_out,
            prior_ledger=[],
            audit_profile="standard",
            force_simulation=False,
            llm_config=anthropic_cfg,
            audit_scope="full",
            max_budget_usd=0.002,  # ~433 input token budget for Anthropic pricing
        )

    assert "src/auth_sql_handler.js" in budget_res.metadata["files_audited"]
    assert "docs/marketing_notes.py" in budget_res.metadata["files_deferred_budget"]
    assert budget_res.metadata["validators"]["findings_valid"] is True, budget_res.metadata
    assert budget_res.metadata["validators"]["ledger_valid"] is True, budget_res.metadata

    budget_ledger = json.loads((budget_out / "cloudflare" / "coverage-ledger.json").read_text(encoding="utf-8"))
    deferred_units = [u for u in budget_ledger if u["status"] == "deferred"]
    assert len(deferred_units) >= 1
    assert any("marketing_notes.py" in " ".join(u.get("starting_paths", [])) for u in deferred_units)


def test_live_llm_malformed_json_fences_and_schema_repair_retry(tmp_path: Path) -> None:
    repo = tmp_path / "resilience-repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "export.js").write_text(
        "const path = require('path');\n"
        "function readExport(baseDir, filename) {\n"
        "  return path.join(baseDir, filename);\n"
        "}\n"
        "module.exports = { readExport };\n",
        encoding="utf-8",
    )

    call_log: list[str] = []

    def fake_complete_text_with_usage(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 3000,
    ):
        call_log.append(system_prompt)
        # Call 1: Session A returns prose + markdown-fenced JSON with // comments & trailing commas
        if "Session A (Hunter)" in system_prompt:
            fenced_payload = (
                "Here are the candidate hypotheses I found:\n"
                "```json\n"
                "// Candidate generated by Hunter\n"
                "{\n"
                '  "candidates": [\n'
                "    {\n"
                '      "rule_id": "path-traversal-export",\n'
                '      "title": "Path traversal in readExport",\n'
                '      "surface": "filesystem-export",\n'
                '      "boundary": "caller-to-filesystem",\n'
                '      "attack_class": "path-traversal",\n'
                '      "file": "src/export.js",\n'
                '      "line": 3,\n'
                '      "scope": "readExport",\n'
                '      "claimed_root_cause": "filename joined directly to baseDir without containment check.",\n'
                '      "intended_behavior": "Restrict reads to baseDir.",\n'
                '      "trace": [\n'
                '        {"file": "src/export.js", "line": 2, "scope": "readExport", "description": "filename parameter received."},\n'
                '        {"file": "src/export.js", "line": 3, "scope": "readExport", "description": "path.join allows traversal.",}\n'
                "      ],\n"
                '      "attacker_perspective": "Caller supplies ../../etc/passwd",\n'
                '      "payloads": ["../../etc/passwd",],\n'
                '      "remediation_hint": "Resolve canonically and assert baseDir prefix.",\n'
                '      "fixed_code": "const resolved = path.resolve(baseDir, path.basename(filename));",\n'
                "    },\n"
                "  ],\n"
                "}\n"
                "```\n"
                "End of Hunter output."
            )
            return fenced_payload, TokenUsage(prompt_tokens=200, completion_tokens=140, estimated_cost_usd=0.00012)

        # Call 2: Session B returns genuinely malformed broken JSON on first try
        if "Session B (Independent Verifier)" in system_prompt:
            broken_json = '{"decision": "confirmed", "title": UNQUOTED BROKEN JSON {{{'
            return broken_json, TokenUsage(prompt_tokens=160, completion_tokens=30, estimated_cost_usd=0.00004)

        # Call 3: Strict JSON schema-repair retry succeeds
        assert "strict JSON repair formatter" in system_prompt
        repaired_json = json.dumps({
            "decision": "confirmed",
            "title": "Path traversal in readExport",
            "description": "Unvalidated filename parameter passed to path.join enables parent directory traversal.",
            "root_cause": "readExport joins untrusted filename into baseDir without canonical containment verification.",
            "intended_behavior": "Exports must stay strictly inside baseDir.",
            "likelihood": "high",
            "likelihood_reason": "Directly reachable from filename argument.",
            "impact": "high",
            "impact_reason": "Allows reading arbitrary files outside baseDir.",
            "overall_severity": "high",
            "confidence": "high",
            "confidence_reason": "Observed directly at src/export.js line 3.",
            "observed_result": "Line 3 executes path.join(baseDir, filename) with no startsWith or basename check.",
            "remediation_strategy": "Resolve canonical path and verify prefix containment inside baseDir.",
            "fixed_code": "const resolved = path.resolve(baseDir, path.basename(filename));",
        })
        return repaired_json, TokenUsage(prompt_tokens=180, completion_tokens=110, estimated_cost_usd=0.00009)

    cfg = EffectiveLLMConfig(
        provider="openai",
        model="gpt-4o-mini",
        gemini_api_key="",
        gemini_source="none",
        anthropic_api_key="",
        anthropic_source="none",
        openai_api_key="sk-resilience-test-key-0001",
        openai_source="vault",
        ollama_url="http://localhost:11434",
        ollama_source="none",
        default_secret_scanner="auto",
        default_audit_scope="full",
        default_max_budget_usd=1.50,
    )

    out_dir = tmp_path / "resilience-out"
    with patch(
        "app.services.llm_providers.IsolatedLLMSession.complete_text_with_usage",
        new=fake_complete_text_with_usage,
    ):
        res = run_gate2_cloudflare(
            run_id="resilience-run",
            target_path=repo,
            run_output_dir=out_dir,
            prior_ledger=[],
            audit_profile="standard",
            force_simulation=False,
            llm_config=cfg,
            audit_scope="full",
        )

    assert res.mode == "live_llm"
    assert len(call_log) == 3, f"Expected 1 Hunter + 1 broken Verifier + 1 schema-repair retry, got {len(call_log)}"
    assert "strict JSON repair formatter" in call_log[2]
    assert len(res.findings) == 1
    assert res.findings[0].verdict == "confirmed"
    assert res.metadata["validators"]["findings_valid"] is True, res.metadata
    assert res.metadata["validators"]["ledger_valid"] is True, res.metadata


def test_post_bla_smoke_verification_pass_fail_and_cli_exit_30(tmp_path: Path) -> None:
    # 1. Passing post-BLA smoke test against hardened mirror
    good_repo = tmp_path / "good-smoke-repo"
    (good_repo / "src").mkdir(parents=True)
    (good_repo / "dist").mkdir(parents=True)
    (good_repo / "src" / "app.js").write_text("console.log('BOOT_OK');\n", encoding="utf-8")
    (good_repo / "dist" / "index.js").write_text("console.log('SMOKE_PASS_OK');\n", encoding="utf-8")

    ok_res = run_gate3_bla(
        run_id="smoke-pass-run",
        target_path=good_repo,
        intensity="balanced",
        force_simulation=True,
        smoke_test_cmd="node dist/index.js",
    )
    assert ok_res.status == "passed"
    assert ok_res.smoke_test is not None
    assert ok_res.smoke_test.status == "passed"
    assert ok_res.smoke_test.exit_code == 0
    assert ok_res.smoke_test.tested_mirror is True
    assert "SMOKE_PASS_OK" in ok_res.smoke_test.stdout

    # 2. Failing post-BLA smoke test catches a broken build and fails Gate 3
    broken_repo = tmp_path / "broken-smoke-repo"
    (broken_repo / "src").mkdir(parents=True)
    (broken_repo / "dist").mkdir(parents=True)
    (broken_repo / "src" / "safe.js").write_text("function add(a, b) { return a + b; }\nmodule.exports = { add };\n", encoding="utf-8")
    (broken_repo / "dist" / "index.js").write_text(
        "console.error('RUNTIME_CRASH_AFTER_HARDENING');\nprocess.exit(2);\n",
        encoding="utf-8",
    )

    fail_res = run_gate3_bla(
        run_id="smoke-fail-run",
        target_path=broken_repo,
        intensity="balanced",
        force_simulation=True,
        smoke_test_cmd="node dist/index.js",
    )
    assert fail_res.status == "failed"
    assert fail_res.smoke_test is not None
    assert fail_res.smoke_test.status == "failed"
    assert fail_res.smoke_test.exit_code == 2
    assert "RUNTIME_CRASH_AFTER_HARDENING" in fail_res.smoke_test.stderr

    # 3. Headless CLI `bastion run --smoke-cmd` MUST exit 30 (Gate 3 blocked before --apply)
    try:
        r30 = cli_runner.invoke(
            cli,
            ["run", str(broken_repo), "--simulate", "--scope", "full", "--smoke-cmd", "node dist/index.js"],
        )
        assert r30.exit_code == 30, r30.output
    finally:
        _cleanup_pytest_projects()

    # 4. API endpoint POST /api/projects/{id}/bla/smoke-test works for both pass and fail
    with TestClient(app) as client:
        projects = client.get("/api/projects").json()
        sample = next((p for p in projects if "sample-target" in p["path"]), projects[0])
        pid = sample["id"]
        smoke_ok = client.post(
            f"/api/projects/{pid}/bla/smoke-test",
            json={"smoke_test_cmd": "node -e \"console.log('API_SMOKE_OK')\""},
        )
        assert smoke_ok.status_code == 200
        assert smoke_ok.json()["status"] == "passed"
        assert "API_SMOKE_OK" in smoke_ok.json()["stdout"]

        smoke_bad = client.post(
            f"/api/projects/{pid}/bla/smoke-test",
            json={"smoke_test_cmd": "node -e \"process.exit(5)\""},
        )
        assert smoke_bad.status_code == 200
        assert smoke_bad.json()["status"] == "failed"
        assert smoke_bad.json()["exit_code"] == 5


def test_github_actions_workflow_yaml_validity_dual_mode() -> None:
    with TestClient(app) as client:
        projects = client.get("/api/projects").json()
        assert len(projects) >= 1
        pid = projects[0]["id"]

        # 1. Published Container mode
        c_resp = client.get(
            f"/api/projects/{pid}/cicd/github-actions?mode=container&image=ghcr.io/acme/bastion-cli:v2.1"
        )
        assert c_resp.status_code == 200
        c_payload = c_resp.json()
        assert c_payload["mode"] == "container"
        assert c_payload["image"] == "ghcr.io/acme/bastion-cli:v2.1"
        c_yaml = c_payload["yaml_content"]
        c_doc = yaml.safe_load(c_yaml)
        assert isinstance(c_doc, dict)
        assert "jobs" in c_doc and "bastion-release-gate" in c_doc["jobs"]
        c_steps = c_doc["jobs"]["bastion-release-gate"]["steps"]
        assert isinstance(c_steps, list) and len(c_steps) >= 4
        assert "ghcr.io/acme/bastion-cli:v2.1" in c_yaml
        assert "--scope diff" in c_yaml
        assert "--scanner gitleaks" in c_yaml
        assert "github/codeql-action/upload-sarif@v3" in c_yaml
        assert "actions/upload-artifact@v4" in c_yaml
        assert "secrets.GEMINI_API_KEY" in c_yaml
        assert "secrets.ANTHROPIC_API_KEY" in c_yaml
        assert "secrets.OPENAI_API_KEY" in c_yaml
        assert "exit 10" in c_yaml and "exit 20" in c_yaml and "exit 30" in c_yaml

        # 2. Self-Built Dockerfile.cli mode
        s_resp = client.get(f"/api/projects/{pid}/cicd/github-actions?mode=self-built")
        assert s_resp.status_code == 200
        s_payload = s_resp.json()
        assert s_payload["mode"] == "self-built"
        s_yaml = s_payload["yaml_content"]
        s_doc = yaml.safe_load(s_yaml)
        assert isinstance(s_doc, dict)
        assert "jobs" in s_doc and "bastion-release-gate" in s_doc["jobs"]
        assert "docker build -f Dockerfile.cli" in s_yaml
        assert "--scope diff" in s_yaml
        assert "--scanner gitleaks" in s_yaml
        assert "github/codeql-action/upload-sarif@v3" in s_yaml

    # 3. Verify Dockerfile.cli is multi-stage, non-root, and AGPL-clean by default
    dockerfile_path = PROJECT_ROOT / "Dockerfile.cli"
    assert dockerfile_path.exists()
    df_text = dockerfile_path.read_text(encoding="utf-8")
    assert "ARG INSTALL_TRUFFLEHOG=false" in df_text
    assert "AS builder" in df_text and "AS runtime" in df_text
    assert "USER bastion" in df_text
    assert "gitleaks" in df_text
    assert "bla-agents" in df_text
