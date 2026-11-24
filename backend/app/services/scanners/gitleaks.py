from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from app.services.event_bus import event_bus
from app.services.scanners.base import (
    ScannerExecutionResult,
    SecretFindingData,
    SecretScanner,
    make_secret_fingerprint,
    normalize_rel_path,
    redact_secret,
)
from app.services.toolchain import find_gitleaks

# High-confidence provider token rules that treat matches as blocking even without live API pings
HIGH_CONFIDENCE_RULES = {
    "aws-access-token",
    "github-pat",
    "github-fine-grained-pat",
    "github-oauth",
    "stripe-access-token",
    "private-key",
    "slack-access-token",
    "gcp-api-key",
    "openai-api-key",
    "anthropic-api-key",
}


class GitleaksScanner(SecretScanner):
    """MIT-licensed Gitleaks CLI plugin normalized to Bastion's SecretFindingData schema."""

    name = "gitleaks"
    license_spdx = "MIT"

    def binary_path(self) -> str | None:
        return find_gitleaks()

    @staticmethod
    def parse_report_items(
        items: list[dict[str, Any]],
        target_path: Path,
        source_kind: str,
    ) -> list[SecretFindingData]:
        normalized: list[SecretFindingData] = []
        for entry in items:
            if not isinstance(entry, dict):
                continue
            rule_id = str(entry.get("RuleID") or entry.get("ruleID") or "gitleaks-secret")
            desc = str(entry.get("Description") or f"Potential {rule_id} secret detected by Gitleaks.")
            raw_file = str(entry.get("File") or "")
            rel_file = normalize_rel_path(target_path, raw_file)
            if rel_file.startswith(".bla-hardened/") or "/.bla-hardened/" in rel_file:
                continue
            line_num = int(entry.get("StartLine") or entry.get("LineNumber") or 1)
            raw_secret = str(entry.get("Secret") or entry.get("Match") or "")
            commit = str(entry.get("Commit") or "")[:12] or None
            is_high_conf = rule_id.lower() in HIGH_CONFIDENCE_RULES or "private-key" in rule_id.lower()

            normalized.append(
                SecretFindingData(
                    fingerprint=make_secret_fingerprint("gitleaks", rule_id, rel_file, line_num, commit),
                    detector_name=rule_id,
                    description=desc,
                    file_path=rel_file,
                    line_number=max(1, line_num),
                    verified=is_high_conf,
                    redacted_secret=redact_secret(raw_secret),
                    git_commit=commit,
                    source_kind=source_kind,
                    rotation_guide="Revoke and rotate this secret, then purge it from Git history.",
                    scanner_engine="gitleaks",
                )
            )
        return normalized

    def scan(self, run_id: str, target_path: Path) -> ScannerExecutionResult:
        start = time.perf_counter()
        gl_bin = self.binary_path()
        if not gl_bin:
            raise RuntimeError("Gitleaks binary not installed on host PATH")

        event_bus.emit_log(run_id, 1, f"Using MIT-licensed Gitleaks CLI plugin: {gl_bin}", "info")
        is_git = (target_path / ".git").exists()
        source_kind = "gitleaks-git" if is_git else "gitleaks-filesystem"

        with tempfile.TemporaryDirectory(prefix="bastion-gitleaks-") as tmp_dir:
            report_path = Path(tmp_dir) / "gitleaks-report.json"
            cmd = [
                gl_bin,
                "detect",
                "--source",
                ".",
                "--report-format",
                "json",
                "--report-path",
                str(report_path),
                "--no-banner",
                "--exit-code",
                "0",
            ]
            if not is_git:
                cmd.append("--no-git")

            event_bus.emit_log(run_id, 1, f"Executing external plugin: {' '.join(cmd)}", "info")
            proc = subprocess.Popen(
                cmd,
                cwd=str(target_path),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            event_bus.register_process(run_id, proc)
            try:
                assert proc.stdout is not None
                for raw_line in proc.stdout:
                    if event_bus.is_cancelled(run_id):
                        proc.terminate()
                        return ScannerExecutionResult(
                            status="aborted",
                            mode="live",
                            engine_name=self.name,
                            duration_ms=int((time.perf_counter() - start) * 1000),
                            summary="Gate 1 aborted by operator.",
                            metadata={"scanner_engine": self.name},
                        )
                    line = raw_line.strip()
                    if line:
                        event_bus.emit_log(run_id, 1, f"gitleaks: {line[:220]}", "info")
                proc.wait(timeout=180)
            finally:
                event_bus.unregister_process(run_id, proc)

            items: list[dict[str, Any]] = []
            if report_path.exists():
                raw_json = report_path.read_text(encoding="utf-8", errors="ignore").strip()
                if raw_json:
                    parsed = json.loads(raw_json)
                    if isinstance(parsed, list):
                        items = parsed

        findings = self.parse_report_items(items, target_path, source_kind)
        for f in findings:
            lvl = "error" if f.verified else "warn"
            state = "HIGH-CONFIDENCE SECRET" if f.verified else "CANDIDATE"
            event_bus.emit_log(
                run_id,
                1,
                f"[{state}] {f.detector_name} in {f.file_path}:{f.line_number} ({f.redacted_secret})",
                lvl,
            )

        verified_count = sum(1 for f in findings if f.verified)
        unverified_count = len(findings) - verified_count
        duration_ms = int((time.perf_counter() - start) * 1000)

        if verified_count > 0:
            status = "failed"
            summary = f"BLOCKED: {verified_count} high-confidence secret(s) detected by Gitleaks ({unverified_count} additional)."
            event_bus.emit_log(run_id, 1, summary, "error")
        elif unverified_count > 0:
            status = "warn"
            summary = f"Passed with warnings: {unverified_count} candidate secret(s) flagged by Gitleaks."
            event_bus.emit_log(run_id, 1, summary, "warn")
        else:
            status = "passed"
            summary = f"Clean: 0 secrets detected across {source_kind} (Gitleaks MIT)."
            event_bus.emit_log(run_id, 1, summary, "success")

        return ScannerExecutionResult(
            status=status,
            mode="live",
            engine_name=self.name,
            duration_ms=duration_ms,
            summary=summary,
            findings=findings,
            metadata={
                "scanner_engine": self.name,
                "scanner_license": self.license_spdx,
                "scanned_sources": [source_kind],
                "verified_count": verified_count,
                "unverified_count": unverified_count,
                "binary": gl_bin,
            },
        )
