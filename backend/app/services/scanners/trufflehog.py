from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

from app.services.event_bus import event_bus
from app.services.scanners.base import (
    ScannerExecutionResult,
    SecretFindingData,
    SecretScanner,
    make_secret_fingerprint,
    normalize_rel_path,
    redact_secret,
)
from app.services.toolchain import find_trufflehog


class TruffleHogScanner(SecretScanner):
    """External user-installed TruffleHog CLI plugin (strict subprocess boundary, zero vendored AGPL code)."""

    name = "trufflehog"
    license_spdx = "AGPL-3.0-only (external CLI plugin)"

    def binary_path(self) -> str | None:
        return find_trufflehog()

    @staticmethod
    def parse_json_line(line: str, target_path: Path, source_kind: str) -> SecretFindingData | None:
        line = line.strip()
        if not line or not line.startswith("{"):
            return None
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return None
        if "DetectorName" not in obj:
            return None

        detector = str(obj.get("DetectorName") or "UnknownDetector")
        desc = str(obj.get("DetectorDescription") or f"Potential {detector} credential detected by TruffleHog.")
        verified = bool(obj.get("Verified", False))
        raw = str(obj.get("Raw") or "")
        redacted_field = str(obj.get("Redacted") or "")
        extra = obj.get("ExtraData") or {}
        rotation = str(extra.get("rotation_guide") or "") if isinstance(extra, dict) else ""

        source_data = (obj.get("SourceMetadata") or {}).get("Data") or {}
        fs_meta = source_data.get("Filesystem") or {}
        git_meta = source_data.get("Git") or {}

        if git_meta:
            raw_file = str(git_meta.get("file") or "")
            line_num = int(git_meta.get("line") or 1)
            commit = str(git_meta.get("commit") or "")[:12] or None
        else:
            raw_file = str(fs_meta.get("file") or "")
            line_num = int(fs_meta.get("line") or 1)
            commit = None

        rel_file = normalize_rel_path(target_path, raw_file)
        if rel_file.startswith(".bla-hardened/") or "/.bla-hardened/" in rel_file:
            return None

        return SecretFindingData(
            fingerprint=make_secret_fingerprint("trufflehog", detector, rel_file, line_num, commit),
            detector_name=detector,
            description=desc,
            file_path=rel_file,
            line_number=max(1, line_num),
            verified=verified,
            redacted_secret=redact_secret(raw, redacted_field),
            git_commit=commit,
            source_kind=source_kind,
            rotation_guide=rotation,
            scanner_engine="trufflehog",
        )

    def _run_subcommand(
        self,
        run_id: str,
        cmd: list[str],
        target_path: Path,
        source_kind: str,
    ) -> tuple[list[SecretFindingData], int, bool]:
        findings: list[SecretFindingData] = []
        aborted = False
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
                    aborted = True
                    proc.terminate()
                    break
                parsed = self.parse_json_line(raw_line, target_path, source_kind)
                if parsed:
                    findings.append(parsed)
                    lvl = "error" if parsed.verified else "warn"
                    state = "VERIFIED LIVE" if parsed.verified else "UNVERIFIED"
                    event_bus.emit_log(
                        run_id,
                        1,
                        f"[{state}] {parsed.detector_name} in {parsed.file_path}:{parsed.line_number} ({parsed.redacted_secret})",
                        lvl,
                    )
                else:
                    trimmed = raw_line.strip()
                    if trimmed.startswith("{"):
                        try:
                            log_obj = json.loads(trimmed)
                            msg = str(log_obj.get("msg") or "")
                            if msg == "finished scanning":
                                chunks = log_obj.get("chunks", 0)
                                nbytes = log_obj.get("bytes", 0)
                                dur = log_obj.get("scan_duration", "")
                                event_bus.emit_log(
                                    run_id,
                                    1,
                                    f"trufflehog({source_kind}): scanned {chunks} chunks ({nbytes} bytes) in {dur}",
                                    "info",
                                )
                            elif log_obj.get("level") == "error":
                                event_bus.emit_log(
                                    run_id,
                                    1,
                                    f"trufflehog({source_kind}) warning: {str(log_obj.get('error') or msg)[:220]}",
                                    "warn",
                                )
                        except json.JSONDecodeError:
                            pass
            rc = proc.wait(timeout=180)
            return findings, rc, aborted
        finally:
            event_bus.unregister_process(run_id, proc)

    def scan(self, run_id: str, target_path: Path) -> ScannerExecutionResult:
        start = time.perf_counter()
        th_bin = self.binary_path()
        if not th_bin:
            raise RuntimeError("TruffleHog binary not installed on host PATH")

        event_bus.emit_log(run_id, 1, f"Using external TruffleHog CLI plugin: {th_bin}", "info")
        dedup: dict[str, SecretFindingData] = {}
        scanned_sources: list[str] = []

        fs_cmd = [th_bin, "filesystem", ".", "--json", "--no-update"]
        fs_findings, _, aborted = self._run_subcommand(run_id, fs_cmd, target_path, "filesystem")
        scanned_sources.append("filesystem")
        for f in fs_findings:
            dedup[f.fingerprint] = f
        if aborted:
            return ScannerExecutionResult(
                status="aborted",
                mode="live",
                engine_name=self.name,
                duration_ms=int((time.perf_counter() - start) * 1000),
                summary="Gate 1 aborted by operator.",
                findings=list(dedup.values()),
                metadata={"scanned_sources": scanned_sources, "scanner_engine": self.name},
            )

        if (target_path / ".git").exists():
            git_cmd = [th_bin, "git", "file://.", "--json", "--no-update"]
            git_findings, _, aborted = self._run_subcommand(run_id, git_cmd, target_path, "git")
            scanned_sources.append("git")
            for f in git_findings:
                dedup[f.fingerprint] = f
            if aborted:
                return ScannerExecutionResult(
                    status="aborted",
                    mode="live",
                    engine_name=self.name,
                    duration_ms=int((time.perf_counter() - start) * 1000),
                    summary="Gate 1 aborted by operator.",
                    findings=list(dedup.values()),
                    metadata={"scanned_sources": scanned_sources, "scanner_engine": self.name},
                )
        else:
            event_bus.emit_log(run_id, 1, "Target is not a Git repository; skipped git history scan.", "info")

        findings = list(dedup.values())
        verified_count = sum(1 for f in findings if f.verified)
        unverified_count = len(findings) - verified_count
        duration_ms = int((time.perf_counter() - start) * 1000)

        if verified_count > 0:
            status = "failed"
            summary = f"BLOCKED: {verified_count} verified live secret(s) detected ({unverified_count} unverified)."
            event_bus.emit_log(run_id, 1, summary, "error")
        elif unverified_count > 0:
            status = "warn"
            summary = f"Passed with warnings: 0 verified live secrets, {unverified_count} unverified candidate(s) for review."
            event_bus.emit_log(run_id, 1, summary, "warn")
        else:
            status = "passed"
            summary = f"Clean: 0 secrets detected across {', '.join(scanned_sources)} (TruffleHog)."
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
                "scanned_sources": scanned_sources,
                "verified_count": verified_count,
                "unverified_count": unverified_count,
                "binary": th_bin,
            },
        )
