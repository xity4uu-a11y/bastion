from __future__ import annotations

import os
import re
import time
from pathlib import Path

from app.services.event_bus import event_bus
from app.services.scanners.base import (
    ScannerExecutionResult,
    SecretFindingData,
    SecretScanner,
    make_secret_fingerprint,
    redact_secret,
)

SKIP_DIRS = {".git", "node_modules", ".bla-hardened", ".venv", "venv", "__pycache__", ".next", "vendor"}

FALLBACK_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], bool]] = [
    ("AWS", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), True),
    ("GitHub", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), True),
    ("Stripe", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), True),
    ("PrivateKey", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), True),
    ("Slack", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b"), False),
    ("GenericAPIKey", re.compile(r"(?i)(?:api[_-]?key|secret[_-]?token)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{24,})['\"]"), False),
]


class SimulationSecretScanner(SecretScanner):
    """Built-in fallback regex scanner used when no external secret CLI is installed or simulation is requested."""

    name = "simulation-regex"
    license_spdx = "MIT"

    def __init__(self, requested_engine: str = "auto") -> None:
        self.requested_engine = requested_engine

    def binary_path(self) -> str | None:
        return None

    def is_available(self) -> bool:
        return True

    def scan(self, run_id: str, target_path: Path) -> ScannerExecutionResult:
        start = time.perf_counter()
        event_bus.emit_log(
            run_id,
            1,
            f"[SIMULATION MODE] External scanner ({self.requested_engine}) unavailable or simulation enabled. Running fallback regex secret detector.",
            "warn",
        )
        dedup: dict[str, SecretFindingData] = {}
        scanned = 0

        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                if event_bus.is_cancelled(run_id):
                    return ScannerExecutionResult(
                        status="aborted",
                        mode="simulation",
                        engine_name=self.name,
                        duration_ms=int((time.perf_counter() - start) * 1000),
                        summary="Gate 1 aborted by operator.",
                        findings=list(dedup.values()),
                        metadata={"scanner_engine": self.name},
                    )
                fpath = Path(root) / fname
                try:
                    if fpath.stat().st_size > 512 * 1024:
                        continue
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                scanned += 1
                rel = fpath.resolve().relative_to(target_path.resolve()).as_posix()
                for lineno, line in enumerate(content.splitlines(), start=1):
                    for detector, pattern, default_verified in FALLBACK_SECRET_PATTERNS:
                        m = pattern.search(line)
                        if m:
                            token = m.group(0)
                            is_placeholder = any(
                                w in line.lower() for w in ("example", "dummy", "placeholder", "your_", "test_key", "redacted")
                            )
                            verified = default_verified and not is_placeholder
                            fp = make_secret_fingerprint("simulation", detector, rel, lineno, None)
                            dedup[fp] = SecretFindingData(
                                fingerprint=fp,
                                detector_name=detector,
                                description=f"Fallback scanner matched {detector} credential pattern.",
                                file_path=rel,
                                line_number=lineno,
                                verified=verified,
                                redacted_secret=redact_secret(token),
                                git_commit=None,
                                source_kind="simulation-filesystem",
                                scanner_engine="simulation-regex",
                            )

        event_bus.emit_log(run_id, 1, f"Fallback scanner inspected {scanned} files.", "info")
        findings = list(dedup.values())
        verified_count = sum(1 for f in findings if f.verified)
        unverified_count = len(findings) - verified_count
        duration_ms = int((time.perf_counter() - start) * 1000)

        if verified_count > 0:
            status = "failed"
            summary = f"BLOCKED: {verified_count} high-confidence secret(s) detected ({unverified_count} candidate)."
            event_bus.emit_log(run_id, 1, summary, "error")
        elif unverified_count > 0:
            status = "warn"
            summary = f"Passed with warnings: {unverified_count} unverified candidate(s) for review."
            event_bus.emit_log(run_id, 1, summary, "warn")
        else:
            status = "passed"
            summary = "Clean: 0 secrets detected across simulation-filesystem."
            event_bus.emit_log(run_id, 1, summary, "success")

        return ScannerExecutionResult(
            status=status,
            mode="simulation",
            engine_name=self.name,
            duration_ms=duration_ms,
            summary=summary,
            findings=findings,
            metadata={
                "scanner_engine": self.name,
                "scanner_license": self.license_spdx,
                "scanned_sources": ["simulation-filesystem"],
                "verified_count": verified_count,
                "unverified_count": unverified_count,
                "binary": None,
            },
        )
