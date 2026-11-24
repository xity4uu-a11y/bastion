from __future__ import annotations

import abc
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class SecretFindingData:
    fingerprint: str
    detector_name: str
    description: str
    file_path: str
    line_number: int
    verified: bool
    redacted_secret: str
    git_commit: str | None = None
    source_kind: str = "filesystem"
    rotation_guide: str = ""
    scanner_engine: str = "trufflehog"


@dataclass
class ScannerExecutionResult:
    status: str  # passed | warn | failed | aborted
    mode: str  # live | simulation
    engine_name: str  # trufflehog | gitleaks | simulation-regex
    duration_ms: int
    summary: str
    findings: list[SecretFindingData] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


def redact_secret(raw: str, existing_redacted: str = "") -> str:
    if existing_redacted and len(existing_redacted.strip()) >= 4:
        val = existing_redacted.strip()
        if len(val) > 8:
            return f"{val[:4]}...{val[-4:]}"
        return "****"
    val = (raw or "").strip()
    if not val or len(val) <= 8:
        return "****"
    return f"{val[:4]}{'*' * min(12, len(val) - 8)}{val[-4:]}"


def make_secret_fingerprint(
    engine: str,
    detector: str,
    file_path: str,
    line_number: int,
    commit: str | None,
) -> str:
    key = f"{engine}:{detector}:{file_path}:{line_number}:{commit or 'fs'}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    safe_det = re.sub(r"[^A-Za-z0-9._-]+", "-", detector.lower()).strip("-") or "secret"
    return f"gate1/{engine}/{safe_det}/{digest}"


def normalize_rel_path(target_path: Path, raw_file: str) -> str:
    if not raw_file:
        return "unknown"
    try:
        p = Path(raw_file)
        if p.is_absolute():
            return p.resolve().relative_to(target_path.resolve()).as_posix()
    except Exception:
        pass
    return raw_file.replace("\\", "/").lstrip("./")


class SecretScanner(abc.ABC):
    """AGPL-safe pluggable interface for external Gate 1 secret scanning engines."""

    name: str
    license_spdx: str

    @abc.abstractmethod
    def binary_path(self) -> str | None:
        """Return absolute path to external user-installed scanner CLI, or None."""

    def is_available(self) -> bool:
        return self.binary_path() is not None

    @abc.abstractmethod
    def scan(self, run_id: str, target_path: Path) -> ScannerExecutionResult:
        """Execute secret scan and return normalized Bastion findings."""
