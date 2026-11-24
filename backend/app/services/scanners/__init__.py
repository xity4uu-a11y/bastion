from __future__ import annotations

from app.services.scanners.base import (
    ScannerExecutionResult,
    SecretFindingData,
    SecretScanner,
    make_secret_fingerprint,
    normalize_rel_path,
    redact_secret,
)
from app.services.scanners.fallback import SimulationSecretScanner
from app.services.scanners.gitleaks import GitleaksScanner
from app.services.scanners.trufflehog import TruffleHogScanner


def resolve_secret_scanner(
    preference: str = "auto",
    force_simulation: bool = False,
) -> SecretScanner:
    """Select an AGPL-safe external CLI secret scanner plugin based on project config."""
    pref = (preference or "auto").lower().strip()
    if force_simulation:
        return SimulationSecretScanner(requested_engine=pref)

    th = TruffleHogScanner()
    gl = GitleaksScanner()

    if pref == "gitleaks":
        return gl if gl.is_available() else SimulationSecretScanner(requested_engine="gitleaks")
    if pref == "trufflehog":
        return th if th.is_available() else SimulationSecretScanner(requested_engine="trufflehog")

    # "auto": prefer TruffleHog -> Gitleaks (MIT) -> Simulation fallback
    if th.is_available():
        return th
    if gl.is_available():
        return gl
    return SimulationSecretScanner(requested_engine="auto")


__all__ = [
    "SecretScanner",
    "SecretFindingData",
    "ScannerExecutionResult",
    "TruffleHogScanner",
    "GitleaksScanner",
    "SimulationSecretScanner",
    "resolve_secret_scanner",
    "make_secret_fingerprint",
    "normalize_rel_path",
    "redact_secret",
]
