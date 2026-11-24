from __future__ import annotations

from pathlib import Path

from app.services.event_bus import event_bus
from app.services.scanners import (
    ScannerExecutionResult as Gate1Result,
    SecretFindingData,
    resolve_secret_scanner,
)


def run_gate1_secret_scan(
    run_id: str,
    target_path: Path,
    scanner_preference: str = "auto",
    force_simulation: bool = False,
) -> Gate1Result:
    scanner = resolve_secret_scanner(preference=scanner_preference, force_simulation=force_simulation)
    event_bus.emit_log(
        run_id,
        1,
        f"Starting Gate 1: Secret Quarantine (engine={scanner.name}, preference={scanner_preference}) on {target_path}",
        "info",
    )
    return scanner.scan(run_id, target_path)


# Backward-compatible alias preserved from v1
def run_gate1_trufflehog(
    run_id: str,
    target_path: Path,
    force_simulation: bool = False,
    scanner_preference: str = "auto",
) -> Gate1Result:
    return run_gate1_secret_scan(
        run_id=run_id,
        target_path=target_path,
        scanner_preference=scanner_preference,
        force_simulation=force_simulation,
    )


__all__ = ["Gate1Result", "SecretFindingData", "run_gate1_secret_scan", "run_gate1_trufflehog"]
