from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.config import settings
from app.services.event_bus import event_bus
from app.services.toolchain import find_bla_command
from app.services.vault import scrub_secrets

BUILD_DIR_NAMES = {"dist", "build", "out", "release"}
ARTIFACT_EXTENSIONS: dict[str, tuple[str, str]] = {
    ".asar": ("electron-asar", "desktop"),
    ".wasm": ("webassembly", "binary"),
    ".py": ("python-source", "python"),
    ".pyc": ("python-bytecode", "python"),
    ".js": ("javascript", "bundle"),
    ".mjs": ("javascript", "bundle"),
    ".cjs": ("javascript", "bundle"),
    ".exe": ("native-pe", "native-binary"),
    ".dll": ("native-pe", "native-binary"),
    ".so": ("native-elf", "native-binary"),
    ".dylib": ("native-macho", "native-binary"),
    ".safetensors": ("ai-safetensors", "ai-model"),
    ".gguf": ("ai-gguf", "ai-model"),
    ".sqlite": ("sqlite-db", "database"),
    ".db": ("sqlite-db", "database"),
}
SKIP_DIRS = {".git", "node_modules", ".bla-hardened", ".venv", "venv", "__pycache__", "vendor"}

SENSITIVE_ENV_PREFIXES = (
    "GEMINI_",
    "ANTHROPIC_",
    "OPENAI_",
    "BASTION_",
    "AWS_",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "STRIPE_",
    "NPM_TOKEN",
)


@dataclass
class ArtifactData:
    relative_path: str
    artifact_format: str
    category: str
    input_bytes: int
    output_bytes: int
    mirror_path: str | None
    intensity: str
    status: str
    defense_score: float
    token_amplification: float
    cost_amplification: float
    before_exposure_score: float
    verified: bool


@dataclass
class SmokeTestResult:
    status: str  # passed | failed | timeout | skipped
    command: str
    exit_code: int | None = None
    duration_ms: int = 0
    stdout: str = ""
    stderr: str = ""
    tested_mirror: bool = False
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "command": self.command,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "tested_mirror": self.tested_mirror,
            "message": self.message,
        }


@dataclass
class Gate3Result:
    status: str
    mode: str
    duration_ms: int
    summary: str
    artifacts: list[ArtifactData] = field(default_factory=list)
    mirror_dir: str | None = None
    smoke_test: SmokeTestResult | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


def discover_build_artifacts(target_path: Path) -> list[ArtifactData]:
    discovered: list[ArtifactData] = []
    seen: set[str] = set()

    for root, dirs, files in os.walk(target_path):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        root_path = Path(root)
        try:
            rel_parts = root_path.resolve().relative_to(target_path.resolve()).parts
        except ValueError:
            continue
        in_build_dir = any(part.lower() in BUILD_DIR_NAMES for part in rel_parts)

        for fname in sorted(files):
            fpath = root_path / fname
            ext = fpath.suffix.lower()
            if ext not in ARTIFACT_EXTENSIONS:
                continue
            always_include = ext in {".asar", ".wasm", ".pyc", ".exe", ".dll", ".so", ".dylib", ".safetensors", ".gguf"}
            if not always_include and not in_build_dir:
                continue
            rel = fpath.resolve().relative_to(target_path.resolve()).as_posix()
            if rel in seen:
                continue
            seen.add(rel)
            fmt, cat = ARTIFACT_EXTENSIONS[ext]
            try:
                size = fpath.stat().st_size
            except OSError:
                size = 0
            discovered.append(
                ArtifactData(
                    relative_path=rel,
                    artifact_format=fmt,
                    category=cat,
                    input_bytes=size,
                    output_bytes=0,
                    mirror_path=None,
                    intensity="balanced",
                    status="discovered",
                    defense_score=0.0,
                    token_amplification=0.0,
                    cost_amplification=0.0,
                    before_exposure_score=78.0,
                    verified=False,
                )
            )
    return discovered[:64]


def _parse_json_output(raw: str) -> dict[str, Any] | None:
    text = (raw or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                return None
    return None


def _category_from_format(fmt: str, rel_path: str) -> str:
    ext = Path(rel_path).suffix.lower()
    if ext in ARTIFACT_EXTENSIONS:
        return ARTIFACT_EXTENSIONS[ext][1]
    if "python" in fmt:
        return "python"
    if "wasm" in fmt:
        return "binary"
    if "asar" in fmt:
        return "desktop"
    if "model" in fmt or "safetensors" in fmt or "gguf" in fmt:
        return "ai-model"
    return "bundle"


def _build_clean_smoke_env(target_path: Path) -> dict[str, str]:
    clean: dict[str, str] = {}
    for k, v in os.environ.items():
        up = k.upper()
        if any(up.startswith(pref) for pref in SENSITIVE_ENV_PREFIXES):
            continue
        clean[k] = v
    node_modules = target_path / "node_modules"
    if node_modules.exists():
        existing_np = clean.get("NODE_PATH", "")
        clean["NODE_PATH"] = f"{node_modules}{os.pathsep}{existing_np}" if existing_np else str(node_modules)
    clean["BASTION_SMOKE_TEST"] = "1"
    return clean


def run_post_bla_smoke_test(
    target_path: Path,
    smoke_cmd: str,
    run_id: str | None = None,
    timeout_seconds: int | None = None,
) -> SmokeTestResult:
    cmd = (smoke_cmd or "").strip()
    if not cmd:
        return SmokeTestResult(status="skipped", command="", message="No smoke test command configured.")

    timeout = timeout_seconds or settings.smoke_test_timeout_seconds
    mirror_root = target_path / ".bla-hardened"
    has_mirror = mirror_root.exists() and any(mirror_root.rglob("*"))

    if run_id:
        event_bus.emit_log(
            run_id,
            3,
            f"Running post-BLA smoke test in isolated working copy ({'with .bla-hardened overlay' if has_mirror else 'against current build'}): {cmd}",
            "info",
        )

    start = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="bastion-smoke-") as tmp_dir:
        sandbox_root = Path(tmp_dir) / "work"

        def _ignore_heavy(_src: str, names: list[str]) -> set[str]:
            return {n for n in names if n in SKIP_DIRS}

        shutil.copytree(target_path, sandbox_root, ignore=_ignore_heavy, dirs_exist_ok=True)

        overlaid = 0
        if has_mirror:
            for root, _, files in os.walk(mirror_root):
                for fname in files:
                    if fname == "bla-harden-summary.json":
                        continue
                    src_file = Path(root) / fname
                    rel = src_file.relative_to(mirror_root)
                    dst_file = sandbox_root / rel
                    dst_file.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src_file, dst_file)
                    overlaid += 1

        clean_env = _build_clean_smoke_env(target_path)
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(sandbox_root),
                env=clean_env,
                shell=True,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
            dur_ms = int((time.perf_counter() - start) * 1000)
            stdout_clean = scrub_secrets((proc.stdout or "").strip())[:2000]
            stderr_clean = scrub_secrets((proc.stderr or "").strip())[:2000]

            if proc.returncode == 0:
                msg = f"Smoke test passed against hardened mirror ({overlaid} overlaid artifact(s), exit 0, {dur_ms} ms)."
                if run_id:
                    event_bus.emit_log(run_id, 3, msg, "success")
                return SmokeTestResult(
                    status="passed",
                    command=cmd,
                    exit_code=0,
                    duration_ms=dur_ms,
                    stdout=stdout_clean,
                    stderr=stderr_clean,
                    tested_mirror=has_mirror,
                    message=msg,
                )

            msg = f"Smoke test FAILED against hardened mirror (exit {proc.returncode}, {dur_ms} ms). Do NOT --apply before resolving."
            if run_id:
                event_bus.emit_log(run_id, 3, msg, "error")
                if stderr_clean:
                    event_bus.emit_log(run_id, 3, f"smoke stderr: {stderr_clean[:240]}", "error")
            return SmokeTestResult(
                status="failed",
                command=cmd,
                exit_code=proc.returncode,
                duration_ms=dur_ms,
                stdout=stdout_clean,
                stderr=stderr_clean,
                tested_mirror=has_mirror,
                message=msg,
            )
        except subprocess.TimeoutExpired:
            dur_ms = int((time.perf_counter() - start) * 1000)
            msg = f"Smoke test timed out after {timeout}s against hardened mirror."
            if run_id:
                event_bus.emit_log(run_id, 3, msg, "error")
            return SmokeTestResult(
                status="timeout",
                command=cmd,
                exit_code=None,
                duration_ms=dur_ms,
                tested_mirror=has_mirror,
                message=msg,
            )


def run_gate3_bla(
    run_id: str,
    target_path: Path,
    intensity: str = "balanced",
    force_simulation: bool = False,
    smoke_test_cmd: str = "",
) -> Gate3Result:
    start = time.perf_counter()
    event_bus.emit_log(
        run_id,
        3,
        f"Starting Gate 3: Anti-REA Build Hardening (BLA | intensity={intensity}) on {target_path}",
        "info",
    )

    discovered = discover_build_artifacts(target_path)
    event_bus.emit_log(
        run_id,
        3,
        f"Auto-discovered {len(discovered)} build/release artifact(s).",
        "info",
    )

    bla_cmd = None if force_simulation else find_bla_command()
    mirror_dir = str(target_path / ".bla-hardened")

    if bla_cmd:
        mode = "live"
        event_bus.emit_log(run_id, 3, f"Using live BLA CLI: {' '.join(bla_cmd)}", "info")
        cmd = [*bla_cmd, "harden", str(target_path), "--intensity", intensity, "--json"]
        event_bus.emit_log(run_id, 3, f"Executing: {' '.join(cmd)}", "info")

        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        event_bus.register_process(run_id, proc)
        try:
            stdout_data, stderr_data = proc.communicate(timeout=180)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            return Gate3Result(
                status="failed",
                mode=mode,
                duration_ms=int((time.perf_counter() - start) * 1000),
                summary="BLA hardening timed out after 180s.",
                artifacts=discovered,
                mirror_dir=mirror_dir,
            )
        finally:
            event_bus.unregister_process(run_id, proc)

        if event_bus.is_cancelled(run_id):
            return Gate3Result(
                status="aborted",
                mode=mode,
                duration_ms=int((time.perf_counter() - start) * 1000),
                summary="Gate 3 aborted by operator.",
                artifacts=discovered,
                mirror_dir=mirror_dir,
            )

        payload = _parse_json_output(stdout_data)
        if not payload:
            err_msg = (stderr_data or stdout_data or f"exit code {rc}").strip()[:240]
            event_bus.emit_log(run_id, 3, f"BLA output error: {err_msg}", "error")
            return Gate3Result(
                status="failed",
                mode=mode,
                duration_ms=int((time.perf_counter() - start) * 1000),
                summary=f"BLA execution failed: {err_msg}",
                artifacts=discovered,
                mirror_dir=mirror_dir,
            )

        mirror_dir = str(payload.get("outputDirectory") or mirror_dir)
        bla_artifacts_raw = payload.get("artifacts") or []
        by_rel: dict[str, ArtifactData] = {a.relative_path: a for a in discovered}

        for item in bla_artifacts_raw:
            rel = str(item.get("relativePath") or "").replace("\\", "/")
            if not rel:
                continue
            fmt = str(item.get("format") or "unknown")
            ok = bool(item.get("success", False))
            score = float(item.get("defenseScore") or 0.0)
            tok_amp = float(item.get("tokenAmplificationFactor") or 0.0)
            cost_amp = float(item.get("costAmplificationFactor") or 0.0)
            in_bytes = int(item.get("inputBytes") or 0)
            out_bytes = int(item.get("outputBytes") or 0)
            out_path = str(item.get("outputPath") or "")

            by_rel[rel] = ArtifactData(
                relative_path=rel,
                artifact_format=fmt,
                category=_category_from_format(fmt, rel),
                input_bytes=in_bytes,
                output_bytes=out_bytes,
                mirror_path=out_path or None,
                intensity=intensity,
                status="hardened" if ok else "failed",
                defense_score=score,
                token_amplification=tok_amp,
                cost_amplification=cost_amp,
                before_exposure_score=round(max(5.0, 100.0 - score * 0.2), 1),
                verified=ok and score >= 50.0,
            )
            event_bus.emit_log(
                run_id,
                3,
                f"[{'VERIFIED' if ok else 'FAILED'}] {rel} ({fmt}) -> defense={score}/100, tokenAmp={tok_amp}x, costAmp={cost_amp}x",
                "success" if ok else "error",
            )

        final_artifacts = list(by_rel.values())
        hardened_cnt = int(payload.get("hardenedCount") or 0)
        failed_cnt = int(payload.get("failedCount") or 0)
        discovered_cnt = int(payload.get("discoveredCount") or len(final_artifacts))

        smoke_res = run_post_bla_smoke_test(target_path, smoke_test_cmd, run_id=run_id) if smoke_test_cmd.strip() else None
        duration_ms = int((time.perf_counter() - start) * 1000)

        if smoke_res and smoke_res.status in ("failed", "timeout"):
            status = "failed"
            summary = f"BLOCKED: Post-BLA smoke test failed ({smoke_res.message})"
        elif discovered_cnt == 0:
            status = "warn"
            summary = "No build artifacts discovered (dist/, build/, .wasm, .asar, binaries). Build project before hardening."
            event_bus.emit_log(run_id, 3, summary, "warn")
        elif failed_cnt > 0:
            status = "failed"
            summary = f"BLA hardened {hardened_cnt}/{discovered_cnt} artifact(s); {failed_cnt} failed verification."
            event_bus.emit_log(run_id, 3, summary, "error")
        else:
            avg_score = round(sum(a.defense_score for a in final_artifacts if a.verified) / max(1, hardened_cnt), 1)
            smoke_suffix = " | smoke test PASSED" if (smoke_res and smoke_res.status == "passed") else ""
            status = "passed"
            summary = f"Hardened & verified {hardened_cnt} artifact(s) in .bla-hardened/ (avg defense {avg_score}/100){smoke_suffix}."
            event_bus.emit_log(run_id, 3, summary, "success")

        return Gate3Result(
            status=status,
            mode=mode,
            duration_ms=duration_ms,
            summary=summary,
            artifacts=final_artifacts,
            mirror_dir=mirror_dir,
            smoke_test=smoke_res,
            metadata={
                "blaVersion": payload.get("blaVersion"),
                "blaRunId": payload.get("runId"),
                "intensity": intensity,
                "discoveredCount": discovered_cnt,
                "hardenedCount": hardened_cnt,
                "failedCount": failed_cnt,
                "mirrorDir": mirror_dir,
                "smoke_test": smoke_res.to_dict() if smoke_res else None,
                "weaveScore": (payload.get("agentWeaveAssessment") or {}).get("weaveScore"),
                "unwovenSourceFiles": (payload.get("agentWeaveAssessment") or {}).get("unwovenSourceFiles", []),
                "nextSteps": payload.get("nextSteps", []),
            },
        )

    mode = "simulation"
    event_bus.emit_log(
        run_id,
        3,
        "[SIMULATION MODE] bla-agents CLI not detected. Creating simulated .bla-hardened/ mirror.",
        "warn",
    )
    mirror_root = target_path / ".bla-hardened"
    intensity_bonus = {"stealth": 78.0, "balanced": 88.0, "maximum": 94.0, "bankrupt": 97.0}.get(intensity, 88.0)
    amp_mult = {"stealth": 12.0, "balanced": 180.0, "maximum": 920.0, "bankrupt": 3400.0}.get(intensity, 180.0)

    for art in discovered:
        src = target_path / art.relative_path
        dst = mirror_root / art.relative_path
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(src, dst)
        except OSError:
            pass
        art.intensity = intensity
        art.mirror_path = str(dst)
        art.output_bytes = int(art.input_bytes * 1.45) + 2048
        art.defense_score = intensity_bonus
        art.token_amplification = amp_mult
        art.cost_amplification = round(amp_mult * 0.42, 1)
        art.status = "hardened"
        art.verified = True
        event_bus.emit_log(
            run_id,
            3,
            f"[SIMULATED VERIFIED] {art.relative_path} -> defense={art.defense_score}/100, tokenAmp={art.token_amplification}x",
            "info",
        )

    smoke_res = run_post_bla_smoke_test(target_path, smoke_test_cmd, run_id=run_id) if smoke_test_cmd.strip() else None
    duration_ms = int((time.perf_counter() - start) * 1000)

    if smoke_res and smoke_res.status in ("failed", "timeout"):
        status = "failed"
        summary = f"BLOCKED: Post-BLA smoke test failed ({smoke_res.message})"
    else:
        status = "passed" if discovered else "warn"
        smoke_suffix = " | smoke test PASSED" if (smoke_res and smoke_res.status == "passed") else ""
        summary = (
            f"[Simulation] Hardened {len(discovered)} artifact(s) into .bla-hardened/ (intensity={intensity}){smoke_suffix}."
            if discovered
            else "[Simulation] No build artifacts discovered in target directory."
        )
    return Gate3Result(
        status=status,
        mode=mode,
        duration_ms=duration_ms,
        summary=summary,
        artifacts=discovered,
        mirror_dir=str(mirror_root),
        smoke_test=smoke_res,
        metadata={
            "intensity": intensity,
            "discoveredCount": len(discovered),
            "hardenedCount": len(discovered),
            "failedCount": 0,
            "smoke_test": smoke_res.to_dict() if smoke_res else None,
        },
    )


def run_bla_apply(target_path: Path, intensity: str = "balanced", force_simulation: bool = False) -> dict[str, Any]:
    bla_cmd = None if force_simulation else find_bla_command()
    if bla_cmd:
        cmd = [*bla_cmd, "harden", str(target_path), "--intensity", intensity, "--apply", "--json"]
        proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=180, check=False)
        payload = _parse_json_output(proc.stdout)
        if not payload:
            raise RuntimeError((proc.stderr or proc.stdout or f"BLA apply failed (rc={proc.returncode})").strip()[:300])
        apply_info = payload.get("apply") or {}
        return {
            "status": apply_info.get("status", "applied"),
            "mode": "live",
            "affected_files": apply_info.get("applied") or [a.get("relativePath") for a in payload.get("artifacts", []) if a.get("success")],
            "backup_directory": apply_info.get("backupDirectory"),
            "message": f"Promoted {len(apply_info.get('applied', []))} hardened artifact(s) to release output.",
            "artifacts": payload.get("artifacts", []),
        }

    mirror_root = target_path / ".bla-hardened"
    backup_root = target_path / ".bla-sim-backup"
    affected: list[str] = []
    if mirror_root.exists():
        for root, _, files in os.walk(mirror_root):
            for fname in files:
                mfile = Path(root) / fname
                rel = mfile.relative_to(mirror_root).as_posix()
                orig = target_path / rel
                if orig.exists():
                    bkp = backup_root / rel
                    bkp.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(orig, bkp)
                    shutil.copy2(mfile, orig)
                    affected.append(rel)
    return {
        "status": "applied",
        "mode": "simulation",
        "affected_files": affected,
        "backup_directory": str(backup_root),
        "message": f"[Simulation] Applied {len(affected)} mirror artifact(s).",
        "artifacts": [],
    }


def run_bla_restore(target_path: Path, force_simulation: bool = False) -> dict[str, Any]:
    bla_cmd = None if force_simulation else find_bla_command()
    if bla_cmd:
        cmd = [*bla_cmd, "harden", str(target_path), "--restore", "--json"]
        proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120, check=False)
        payload = _parse_json_output(proc.stdout)
        if not payload:
            raise RuntimeError((proc.stderr or proc.stdout or f"BLA restore failed (rc={proc.returncode})").strip()[:300])
        restored = payload.get("restored") or []
        return {
            "status": payload.get("status", "restored"),
            "mode": "live",
            "affected_files": restored,
            "backup_directory": None,
            "message": f"Restored {len(restored)} original build artifact(s) from BLA backup.",
            "artifacts": [],
        }

    backup_root = target_path / ".bla-sim-backup"
    restored: list[str] = []
    if backup_root.exists():
        for root, _, files in os.walk(backup_root):
            for fname in files:
                bfile = Path(root) / fname
                rel = bfile.relative_to(backup_root).as_posix()
                dst = target_path / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(bfile, dst)
                restored.append(rel)
        shutil.rmtree(backup_root, ignore_errors=True)
    return {
        "status": "restored",
        "mode": "simulation",
        "affected_files": restored,
        "backup_directory": None,
        "message": f"[Simulation] Restored {len(restored)} original build artifact(s).",
        "artifacts": [],
    }
