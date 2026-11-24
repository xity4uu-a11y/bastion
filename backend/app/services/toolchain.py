from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from app.config import PROJECT_ROOT, settings
from app.schemas import SystemToolsResponse, ToolStatus
from app.services.keys import ensure_ed25519_keypair


def _run_version(cmd: list[str], timeout: float = 15.0) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        out = (proc.stdout or proc.stderr or "").strip()
        first_line = next((line.strip() for line in out.splitlines() if line.strip()), "")
        return proc.returncode == 0 or bool(first_line), first_line
    except Exception as exc:
        return False, str(exc)


def find_trufflehog() -> str | None:
    candidates: list[str] = []
    which = shutil.which("trufflehog")
    if which:
        candidates.append(which)
    home = Path.home()
    for p in [
        home / ".local" / "bin" / "trufflehog.exe",
        home / ".local" / "bin" / "trufflehog",
        home / "go" / "bin" / "trufflehog.exe",
        home / "go" / "bin" / "trufflehog",
        Path("/usr/local/bin/trufflehog"),
    ]:
        if p.exists():
            candidates.append(str(p))
    return candidates[0] if candidates else None


def find_gitleaks() -> str | None:
    which = shutil.which("gitleaks")
    if which:
        return which
    home = Path.home()
    for p in [
        home / ".local" / "bin" / "gitleaks.exe",
        home / ".local" / "bin" / "gitleaks",
        home / "go" / "bin" / "gitleaks.exe",
        home / "go" / "bin" / "gitleaks",
        Path("/usr/local/bin/gitleaks"),
    ]:
        if p.exists():
            return str(p)
    return None


def find_bla_command() -> list[str] | None:
    is_win = os.name == "nt"
    names = ["bla.cmd", "bla-agents.cmd", "bla", "bla-agents"] if is_win else ["bla", "bla-agents"]
    for name in names:
        found = shutil.which(name)
        if found:
            if is_win and found.lower().endswith(".ps1"):
                cmd_sibling = found[:-4] + ".cmd"
                if Path(cmd_sibling).exists():
                    return [cmd_sibling]
                continue
            return [found]
    if is_win:
        search_dirs = [
            Path(os.environ.get("APPDATA", "")) / "npm",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "nodejs",
        ]
        node_bin = shutil.which("node")
        if node_bin:
            search_dirs.insert(0, Path(node_bin).parent)
        for directory in search_dirs:
            for exe in ("bla.cmd", "bla-agents.cmd"):
                p = directory / exe
                if p.exists():
                    return [str(p)]
    return None


def find_node() -> str | None:
    return shutil.which("node")


def find_git() -> str | None:
    return shutil.which("git")


def inspect_toolchain() -> SystemToolsResponse:
    # 1a. TruffleHog (external AGPL CLI plugin)
    th_path = find_trufflehog()
    if th_path and not settings.force_simulation:
        ok, ver = _run_version([th_path, "--version"])
        th_status = ToolStatus(
            name="TruffleHog (External CLI)",
            installed=ok,
            version=ver if ok else None,
            path=th_path,
            mode="live" if ok else "simulation_fallback",
            details="External user-installed CLI plugin with live secret verification" if ok else f"Binary error: {ver}",
        )
    else:
        th_status = ToolStatus(
            name="TruffleHog (External CLI)",
            installed=False,
            version=None,
            path=None,
            mode="simulation_fallback",
            details="Not installed on host PATH; select Gitleaks (MIT) or install TruffleHog externally.",
        )

    # 1b. Gitleaks (MIT alternative)
    gl_path = find_gitleaks()
    if gl_path and not settings.force_simulation:
        ok, ver = _run_version([gl_path, "version"])
        gl_status = ToolStatus(
            name="Gitleaks (MIT Plugin)",
            installed=ok,
            version=ver if ok else None,
            path=gl_path,
            mode="live" if ok else "simulation_fallback",
            details="MIT-licensed alternative secret scanner plugin" if ok else f"Binary error: {ver}",
        )
    else:
        gl_status = ToolStatus(
            name="Gitleaks (MIT Plugin)",
            installed=False,
            version=None,
            path=None,
            mode="simulation_fallback",
            details="Optional MIT-licensed alternative for Gate 1; install via brew/winget/GitHub Releases.",
        )

    # 2. Cloudflare Security Audit Skill
    cf_dir = settings.resolved_cloudflare_skill_dir
    node_path = find_node()
    if cf_dir and not settings.force_simulation:
        has_validators = (cf_dir / "validate-findings.cjs").exists() and (cf_dir / "validate-coverage-ledger.cjs").exists()
        cf_status = ToolStatus(
            name="Cloudflare Security Audit Skill",
            installed=True,
            version="6-phase / schema-v1",
            path=str(cf_dir),
            mode="live" if (has_validators and node_path) else "simulation_fallback",
            details=(
                "Installed with report-schema.json, validate-findings.cjs, and validate-coverage-ledger.cjs"
                if has_validators
                else "Skill directory found; schema validators unavailable."
            ),
        )
    else:
        cf_status = ToolStatus(
            name="Cloudflare Security Audit Skill",
            installed=False,
            version=None,
            path=None,
            mode="simulation_fallback",
            details="Skill not found; Gate 2 will use built-in schema fallback.",
        )

    # 3. BLA (Blind LLM Agents)
    bla_cmd = find_bla_command()
    if bla_cmd and not settings.force_simulation:
        ok, ver = _run_version([*bla_cmd, "--version"])
        bla_status = ToolStatus(
            name="BLA (bla-agents)",
            installed=ok,
            version=ver if ok else None,
            path=bla_cmd[0],
            mode="live" if ok else "simulation_fallback",
            details="Counter-REA build hardening engine with .bla-hardened staging, --apply, and --restore" if ok else ver,
        )
    else:
        bla_status = ToolStatus(
            name="BLA (bla-agents)",
            installed=False,
            version=None,
            path=None,
            mode="simulation_fallback",
            details="Not installed; Gate 3 will run in fallback simulation mode.",
        )

    # 4. Node.js
    if node_path:
        ok, ver = _run_version([node_path, "--version"])
        node_status = ToolStatus(
            name="Node.js",
            installed=ok,
            version=ver if ok else None,
            path=node_path,
            mode="live" if ok else "simulation_fallback",
            details="Required for BLA CLI and Cloudflare schema validators",
        )
    else:
        node_status = ToolStatus(
            name="Node.js",
            installed=False,
            version=None,
            path=None,
            mode="simulation_fallback",
            details="Node.js not detected on PATH",
        )

    # 5. Git
    git_path = find_git()
    if git_path:
        ok, ver = _run_version([git_path, "--version"])
        git_status = ToolStatus(
            name="Git",
            installed=ok,
            version=ver if ok else None,
            path=git_path,
            mode="live" if ok else "simulation_fallback",
            details="Git history scanning and commit metadata capture",
        )
    else:
        git_status = ToolStatus(
            name="Git",
            installed=False,
            version=None,
            path=None,
            mode="simulation_fallback",
            details="Git not detected on PATH",
        )

    key_info = ensure_ed25519_keypair()
    gate1_live = th_status.mode == "live" or gl_status.mode == "live"
    all_live = gate1_live and cf_status.mode == "live" and bla_status.mode == "live"
    return SystemToolsResponse(
        trufflehog=th_status,
        gitleaks=gl_status,
        cloudflare_skill=cf_status,
        bla=bla_status,
        node=node_status,
        git=git_status,
        all_live=all_live,
        ed25519_key_fingerprint=key_info.key_fingerprint,
        ed25519_public_key_path=str(key_info.public_key_path),
        setup_ps1_path=str(PROJECT_ROOT / "setup.ps1"),
        setup_sh_path=str(PROJECT_ROOT / "setup.sh"),
    )


def get_git_metadata(target_path: Path) -> tuple[bool, str | None, str | None, bool]:
    git_path = find_git()
    if not git_path or not (target_path / ".git").exists():
        return False, None, None, False
    try:
        commit_p = subprocess.run(
            [git_path, "-C", str(target_path), "rev-parse", "--short=12", "HEAD"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        branch_p = subprocess.run(
            [git_path, "-C", str(target_path), "rev-parse", "--abbrev-ref", "HEAD"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        dirty_p = subprocess.run(
            [git_path, "-C", str(target_path), "status", "--porcelain"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        commit = commit_p.stdout.strip() if commit_p.returncode == 0 else None
        branch = branch_p.stdout.strip() if branch_p.returncode == 0 else None
        dirty = bool(dirty_p.stdout.strip()) if dirty_p.returncode == 0 else False
        return True, commit, branch, dirty
    except Exception:
        return True, None, None, False
