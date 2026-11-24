from __future__ import annotations

import os
import re
import subprocess
import threading
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import settings

ENCRYPTED_PREFIX = "enc:fernet:v1:"
SECRET_SETTING_KEYS = ("gemini_api_key", "anthropic_api_key", "openai_api_key")

_SCRUB_LOCK = threading.Lock()
_REGISTERED_SECRETS: set[str] = set()

_GENERIC_KEY_PATTERNS = [
    re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{16,}\b"),
    re.compile(r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_\-]{16,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{25,}\b"),
]


def _restrict_key_permissions(key_path: Path) -> None:
    if os.name != "nt":
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
        return

    # Windows current-user-only ACL (best-effort; never breaks restricted/domain accounts)
    username = os.environ.get("USERNAME") or os.environ.get("USER")
    if not username:
        return
    try:
        subprocess.run(
            ["icacls", str(key_path), "/inheritance:r", "/grant:r", f"{username}:(R,W)"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except Exception:
        pass


def ensure_vault_master_key(keys_dir: Path | None = None) -> tuple[bytes, Path]:
    """Load or auto-generate the Fernet master key outside the project at ~/.bastion/keys/vault.key."""
    target_dir = (keys_dir or settings.resolved_keys_dir).expanduser().resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    key_path = target_dir / "vault.key"

    if key_path.exists():
        raw = key_path.read_bytes().strip()
        if raw:
            return raw, key_path

    key = Fernet.generate_key()
    key_path.write_bytes(key)
    _restrict_key_permissions(key_path)
    return key, key_path


def _get_fernet(keys_dir: Path | None = None) -> Fernet:
    key, _ = ensure_vault_master_key(keys_dir=keys_dir)
    return Fernet(key)


def is_encrypted(value: str | None) -> bool:
    return bool(value) and str(value).startswith(ENCRYPTED_PREFIX)


def encrypt_secret(plaintext: str, keys_dir: Path | None = None) -> str:
    raw = (plaintext or "").strip()
    if not raw:
        return ""
    if is_encrypted(raw):
        return raw
    register_secret_for_scrubbing(raw)
    token = _get_fernet(keys_dir=keys_dir).encrypt(raw.encode("utf-8")).decode("ascii")
    return f"{ENCRYPTED_PREFIX}{token}"


def decrypt_secret(stored: str | None, keys_dir: Path | None = None) -> str:
    val = (stored or "").strip()
    if not val:
        return ""
    if not is_encrypted(val):
        # Legacy plaintext value prior to migration
        register_secret_for_scrubbing(val)
        return val
    token = val[len(ENCRYPTED_PREFIX) :].encode("ascii")
    try:
        plain = _get_fernet(keys_dir=keys_dir).decrypt(token).decode("utf-8")
        register_secret_for_scrubbing(plain)
        return plain
    except InvalidToken:
        return ""


def mask_secret(raw: str | None) -> str:
    val = (raw or "").strip()
    if not val:
        return ""
    if len(val) <= 8:
        return "••••"
    suffix = val[-4:]
    if val.startswith("sk-ant-"):
        return f"sk-ant-••••{suffix}"
    if val.startswith("sk-"):
        return f"sk-••••{suffix}"
    if val.startswith("AIza"):
        return f"AIza••••{suffix}"
    return f"{val[:3]}••••{suffix}"


def register_secret_for_scrubbing(secret: str | None) -> None:
    val = (secret or "").strip()
    if len(val) >= 8:
        with _SCRUB_LOCK:
            _REGISTERED_SECRETS.add(val)


def scrub_secrets(text_value: str) -> str:
    """Scrub any loaded BYOK API keys and common provider key patterns from logs, errors, and reports."""
    if not text_value:
        return text_value
    out = text_value
    # Also register env keys opportunistically
    for env_name in (
        "GEMINI_API_KEY",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "BASTION_GEMINI_API_KEY",
        "BASTION_ANTHROPIC_API_KEY",
        "BASTION_OPENAI_API_KEY",
    ):
        ev = os.environ.get(env_name, "").strip()
        if len(ev) >= 8:
            register_secret_for_scrubbing(ev)

    with _SCRUB_LOCK:
        secrets_snapshot = sorted(_REGISTERED_SECRETS, key=len, reverse=True)
    for sec in secrets_snapshot:
        if sec in out:
            out = out.replace(sec, "[REDACTED_API_KEY]")
    for pat in _GENERIC_KEY_PATTERNS:
        out = pat.sub("[REDACTED_API_KEY]", out)
    return out


def migrate_plaintext_app_settings(db: Session, keys_dir: Path | None = None) -> int:
    """Automatically encrypt any legacy plaintext LLM keys stored in SQLite AppSetting."""
    from app.models import AppSetting

    migrated = 0
    for key_name in SECRET_SETTING_KEYS:
        row = db.get(AppSetting, key_name)
        if row and row.value and row.value.strip() and not is_encrypted(row.value):
            row.value = encrypt_secret(row.value.strip(), keys_dir=keys_dir)
            migrated += 1

    if migrated > 0:
        db.commit()
        db.expire_all()
        # Compact SQLite WAL & free pages outside a transaction so raw DB bytes contain zero leftover plaintext
        try:
            bind = db.get_bind()
            with bind.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
                conn.execute(text("PRAGMA secure_delete = ON"))
                conn.execute(text("PRAGMA wal_checkpoint(TRUNCATE)"))
                conn.execute(text("VACUUM"))
                conn.execute(text("PRAGMA wal_checkpoint(TRUNCATE)"))
        except Exception:
            pass
    return migrated
