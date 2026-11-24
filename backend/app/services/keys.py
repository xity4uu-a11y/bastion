from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from app.config import settings


@dataclass
class Ed25519KeyPairInfo:
    private_key_path: Path
    public_key_path: Path
    public_key_pem: str
    key_fingerprint: str


def compute_public_key_fingerprint(public_key: Ed25519PublicKey) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return f"ed25519:{hashlib.sha256(der).hexdigest()[:32]}"


def ensure_ed25519_keypair(keys_dir: Path | None = None) -> Ed25519KeyPairInfo:
    """Auto-generate and securely persist an Ed25519 signing keypair outside any target repo."""
    target_dir = (keys_dir or settings.resolved_keys_dir).expanduser().resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    priv_path = target_dir / "ed25519_private.pem"
    pub_path = target_dir / "ed25519_public.pem"

    if priv_path.exists() and pub_path.exists():
        pub_pem = pub_path.read_text(encoding="utf-8")
        pub_key = serialization.load_pem_public_key(pub_pem.encode("utf-8"))
        if not isinstance(pub_key, Ed25519PublicKey):
            raise ValueError(f"Expected Ed25519 public key at {pub_path}")
        return Ed25519KeyPairInfo(
            private_key_path=priv_path,
            public_key_path=pub_path,
            public_key_pem=pub_pem,
            key_fingerprint=compute_public_key_fingerprint(pub_key),
        )

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem_bytes)
    if os.name != "nt":
        try:
            os.chmod(priv_path, 0o600)
            os.chmod(pub_path, 0o644)
        except OSError:
            pass

    return Ed25519KeyPairInfo(
        private_key_path=priv_path,
        public_key_path=pub_path,
        public_key_pem=pub_pem_bytes.decode("utf-8"),
        key_fingerprint=compute_public_key_fingerprint(public_key),
    )


def sign_ed25519(payload_bytes: bytes, keys_dir: Path | None = None) -> tuple[str, Ed25519KeyPairInfo]:
    info = ensure_ed25519_keypair(keys_dir)
    priv_key = serialization.load_pem_private_key(
        info.private_key_path.read_bytes(),
        password=None,
    )
    if not isinstance(priv_key, Ed25519PrivateKey):
        raise ValueError(f"Invalid Ed25519 private key at {info.private_key_path}")
    raw_sig = priv_key.sign(payload_bytes)
    sig_b64 = base64.b64encode(raw_sig).decode("ascii")
    return sig_b64, info


def verify_ed25519(
    payload_bytes: bytes,
    signature_b64: str,
    public_key_pem: str,
) -> tuple[bool, str, str]:
    try:
        pub_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(pub_key, Ed25519PublicKey):
            return False, "", "Provided key is not an Ed25519 public key."
        fp = compute_public_key_fingerprint(pub_key)
    except Exception as exc:
        return False, "", f"Failed to parse Ed25519 public key PEM: {exc}"

    try:
        sig_bytes = base64.b64decode(signature_b64.encode("ascii"), validate=True)
    except Exception:
        return False, fp, "Signature is not valid base64."

    try:
        pub_key.verify(sig_bytes, payload_bytes)
        return True, fp, "Ed25519 signature verified."
    except InvalidSignature:
        return False, fp, "Ed25519 cryptographic signature mismatch."
    except Exception as exc:
        return False, fp, f"Signature verification error: {exc}"
