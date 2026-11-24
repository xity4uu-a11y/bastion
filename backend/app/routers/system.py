from __future__ import annotations

from pathlib import Path
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.config import PROJECT_ROOT, settings
from app.database import get_db
from app.schemas import (
    CertificateVerifyRequest,
    CertificateVerifyResponse,
    LLMSettingsResponse,
    LLMSettingsUpdate,
    LLMTestResponse,
    PublicKeyResponse,
    SystemToolsResponse,
)
from app.services.certificate import verify_certificate_document
from app.services.keys import ensure_ed25519_keypair
from app.services.llm_providers import (
    get_effective_llm_config,
    save_llm_settings,
    test_llm_connection,
    to_public_llm_settings,
)
from app.services.toolchain import get_git_metadata, inspect_toolchain

router = APIRouter(prefix="/api", tags=["system"])


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": settings.app_name, "version": settings.version}


@router.get("/system/tools", response_model=SystemToolsResponse)
def get_system_tools() -> SystemToolsResponse:
    return inspect_toolchain()


@router.get("/system/public-key", response_model=PublicKeyResponse)
def get_signing_public_key() -> PublicKeyResponse:
    info = ensure_ed25519_keypair()
    return PublicKeyResponse(
        algorithm="Ed25519",
        key_fingerprint=info.key_fingerprint,
        public_key_path=str(info.public_key_path),
        public_key_pem=info.public_key_pem,
    )


@router.post("/certificates/verify", response_model=CertificateVerifyResponse)
def verify_certificate_api(payload: CertificateVerifyRequest) -> CertificateVerifyResponse:
    result = verify_certificate_document(
        doc=payload.certificate,
        public_key_pem=payload.public_key_pem,
    )
    return CertificateVerifyResponse(**result)


@router.get("/settings/llm", response_model=LLMSettingsResponse)
def get_llm_settings(db: Session = Depends(get_db)) -> LLMSettingsResponse:
    cfg = get_effective_llm_config(db)
    return to_public_llm_settings(cfg)


@router.put("/settings/llm", response_model=LLMSettingsResponse)
def update_llm_settings(
    payload: LLMSettingsUpdate,
    db: Session = Depends(get_db),
) -> LLMSettingsResponse:
    cfg = save_llm_settings(db, payload)
    return to_public_llm_settings(cfg)


@router.post("/settings/llm/test", response_model=LLMTestResponse)
def test_llm_settings(db: Session = Depends(get_db)) -> LLMTestResponse:
    cfg = get_effective_llm_config(db)
    return test_llm_connection(cfg)


@router.get("/system/inspect-path")
def inspect_local_path(path: str) -> dict[str, object]:
    p = Path(path).expanduser()
    exists = p.exists() and p.is_dir()
    is_git, commit, branch, dirty = get_git_metadata(p) if exists else (False, None, None, False)
    return {
        "path": str(p),
        "exists": exists,
        "is_git_repo": is_git,
        "git_commit": commit,
        "git_branch": branch,
        "git_dirty": dirty,
        "suggested_name": p.name if p.name else "project",
        "sample_target_path": str(PROJECT_ROOT / "sample-target"),
    }
