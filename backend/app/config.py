from __future__ import annotations

import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BACKEND_ROOT.parent
DEFAULT_DATA_DIR = PROJECT_ROOT / "data"
DEFAULT_KEYS_DIR = Path.home() / ".bastion" / "keys"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="BASTION_", env_file=str(PROJECT_ROOT / ".env"), extra="ignore")

    app_name: str = "Bastion"
    version: str = "2.1.0"
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    data_dir: Path = DEFAULT_DATA_DIR
    keys_dir: Path = DEFAULT_KEYS_DIR
    database_url: str | None = None
    certificate_ttl_days: int = 30
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000,http://localhost:3001,http://127.0.0.1:3001"
    cloudflare_skill_dir: Path | None = None
    force_simulation: bool = False

    # Gate 1 pluggable scanner default: auto | trufflehog | gitleaks
    default_secret_scanner: str = "auto"

    # Gate 2 BYOK LLM Provider configuration (.env defaults; env vars override vault)
    llm_provider: str = "none"  # none | gemini | anthropic | openai | ollama
    llm_model: str = ""
    gemini_api_key: str = ""
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    ollama_url: str = "http://localhost:11434"
    llm_timeout_seconds: float = 90.0

    # Gate 2 Scoping & Token/Cost Budgeting defaults
    default_audit_scope: str = "diff"  # diff | full
    default_max_budget_usd: float = 1.50
    default_max_input_tokens: int = 120000

    # Gate 3 Post-BLA smoke verification timeout
    smoke_test_timeout_seconds: int = 30

    @property
    def resolved_data_dir(self) -> Path:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return self.data_dir

    @property
    def resolved_keys_dir(self) -> Path:
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        return self.keys_dir

    @property
    def resolved_db_url(self) -> str:
        if self.database_url:
            return self.database_url
        db_path = self.resolved_data_dir / "bastion.db"
        return f"sqlite:///{db_path.as_posix()}"

    @property
    def runs_output_dir(self) -> Path:
        out = self.resolved_data_dir / "runs"
        out.mkdir(parents=True, exist_ok=True)
        return out

    @property
    def resolved_cloudflare_skill_dir(self) -> Path | None:
        candidates: list[Path] = []
        if self.cloudflare_skill_dir:
            candidates.append(self.cloudflare_skill_dir)
        env_dir = os.environ.get("BASTION_CLOUDFLARE_SKILL_DIR")
        if env_dir:
            candidates.append(Path(env_dir))
        candidates.extend([
            PROJECT_ROOT / "vendor" / "security-audit-skill" / "skills" / "security-audit",
            Path.home() / "AppData" / "Local" / "Programs" / "antigravity" / ".agents" / "skills" / "security-audit",
            Path.home() / ".agents" / "skills" / "security-audit",
            Path.home() / ".claude" / "skills" / "security-audit",
        ])
        for candidate in candidates:
            if candidate.exists() and (candidate / "report-schema.json").exists():
                return candidate
        return None

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
