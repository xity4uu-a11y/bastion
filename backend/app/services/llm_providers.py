from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any

import httpx
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import settings
from app.models import AppSetting
from app.schemas import (
    LLMSettingsResponse,
    LLMSettingsUpdate,
    LLMTestResponse,
    ProviderSecretStatus,
)
from app.services.vault import (
    decrypt_secret,
    encrypt_secret,
    mask_secret,
    register_secret_for_scrubbing,
    scrub_secrets,
)

DEFAULT_MODELS: dict[str, str] = {
    "gemini": "gemini-2.5-flash",
    "anthropic": "claude-3-5-sonnet-latest",
    "openai": "gpt-4o-mini",
    "ollama": "qwen2.5-coder:7b",
    "none": "",
}

# Approximate USD per 1M tokens (input, output) for pre-flight budget capping & telemetry
MODEL_PRICING_PER_1M: dict[str, tuple[float, float]] = {
    "gemini": (0.30, 2.50),
    "anthropic": (3.00, 15.00),
    "openai": (0.15, 0.60),
    "ollama": (0.0, 0.0),
    "none": (0.0, 0.0),
}


@dataclass
class TokenUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    estimated_cost_usd: float = 0.0

    def add(self, other: "TokenUsage") -> None:
        self.prompt_tokens += other.prompt_tokens
        self.completion_tokens += other.completion_tokens
        self.estimated_cost_usd = round(self.estimated_cost_usd + other.estimated_cost_usd, 6)


def estimate_tokens(text_value: str) -> int:
    return max(1, (len(text_value or "") + 3) // 4)


def estimate_cost_usd(provider: str, prompt_tokens: int, completion_tokens: int) -> float:
    in_rate, out_rate = MODEL_PRICING_PER_1M.get(provider, (1.0, 4.0))
    return round((prompt_tokens / 1_000_000.0) * in_rate + (completion_tokens / 1_000_000.0) * out_rate, 6)


def max_input_tokens_for_budget(provider: str, max_budget_usd: float, hard_cap: int = 120000) -> int:
    in_rate, _out_rate = MODEL_PRICING_PER_1M.get(provider, (1.0, 4.0))
    if in_rate <= 0:
        if max_budget_usd < 0.05:
            return max(60, int(max_budget_usd * 20000))
        return hard_cap
    effective_in_budget = max(0.0001, max_budget_usd * 0.65)
    est_tokens = int((effective_in_budget / in_rate) * 1_000_000.0)
    return max(60, min(hard_cap, est_tokens))


@dataclass
class EffectiveLLMConfig:
    provider: str  # none | gemini | anthropic | openai | ollama
    model: str
    gemini_api_key: str
    gemini_source: str  # env | vault | none
    anthropic_api_key: str
    anthropic_source: str  # env | vault | none
    openai_api_key: str
    openai_source: str  # env | vault | none
    ollama_url: str
    ollama_source: str  # env | vault | none
    default_secret_scanner: str
    default_audit_scope: str = "diff"
    default_max_budget_usd: float = 1.50

    @property
    def resolved_model(self) -> str:
        return self.model.strip() or DEFAULT_MODELS.get(self.provider, "")

    @property
    def active_key(self) -> str:
        if self.provider == "gemini":
            return self.gemini_api_key.strip()
        if self.provider == "anthropic":
            return self.anthropic_api_key.strip()
        if self.provider == "openai":
            return self.openai_api_key.strip()
        return ""

    @property
    def active_source(self) -> str:
        if self.provider == "gemini":
            return self.gemini_source
        if self.provider == "anthropic":
            return self.anthropic_source
        if self.provider == "openai":
            return self.openai_source
        if self.provider == "ollama":
            return self.ollama_source
        return "none"

    @property
    def is_configured(self) -> bool:
        if self.provider in ("gemini", "anthropic", "openai"):
            return bool(self.active_key)
        if self.provider == "ollama":
            return bool(self.ollama_url.strip())
        return False

    @property
    def active_mode(self) -> str:
        return "live_llm" if self.is_configured else "static_heuristic"

    @property
    def active_badge(self) -> str:
        if self.is_configured:
            return f"Multi-Agent LLM ({self.provider}/{self.resolved_model})"
        return "Static Heuristic Fallback (No LLM)"


def _read_db_settings(db: Session | None) -> dict[str, str]:
    if db is None:
        return {}
    rows = db.query(AppSetting).all()
    return {r.key: r.value for r in rows}


def _resolve_secret_with_precedence(
    env_names: tuple[str, ...],
    settings_default: str,
    db_raw_value: str | None,
) -> tuple[str, str]:
    """Strict precedence: explicit OS env vars ALWAYS override stored Fernet vault entries."""
    for env_name in env_names:
        val = os.environ.get(env_name, "").strip()
        if val:
            register_secret_for_scrubbing(val)
            return val, "env"
    if settings_default and settings_default.strip():
        val = settings_default.strip()
        register_secret_for_scrubbing(val)
        return val, "env"
    if db_raw_value and db_raw_value.strip():
        decrypted = decrypt_secret(db_raw_value)
        if decrypted:
            register_secret_for_scrubbing(decrypted)
            return decrypted, "vault"
    return "", "none"


def get_effective_llm_config(db: Session | None = None) -> EffectiveLLMConfig:
    db_vals = _read_db_settings(db)

    gemini_key, gemini_src = _resolve_secret_with_precedence(
        ("GEMINI_API_KEY", "BASTION_GEMINI_API_KEY"),
        settings.gemini_api_key,
        db_vals.get("gemini_api_key"),
    )
    anthropic_key, anthropic_src = _resolve_secret_with_precedence(
        ("ANTHROPIC_API_KEY", "BASTION_ANTHROPIC_API_KEY"),
        settings.anthropic_api_key,
        db_vals.get("anthropic_api_key"),
    )
    openai_key, openai_src = _resolve_secret_with_precedence(
        ("OPENAI_API_KEY", "BASTION_OPENAI_API_KEY"),
        settings.openai_api_key,
        db_vals.get("openai_api_key"),
    )

    ollama_env = (
        os.environ.get("OLLAMA_BASE_URL", "").strip()
        or os.environ.get("BASTION_OLLAMA_URL", "").strip()
    )
    if ollama_env:
        ollama_url = ollama_env.rstrip("/")
        ollama_src = "env"
    elif db_vals.get("ollama_url", "").strip():
        ollama_url = db_vals["ollama_url"].strip().rstrip("/")
        ollama_src = "vault"
    else:
        ollama_url = (settings.ollama_url or "http://localhost:11434").rstrip("/")
        ollama_src = "none"

    env_provider = os.environ.get("BASTION_LLM_PROVIDER", "").strip().lower()
    if env_provider in DEFAULT_MODELS:
        provider = env_provider
    elif db_vals.get("llm_provider", "").strip().lower() in DEFAULT_MODELS:
        provider = db_vals["llm_provider"].strip().lower()
    else:
        provider = (settings.llm_provider or "none").strip().lower()
        if provider not in DEFAULT_MODELS:
            provider = "none"

    # Auto-select provider if an env var API key is injected in CI/CD without explicit BASTION_LLM_PROVIDER
    if provider == "none":
        if gemini_src == "env":
            provider = "gemini"
        elif anthropic_src == "env":
            provider = "anthropic"
        elif openai_src == "env":
            provider = "openai"
        elif ollama_src == "env":
            provider = "ollama"

    model = (
        os.environ.get("BASTION_LLM_MODEL", "").strip()
        or db_vals.get("llm_model", "").strip()
        or settings.llm_model.strip()
    )
    scanner = (
        os.environ.get("BASTION_DEFAULT_SECRET_SCANNER", "").strip().lower()
        or db_vals.get("default_secret_scanner", "").strip().lower()
        or settings.default_secret_scanner.strip().lower()
        or "auto"
    )
    scope = (
        os.environ.get("BASTION_DEFAULT_AUDIT_SCOPE", "").strip().lower()
        or db_vals.get("default_audit_scope", "").strip().lower()
        or settings.default_audit_scope.strip().lower()
        or "diff"
    )
    raw_budget = (
        os.environ.get("BASTION_DEFAULT_MAX_BUDGET_USD", "").strip()
        or db_vals.get("default_max_budget_usd", "").strip()
    )
    try:
        max_budget = float(raw_budget) if raw_budget else float(settings.default_max_budget_usd)
    except ValueError:
        max_budget = float(settings.default_max_budget_usd)

    return EffectiveLLMConfig(
        provider=provider,
        model=model,
        gemini_api_key=gemini_key,
        gemini_source=gemini_src,
        anthropic_api_key=anthropic_key,
        anthropic_source=anthropic_src,
        openai_api_key=openai_key,
        openai_source=openai_src,
        ollama_url=ollama_url,
        ollama_source="vault" if (provider == "ollama" and ollama_src == "none") else ollama_src,
        default_secret_scanner=scanner if scanner in ("auto", "trufflehog", "gitleaks") else "auto",
        default_audit_scope=scope if scope in ("diff", "full") else "diff",
        default_max_budget_usd=max(0.05, min(100.0, max_budget)),
    )


def to_public_llm_settings(cfg: EffectiveLLMConfig) -> LLMSettingsResponse:
    providers = {
        "gemini": ProviderSecretStatus(
            configured=bool(cfg.gemini_api_key),
            source=cfg.gemini_source,
            masked_key=mask_secret(cfg.gemini_api_key),
        ),
        "anthropic": ProviderSecretStatus(
            configured=bool(cfg.anthropic_api_key),
            source=cfg.anthropic_source,
            masked_key=mask_secret(cfg.anthropic_api_key),
        ),
        "openai": ProviderSecretStatus(
            configured=bool(cfg.openai_api_key),
            source=cfg.openai_source,
            masked_key=mask_secret(cfg.openai_api_key),
        ),
        "ollama": ProviderSecretStatus(
            configured=bool(cfg.ollama_url),
            source=cfg.ollama_source,
            masked_key=cfg.ollama_url,
        ),
    }
    return LLMSettingsResponse(
        provider=cfg.provider,
        model=cfg.resolved_model,
        ollama_url=cfg.ollama_url,
        default_secret_scanner=cfg.default_secret_scanner,
        default_audit_scope=cfg.default_audit_scope,
        default_max_budget_usd=cfg.default_max_budget_usd,
        configured=cfg.is_configured,
        source=cfg.active_source,
        masked_key=mask_secret(cfg.active_key),
        providers=providers,
        vault_encrypted=True,
        gemini_key_set=bool(cfg.gemini_api_key),
        anthropic_key_set=bool(cfg.anthropic_api_key),
        openai_key_set=bool(cfg.openai_api_key),
        active_mode=cfg.active_mode,
        active_badge=cfg.active_badge,
    )


def save_llm_settings(db: Session, payload: LLMSettingsUpdate) -> EffectiveLLMConfig:
    def _upsert(key: str, value: str) -> None:
        row = db.get(AppSetting, key)
        if row:
            row.value = value
        else:
            db.add(AppSetting(key=key, value=value))

    _upsert("llm_provider", payload.provider.strip().lower())
    _upsert("llm_model", payload.model.strip())
    _upsert("ollama_url", (payload.ollama_url.strip() or "http://localhost:11434").rstrip("/"))
    _upsert("default_secret_scanner", payload.default_secret_scanner.strip().lower())
    _upsert("default_audit_scope", payload.default_audit_scope.strip().lower())
    _upsert("default_max_budget_usd", f"{payload.default_max_budget_usd:.2f}")

    if payload.clear_keys:
        _upsert("gemini_api_key", "")
        _upsert("anthropic_api_key", "")
        _upsert("openai_api_key", "")
    else:
        if payload.gemini_api_key is not None and payload.gemini_api_key.strip():
            _upsert("gemini_api_key", encrypt_secret(payload.gemini_api_key.strip()))
        if payload.anthropic_api_key is not None and payload.anthropic_api_key.strip():
            _upsert("anthropic_api_key", encrypt_secret(payload.anthropic_api_key.strip()))
        if payload.openai_api_key is not None and payload.openai_api_key.strip():
            _upsert("openai_api_key", encrypt_secret(payload.openai_api_key.strip()))

    db.commit()
    try:
        db.execute(text("PRAGMA wal_checkpoint(TRUNCATE)"))
    except Exception:
        pass
    return get_effective_llm_config(db)


def _strip_json_comments_and_trailing_commas(raw: str) -> str:
    # Remove single-line // comments outside quoted strings safely (line-leading or whitespace-prefixed)
    cleaned = re.sub(r"(?m)^\s*//[^\n]*$", "", raw)
    # Remove trailing commas before closing } or ]
    cleaned = re.sub(r",\s*([}\]])", r"\1", cleaned)
    return cleaned.strip()


def extract_json_payload(raw_text: str) -> Any:
    """Defensively parse JSON from prose-wrapped, fenced, or trailing-comma LLM output."""
    text_val = (raw_text or "").strip()
    if not text_val:
        raise ValueError("Empty response from LLM provider")

    candidates: list[str] = [text_val]
    for fence in re.finditer(r"```(?:json|javascript|js)?\s*([\s\S]*?)```", text_val, re.IGNORECASE):
        candidates.insert(0, fence.group(1).strip())

    # Also extract outermost balanced {...} or [...] slice
    for open_ch, close_ch in (("{", "}"), ("[", "]")):
        start = text_val.find(open_ch)
        end = text_val.rfind(close_ch)
        if start != -1 and end > start:
            candidates.append(text_val[start : end + 1])

    for cand in candidates:
        for variant in (cand, _strip_json_comments_and_trailing_commas(cand)):
            try:
                return json.loads(variant)
            except json.JSONDecodeError:
                continue

    raise ValueError(f"LLM output was not valid JSON: {scrub_secrets(text_val[:180])}")


class IsolatedLLMSession:
    """Stateless single-session BYOK LLM caller with usage accounting and 1-shot schema-repair retry."""

    def __init__(self, config: EffectiveLLMConfig, timeout: float | None = None) -> None:
        self.config = config
        self.timeout = timeout or settings.llm_timeout_seconds

    def complete_json(self, system_prompt: str, user_prompt: str, max_tokens: int = 3000) -> Any:
        parsed, _ = self.complete_json_with_usage(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=max_tokens,
        )
        return parsed

    def complete_json_with_usage(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 3000,
        schema_hint: str = "a single valid JSON object",
    ) -> tuple[Any, TokenUsage]:
        total_usage = TokenUsage()
        raw, usage1 = self.complete_text_with_usage(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=max_tokens,
        )
        total_usage.add(usage1)

        try:
            return extract_json_payload(raw), total_usage
        except ValueError as first_err:
            # Strict single schema-repair retry
            repair_system = (
                "You are a strict JSON repair formatter. Return ONLY valid RFC-8259 JSON matching "
                f"{schema_hint}. Do not include markdown fences, comments, trailing commas, or prose."
            )
            repair_user = (
                f"Previous output failed JSON parsing ({first_err}). Repair it into strictly valid JSON:\n\n"
                f"{raw[:12000]}"
            )
            repaired_raw, usage2 = self.complete_text_with_usage(
                system_prompt=repair_system,
                user_prompt=repair_user,
                max_tokens=max_tokens,
            )
            total_usage.add(usage2)
            return extract_json_payload(repaired_raw), total_usage

    def complete_text(self, system_prompt: str, user_prompt: str, max_tokens: int = 3000) -> str:
        raw, _ = self.complete_text_with_usage(system_prompt=system_prompt, user_prompt=user_prompt, max_tokens=max_tokens)
        return raw

    def complete_text_with_usage(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 3000,
    ) -> tuple[str, TokenUsage]:
        provider = self.config.provider
        model = self.config.resolved_model
        if not self.config.is_configured:
            raise RuntimeError("No BYOK LLM provider is configured")

        try:
            if provider == "gemini":
                return self._call_gemini(model, system_prompt, user_prompt, max_tokens)
            if provider == "anthropic":
                return self._call_anthropic(model, system_prompt, user_prompt, max_tokens)
            if provider == "openai":
                return self._call_openai(model, system_prompt, user_prompt, max_tokens)
            if provider == "ollama":
                return self._call_ollama(model, system_prompt, user_prompt)
            raise RuntimeError(f"Unsupported LLM provider: {provider}")
        except Exception as exc:
            raise RuntimeError(scrub_secrets(str(exc))) from None

    def _call_gemini(self, model: str, system_prompt: str, user_prompt: str, max_tokens: int) -> tuple[str, TokenUsage]:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        body = {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {
                "temperature": 0.1,
                "maxOutputTokens": max_tokens,
                "responseMimeType": "application/json",
            },
        }
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(url, params={"key": self.config.gemini_api_key.strip()}, json=body)
            resp.raise_for_status()
            data = resp.json()
        candidates = data.get("candidates") or []
        if not candidates:
            raise RuntimeError("Gemini returned no candidates")
        parts = (candidates[0].get("content") or {}).get("parts") or []
        text_out = "".join(str(p.get("text") or "") for p in parts)
        meta = data.get("usageMetadata") or {}
        p_tok = int(meta.get("promptTokenCount") or estimate_tokens(system_prompt + user_prompt))
        c_tok = int(meta.get("candidatesTokenCount") or estimate_tokens(text_out))
        return text_out, TokenUsage(p_tok, c_tok, estimate_cost_usd("gemini", p_tok, c_tok))

    def _call_anthropic(self, model: str, system_prompt: str, user_prompt: str, max_tokens: int) -> tuple[str, TokenUsage]:
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.config.anthropic_api_key.strip(),
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        body = {
            "model": model,
            "max_tokens": max_tokens,
            "temperature": 0.1,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(url, headers=headers, json=body)
            resp.raise_for_status()
            data = resp.json()
        blocks = data.get("content") or []
        text_out = "".join(str(b.get("text") or "") for b in blocks if b.get("type") == "text")
        usage = data.get("usage") or {}
        p_tok = int(usage.get("input_tokens") or estimate_tokens(system_prompt + user_prompt))
        c_tok = int(usage.get("output_tokens") or estimate_tokens(text_out))
        return text_out, TokenUsage(p_tok, c_tok, estimate_cost_usd("anthropic", p_tok, c_tok))

    def _call_openai(self, model: str, system_prompt: str, user_prompt: str, max_tokens: int) -> tuple[str, TokenUsage]:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.config.openai_api_key.strip()}",
            "Content-Type": "application/json",
        }
        body = {
            "model": model,
            "temperature": 0.1,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(url, headers=headers, json=body)
            resp.raise_for_status()
            data = resp.json()
        choices = data.get("choices") or []
        if not choices:
            raise RuntimeError("OpenAI returned no choices")
        text_out = str((choices[0].get("message") or {}).get("content") or "")
        usage = data.get("usage") or {}
        p_tok = int(usage.get("prompt_tokens") or estimate_tokens(system_prompt + user_prompt))
        c_tok = int(usage.get("completion_tokens") or estimate_tokens(text_out))
        return text_out, TokenUsage(p_tok, c_tok, estimate_cost_usd("openai", p_tok, c_tok))

    def _call_ollama(self, model: str, system_prompt: str, user_prompt: str) -> tuple[str, TokenUsage]:
        url = f"{self.config.ollama_url}/api/chat"
        body = {
            "model": model,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.1},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(url, json=body)
            resp.raise_for_status()
            data = resp.json()
        text_out = str((data.get("message") or {}).get("content") or "")
        p_tok = int(data.get("prompt_eval_count") or estimate_tokens(system_prompt + user_prompt))
        c_tok = int(data.get("eval_count") or estimate_tokens(text_out))
        return text_out, TokenUsage(p_tok, c_tok, 0.0)


def test_llm_connection(cfg: EffectiveLLMConfig) -> LLMTestResponse:
    start = time.perf_counter()
    if not cfg.is_configured:
        return LLMTestResponse(
            ok=False,
            provider=cfg.provider,
            model=cfg.resolved_model,
            latency_ms=0,
            message="Provider is not configured. Add an API key or select Ollama.",
        )

    try:
        if cfg.provider == "ollama":
            with httpx.Client(timeout=8.0) as client:
                r = client.get(f"{cfg.ollama_url}/api/tags")
                r.raise_for_status()
                models = [m.get("name", "") for m in (r.json().get("models") or [])]
            elapsed = int((time.perf_counter() - start) * 1000)
            note = f"Ollama reachable ({len(models)} local model(s))."
            if cfg.resolved_model and models and not any(cfg.resolved_model in m for m in models):
                note += f" Note: model '{cfg.resolved_model}' not yet pulled."
            return LLMTestResponse(ok=True, provider="ollama", model=cfg.resolved_model, latency_ms=elapsed, message=note)

        session = IsolatedLLMSession(cfg, timeout=15.0)
        res, _ = session.complete_json_with_usage(
            system_prompt='Respond strictly with JSON: {"ok": true}',
            user_prompt="Health check.",
            max_tokens=64,
        )
        elapsed = int((time.perf_counter() - start) * 1000)
        return LLMTestResponse(
            ok=bool(isinstance(res, dict)),
            provider=cfg.provider,
            model=cfg.resolved_model,
            latency_ms=elapsed,
            message=f"Connected to {cfg.provider} ({cfg.resolved_model}) in {elapsed} ms (source={cfg.active_source}).",
        )
    except Exception as exc:
        elapsed = int((time.perf_counter() - start) * 1000)
        return LLMTestResponse(
            ok=False,
            provider=cfg.provider,
            model=cfg.resolved_model,
            latency_ms=elapsed,
            message=f"Connection failed: {scrub_secrets(str(exc))[:220]}",
        )
