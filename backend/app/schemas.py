from __future__ import annotations

import datetime as dt
from typing import Any
from pydantic import BaseModel, Field


class ToolStatus(BaseModel):
    name: str
    installed: bool
    version: str | None = None
    path: str | None = None
    mode: str
    details: str = ""


class SystemToolsResponse(BaseModel):
    trufflehog: ToolStatus
    gitleaks: ToolStatus
    cloudflare_skill: ToolStatus
    bla: ToolStatus
    node: ToolStatus
    git: ToolStatus
    all_live: bool
    ed25519_key_fingerprint: str = ""
    ed25519_public_key_path: str = ""
    setup_ps1_path: str
    setup_sh_path: str


class ProviderSecretStatus(BaseModel):
    configured: bool
    source: str  # env | vault | none
    masked_key: str = ""


class LLMSettingsResponse(BaseModel):
    provider: str  # none | gemini | anthropic | openai | ollama
    model: str
    ollama_url: str
    default_secret_scanner: str  # auto | trufflehog | gitleaks
    default_audit_scope: str = "diff"  # diff | full
    default_max_budget_usd: float = 1.50
    configured: bool = False
    source: str = "none"  # env | vault | none
    masked_key: str = ""
    providers: dict[str, ProviderSecretStatus] = Field(default_factory=dict)
    vault_encrypted: bool = True
    gemini_key_set: bool = False
    anthropic_key_set: bool = False
    openai_key_set: bool = False
    active_mode: str = "static_heuristic"
    active_badge: str = "Static Heuristic Fallback (No LLM)"


class LLMSettingsUpdate(BaseModel):
    provider: str = Field(pattern="^(none|gemini|anthropic|openai|ollama)$")
    model: str = ""
    ollama_url: str = "http://localhost:11434"
    default_secret_scanner: str = Field(default="auto", pattern="^(auto|trufflehog|gitleaks)$")
    default_audit_scope: str = Field(default="diff", pattern="^(diff|full)$")
    default_max_budget_usd: float = Field(default=1.50, ge=0.05, le=100.0)
    gemini_api_key: str | None = None
    anthropic_api_key: str | None = None
    openai_api_key: str | None = None
    clear_keys: bool = False


class LLMTestResponse(BaseModel):
    ok: bool
    provider: str
    model: str
    latency_ms: int
    message: str


class PublicKeyResponse(BaseModel):
    algorithm: str
    key_fingerprint: str
    public_key_path: str
    public_key_pem: str


class CertificateVerifyRequest(BaseModel):
    certificate: dict[str, Any]
    public_key_pem: str | None = None


class CertificateVerifyResponse(BaseModel):
    valid: bool
    status: str
    tampered: bool
    expired: bool
    signature_valid: bool
    signer_matched: bool
    algorithm: str
    key_fingerprint: str | None = None
    expected_key_fingerprint: str | None = None
    certificate_id: str | None = None
    release_decision: str | None = None
    issued_at: str | None = None
    expires_at: str | None = None
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    path: str = Field(min_length=1, max_length=1024)
    description: str = ""
    default_secret_scanner: str = Field(default="auto", pattern="^(auto|trufflehog|gitleaks)$")
    default_bla_intensity: str = Field(default="balanced", pattern="^(stealth|balanced|maximum|bankrupt)$")
    default_audit_profile: str = Field(default="standard", pattern="^(quick|standard|deep)$")
    smoke_test_cmd: str = ""


class ProjectUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    default_secret_scanner: str | None = Field(default=None, pattern="^(auto|trufflehog|gitleaks)$")
    default_bla_intensity: str | None = Field(default=None, pattern="^(stealth|balanced|maximum|bankrupt)$")
    default_audit_profile: str | None = Field(default=None, pattern="^(quick|standard|deep)$")
    smoke_test_cmd: str | None = None


class ProjectResponse(BaseModel):
    id: str
    name: str
    path: str
    description: str
    default_secret_scanner: str
    default_bla_intensity: str
    default_audit_profile: str
    smoke_test_cmd: str = ""
    bla_applied: bool
    bla_backup_dir: str | None
    is_git_repo: bool = False
    path_exists: bool = False
    latest_run_id: str | None = None
    latest_run_status: str | None = None
    latest_readiness_score: int | None = None
    latest_smoke_status: str | None = None
    created_at: dt.datetime
    updated_at: dt.datetime


class RunCreate(BaseModel):
    project_id: str
    secret_scanner: str | None = Field(default=None, pattern="^(auto|trufflehog|gitleaks)$")
    bla_intensity: str | None = Field(default=None, pattern="^(stealth|balanced|maximum|bankrupt)$")
    audit_profile: str | None = Field(default=None, pattern="^(quick|standard|deep)$")
    audit_scope: str | None = Field(default=None, pattern="^(diff|full)$")
    base_ref: str | None = None
    max_budget_usd: float | None = Field(default=None, ge=0.05, le=100.0)
    smoke_test_cmd: str | None = None
    stop_on_gate1_fail: bool = True
    force_simulation: bool = False


class GateExecutionResponse(BaseModel):
    id: str
    gate_number: int
    name: str
    engine: str
    status: str
    mode: str
    findings_count: int
    blocking_count: int
    duration_ms: int
    summary: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    started_at: dt.datetime | None
    completed_at: dt.datetime | None


class AuditEventResponse(BaseModel):
    id: int
    run_id: str
    gate_number: int
    level: str
    message: str
    timestamp: dt.datetime


class ReleaseRunResponse(BaseModel):
    id: str
    project_id: str
    project_name: str = ""
    run_number: int
    status: str
    current_gate: int
    readiness_score: int
    git_commit: str | None
    git_branch: str | None
    git_dirty: bool
    secret_scanner: str = "auto"
    bla_intensity: str
    audit_profile: str
    audit_scope: str = "full"
    base_ref: str = ""
    max_budget_usd: float = 1.50
    smoke_test_cmd: str = ""
    simulation_used: bool
    output_dir: str | None
    summary: dict[str, Any] = Field(default_factory=dict)
    gates: list[GateExecutionResponse] = Field(default_factory=list)
    started_at: dt.datetime | None
    completed_at: dt.datetime | None
    created_at: dt.datetime


class FindingResponse(BaseModel):
    id: str
    run_id: str
    project_id: str
    gate_number: int
    source_engine: str
    fingerprint: str
    title: str
    description: str
    detector_or_class: str
    file_path: str
    line_number: int
    verified: bool | None
    redacted_secret: str | None
    git_commit: str | None
    verdict: str
    severity: str
    confidence: str
    hunter_agent_id: str | None
    verifier_agent_id: str | None
    root_cause: str
    remediation: str
    fixed_code: str
    trace: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    resolved: bool
    resolution_note: str
    resolved_at: dt.datetime | None
    created_at: dt.datetime


class FindingUpdate(BaseModel):
    resolved: bool | None = None
    resolution_note: str | None = None


class CodeContextLine(BaseModel):
    line_number: int
    content: str
    highlight: bool = False


class FindingCodeContextResponse(BaseModel):
    finding_id: str
    file_path: str
    line_number: int
    language: str
    exists: bool
    lines: list[CodeContextLine]
    fixed_code: str = ""
    remediation: str = ""


class CoverageLedgerResponse(BaseModel):
    id: str
    project_id: str
    last_run_id: str | None
    coverage_id: str
    surface: str
    boundary: str
    subsystem: str
    attack_class: str
    status: str
    prior_status: str
    wave: int
    hunter_agent_id: str | None
    verifier_agent_id: str | None
    source_hash: str
    updated_at: dt.datetime


class ArtifactResponse(BaseModel):
    id: str
    run_id: str
    project_id: str
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
    created_at: dt.datetime


class BlaActionRequest(BaseModel):
    intensity: str = Field(default="balanced", pattern="^(stealth|balanced|maximum|bankrupt)$")
    force_simulation: bool = False


class BlaActionResponse(BaseModel):
    status: str
    mode: str
    project_id: str
    bla_applied: bool
    affected_files: list[str]
    backup_directory: str | None = None
    message: str
    artifacts: list[dict[str, Any]] = Field(default_factory=list)


class SmokeTestRequest(BaseModel):
    smoke_test_cmd: str | None = None
    timeout_seconds: int = Field(default=30, ge=3, le=180)


class SmokeTestResultResponse(BaseModel):
    status: str  # passed | failed | timeout | skipped
    command: str
    exit_code: int | None = None
    duration_ms: int = 0
    stdout: str = ""
    stderr: str = ""
    tested_mirror: bool = False
    message: str = ""


class CicdWorkflowResponse(BaseModel):
    project_id: str
    project_name: str
    mode: str  # container | self-built
    image: str
    filename: str
    yaml_content: str
