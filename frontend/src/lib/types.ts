export type NavTab = "overview" | "runner" | "findings" | "shield" | "reports";

export type SecretScannerPref = "auto" | "trufflehog" | "gitleaks";
export type LLMProviderId = "none" | "gemini" | "anthropic" | "openai" | "ollama";
export type AuditScope = "diff" | "full";
export type SecretSource = "env" | "vault" | "none";
export type SmokeTestStatus = "passed" | "failed" | "timeout" | "skipped";
export type CicdMode = "container" | "self-built";

export interface ToolStatus {
  name: string;
  installed: boolean;
  version: string | null;
  path: string | null;
  mode: "live" | "simulation_fallback";
  details: string;
}

export interface SystemToolsResponse {
  trufflehog: ToolStatus;
  gitleaks: ToolStatus;
  cloudflare_skill: ToolStatus;
  bla: ToolStatus;
  node: ToolStatus;
  git: ToolStatus;
  all_live: boolean;
  ed25519_key_fingerprint: string;
  ed25519_public_key_path: string;
  setup_ps1_path: string;
  setup_sh_path: string;
}

export interface ProviderSecretStatus {
  configured: boolean;
  source: SecretSource;
  masked_key: string;
}

export interface LLMSettings {
  provider: LLMProviderId;
  model: string;
  ollama_url: string;
  default_secret_scanner: SecretScannerPref;
  default_audit_scope: AuditScope;
  default_max_budget_usd: number;
  configured: boolean;
  source: SecretSource;
  masked_key: string;
  providers: Record<string, ProviderSecretStatus>;
  vault_encrypted: boolean;
  gemini_key_set: boolean;
  anthropic_key_set: boolean;
  openai_key_set: boolean;
  active_mode: "live_llm" | "static_heuristic";
  active_badge: string;
}

export interface LLMSettingsUpdate {
  provider: LLMProviderId;
  model: string;
  ollama_url: string;
  default_secret_scanner: SecretScannerPref;
  default_audit_scope?: AuditScope;
  default_max_budget_usd?: number;
  gemini_api_key?: string;
  anthropic_api_key?: string;
  openai_api_key?: string;
  clear_keys?: boolean;
}

export interface LLMTestResponse {
  ok: boolean;
  provider: string;
  model: string;
  latency_ms: number;
  message: string;
}

export interface PublicKeyResponse {
  algorithm: string;
  key_fingerprint: string;
  public_key_path: string;
  public_key_pem: string;
}

export interface CertificateVerifyResponse {
  valid: boolean;
  status: "valid" | "tampered" | "expired" | "invalid_signature" | "invalid_format";
  tampered: boolean;
  expired: boolean;
  signature_valid: boolean;
  signer_matched: boolean;
  algorithm: string;
  key_fingerprint: string | null;
  expected_key_fingerprint: string | null;
  certificate_id: string | null;
  release_decision: string | null;
  issued_at: string | null;
  expires_at: string | null;
  errors: string[];
  warnings: string[];
}

export interface CicdWorkflowResponse {
  project_id: string;
  project_name: string;
  mode: CicdMode;
  image: string;
  filename: string;
  yaml_content: string;
}

export interface SmokeTestResult {
  status: SmokeTestStatus;
  command: string;
  exit_code: number | null;
  duration_ms: number;
  stdout: string;
  stderr: string;
  tested_mirror: boolean;
  message: string;
}

export interface Project {
  id: string;
  name: string;
  path: string;
  description: string;
  default_secret_scanner: SecretScannerPref;
  default_bla_intensity: "stealth" | "balanced" | "maximum" | "bankrupt";
  default_audit_profile: "quick" | "standard" | "deep";
  smoke_test_cmd: string;
  bla_applied: boolean;
  bla_backup_dir: string | null;
  is_git_repo: boolean;
  path_exists: boolean;
  latest_run_id: string | null;
  latest_run_status: string | null;
  latest_readiness_score: number | null;
  latest_smoke_status: SmokeTestStatus | null;
  created_at: string;
  updated_at: string;
}

export interface GateExecution {
  id: string;
  gate_number: number;
  name: string;
  engine: string;
  status: "pending" | "running" | "passed" | "warn" | "failed" | "skipped" | "aborted";
  mode: "live" | "live_llm" | "static_heuristic" | "simulation";
  findings_count: number;
  blocking_count: number;
  duration_ms: number;
  summary: string;
  metadata: Record<string, unknown>;
  started_at: string | null;
  completed_at: string | null;
}

export interface ReleaseRun {
  id: string;
  project_id: string;
  project_name: string;
  run_number: number;
  status: "queued" | "running" | "passed" | "failed" | "aborted";
  current_gate: number;
  readiness_score: number;
  git_commit: string | null;
  git_branch: string | null;
  git_dirty: boolean;
  secret_scanner: SecretScannerPref;
  bla_intensity: string;
  audit_profile: string;
  audit_scope: AuditScope;
  base_ref: string;
  max_budget_usd: number;
  smoke_test_cmd: string;
  simulation_used: boolean;
  output_dir: string | null;
  summary: Record<string, unknown>;
  gates: GateExecution[];
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface AuditEvent {
  id: number;
  run_id: string;
  gate_number: number;
  level: "info" | "warn" | "error" | "success";
  message: string;
  timestamp: string;
}

export interface Finding {
  id: string;
  run_id: string;
  project_id: string;
  gate_number: number;
  source_engine: string;
  fingerprint: string;
  title: string;
  description: string;
  detector_or_class: string;
  file_path: string;
  line_number: number;
  verified: boolean | null;
  redacted_secret: string | null;
  git_commit: string | null;
  verdict: "confirmed" | "needs_validation" | "hardening_note" | "rejected";
  severity: "critical" | "high" | "medium" | "low" | "informational" | "unrated";
  confidence: string;
  hunter_agent_id: string | null;
  verifier_agent_id: string | null;
  root_cause: string;
  remediation: string;
  fixed_code: string;
  trace: Array<{ kind: string; file: string; line: number; scope: string; description: string }>;
  evidence: Array<{ file: string; line: number; description: string }>;
  blockers: string[];
  resolved: boolean;
  resolution_note: string;
  resolved_at: string | null;
  created_at: string;
}

export interface FindingCodeContext {
  finding_id: string;
  file_path: string;
  line_number: number;
  language: string;
  exists: boolean;
  lines: Array<{ line_number: number; content: string; highlight: boolean }>;
  fixed_code: string;
  remediation: string;
}

export interface CoverageLedgerEntry {
  id: string;
  project_id: string;
  last_run_id: string | null;
  coverage_id: string;
  surface: string;
  boundary: string;
  subsystem: string;
  attack_class: string;
  status: string;
  prior_status: string;
  wave: number;
  hunter_agent_id: string | null;
  verifier_agent_id: string | null;
  source_hash: string;
  updated_at: string;
}

export interface ArtifactRecord {
  id: string;
  run_id: string;
  project_id: string;
  relative_path: string;
  artifact_format: string;
  category: string;
  input_bytes: number;
  output_bytes: number;
  mirror_path: string | null;
  intensity: string;
  status: "discovered" | "hardened" | "applied" | "restored" | "failed";
  defense_score: number;
  token_amplification: number;
  cost_amplification: number;
  before_exposure_score: number;
  verified: boolean;
  created_at: string;
}

export interface BlaActionResponse {
  status: string;
  mode: string;
  project_id: string;
  bla_applied: boolean;
  affected_files: string[];
  backup_directory: string | null;
  message: string;
}
