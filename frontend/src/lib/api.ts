import type {
  ArtifactRecord,
  AuditEvent,
  AuditScope,
  BlaActionResponse,
  CertificateVerifyResponse,
  CicdMode,
  CicdWorkflowResponse,
  CoverageLedgerEntry,
  Finding,
  FindingCodeContext,
  LLMSettings,
  LLMSettingsUpdate,
  LLMTestResponse,
  Project,
  PublicKeyResponse,
  ReleaseRun,
  SecretScannerPref,
  SmokeTestResult,
  SystemToolsResponse,
} from "./types";

export const API_BASE =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") || "http://127.0.0.1:8000";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers || {}),
    },
    cache: "no-store",
  });
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const errBody = (await res.json()) as { detail?: string };
      if (errBody?.detail) detail = errBody.detail;
    } catch {
      // ignore non-json error body
    }
    throw new Error(detail);
  }
  if (res.status === 204) {
    return undefined as T;
  }
  return (await res.json()) as T;
}

export const api = {
  getTools: () => request<SystemToolsResponse>("/api/system/tools"),

  getPublicKey: () => request<PublicKeyResponse>("/api/system/public-key"),

  verifyCertificate: (certificate: Record<string, unknown>, publicKeyPem?: string) =>
    request<CertificateVerifyResponse>("/api/certificates/verify", {
      method: "POST",
      body: JSON.stringify({
        certificate,
        public_key_pem: publicKeyPem?.trim() || null,
      }),
    }),

  getLLMSettings: () => request<LLMSettings>("/api/settings/llm"),

  updateLLMSettings: (payload: LLMSettingsUpdate) =>
    request<LLMSettings>("/api/settings/llm", {
      method: "PUT",
      body: JSON.stringify(payload),
    }),

  testLLMSettings: () =>
    request<LLMTestResponse>("/api/settings/llm/test", { method: "POST" }),

  inspectPath: (path: string) =>
    request<{
      path: string;
      exists: boolean;
      is_git_repo: boolean;
      git_commit: string | null;
      git_branch: string | null;
      git_dirty: boolean;
      suggested_name: string;
      sample_target_path: string;
    }>(`/api/system/inspect-path?path=${encodeURIComponent(path)}`),

  listProjects: () => request<Project[]>("/api/projects"),

  createProject: (payload: {
    name: string;
    path: string;
    description: string;
    default_secret_scanner: SecretScannerPref;
    default_bla_intensity: Project["default_bla_intensity"];
    default_audit_profile: Project["default_audit_profile"];
    smoke_test_cmd?: string;
  }) =>
    request<Project>("/api/projects", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  updateProject: (
    projectId: string,
    payload: Partial<
      Pick<
        Project,
        | "name"
        | "description"
        | "default_secret_scanner"
        | "default_bla_intensity"
        | "default_audit_profile"
        | "smoke_test_cmd"
      >
    >
  ) =>
    request<Project>(`/api/projects/${projectId}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),

  deleteProject: (projectId: string) =>
    request<void>(`/api/projects/${projectId}`, { method: "DELETE" }),

  getGithubActionsWorkflow: (projectId: string, mode: CicdMode = "container", image?: string) => {
    const qs = new URLSearchParams({ mode });
    if (image && image.trim()) {
      qs.set("image", image.trim());
    }
    return request<CicdWorkflowResponse>(
      `/api/projects/${projectId}/cicd/github-actions?${qs.toString()}`
    );
  },

  getProjectArtifacts: (projectId: string) =>
    request<ArtifactRecord[]>(`/api/projects/${projectId}/artifacts`),

  getProjectLedger: (projectId: string) =>
    request<CoverageLedgerEntry[]>(`/api/projects/${projectId}/ledger`),

  applyBla: (projectId: string, intensity: string, forceSimulation = false) =>
    request<BlaActionResponse>(`/api/projects/${projectId}/bla/apply`, {
      method: "POST",
      body: JSON.stringify({ intensity, force_simulation: forceSimulation }),
    }),

  restoreBla: (projectId: string, forceSimulation = false) =>
    request<BlaActionResponse>(
      `/api/projects/${projectId}/bla/restore?force_simulation=${forceSimulation}`,
      { method: "POST" }
    ),

  runSmokeTest: (projectId: string, smokeTestCmd?: string, timeoutSeconds = 30) =>
    request<SmokeTestResult>(`/api/projects/${projectId}/bla/smoke-test`, {
      method: "POST",
      body: JSON.stringify({
        smoke_test_cmd: smokeTestCmd?.trim() || null,
        timeout_seconds: timeoutSeconds,
      }),
    }),

  listRuns: (projectId?: string) =>
    request<ReleaseRun[]>(
      projectId ? `/api/runs?project_id=${encodeURIComponent(projectId)}` : "/api/runs"
    ),

  getRun: (runId: string) => request<ReleaseRun>(`/api/runs/${runId}`),

  getRunEvents: (runId: string) => request<AuditEvent[]>(`/api/runs/${runId}/events`),

  startRun: (payload: {
    project_id: string;
    secret_scanner?: SecretScannerPref;
    bla_intensity?: string;
    audit_profile?: string;
    audit_scope?: AuditScope;
    base_ref?: string;
    max_budget_usd?: number;
    smoke_test_cmd?: string;
    stop_on_gate1_fail?: boolean;
    force_simulation?: boolean;
  }) =>
    request<ReleaseRun>("/api/runs", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  abortRun: (runId: string) =>
    request<{ run_id: string; abort_requested: boolean }>(`/api/runs/${runId}/abort`, {
      method: "POST",
    }),

  retryRun: (runId: string) =>
    request<ReleaseRun>(`/api/runs/${runId}/retry`, { method: "POST" }),

  listFindings: (params: {
    project_id?: string;
    run_id?: string;
    gate_number?: number;
    verdict?: string;
    severity?: string;
    resolved?: boolean;
    search?: string;
  }) => {
    const qs = new URLSearchParams();
    if (params.project_id) qs.set("project_id", params.project_id);
    if (params.run_id) qs.set("run_id", params.run_id);
    if (params.gate_number) qs.set("gate_number", String(params.gate_number));
    if (params.verdict) qs.set("verdict", params.verdict);
    if (params.severity) qs.set("severity", params.severity);
    if (params.resolved !== undefined) qs.set("resolved", String(params.resolved));
    if (params.search) qs.set("search", params.search);
    const query = qs.toString();
    return request<Finding[]>(`/api/findings${query ? `?${query}` : ""}`);
  },

  updateFinding: (findingId: string, payload: { resolved?: boolean; resolution_note?: string }) =>
    request<Finding>(`/api/findings/${findingId}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),

  getFindingContext: (findingId: string) =>
    request<FindingCodeContext>(`/api/findings/${findingId}/context`),

  sarifExportUrl: (projectId?: string, runId?: string) => {
    const qs = new URLSearchParams();
    if (projectId) qs.set("project_id", projectId);
    if (runId) qs.set("run_id", runId);
    return `${API_BASE}/api/findings/export/sarif?${qs.toString()}`;
  },

  certificateUrl: (runId: string, format: "json" | "md" | "pdf") =>
    `${API_BASE}/api/runs/${runId}/certificate?format=${format}`,

  getCertificateJson: (runId: string) =>
    request<Record<string, unknown>>(`/api/runs/${runId}/certificate?format=json`),

  runStreamUrl: (runId: string) => `${API_BASE}/api/runs/${runId}/stream`,
};
