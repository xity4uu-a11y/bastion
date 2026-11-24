"use client";

import React, { useEffect, useState } from "react";
import {
  X,
  Cpu,
  CheckCircle2,
  AlertCircle,
  KeyRound,
  Activity,
  Shield,
  Sliders,
} from "lucide-react";
import { api } from "@/lib/api";
import type {
  AuditScope,
  LLMProviderId,
  LLMSettings,
  LLMTestResponse,
  ProviderSecretStatus,
  SecretScannerPref,
} from "@/lib/types";
import { StatusBadge } from "./StatusBadge";

interface SettingsDrawerProps {
  open: boolean;
  settings: LLMSettings | null;
  onClose: () => void;
  onUpdated: (next: LLMSettings) => void;
}

const PROVIDER_DEFAULTS: Record<LLMProviderId, { label: string; model: string; envVar: string; note: string }> = {
  none: {
    label: "Disabled — Static Heuristic Fallback (No LLM)",
    model: "",
    envVar: "",
    note: "Runs deterministic pattern & boundary rules with Cloudflare schema validators. Clearly badged as Static Heuristic Fallback.",
  },
  gemini: {
    label: "Google Gemini (BYOK)",
    model: "gemini-2.5-flash",
    envVar: "GEMINI_API_KEY",
    note: "Launches isolated Session A (Hunter) and Session B (Verifier) via Google Generative Language API.",
  },
  anthropic: {
    label: "Anthropic Claude (BYOK)",
    model: "claude-3-5-sonnet-latest",
    envVar: "ANTHROPIC_API_KEY",
    note: "Launches isolated Session A (Hunter) and Session B (Verifier) via Anthropic Messages API.",
  },
  openai: {
    label: "OpenAI (BYOK)",
    model: "gpt-4o-mini",
    envVar: "OPENAI_API_KEY",
    note: "Launches isolated Session A (Hunter) and Session B (Verifier) via OpenAI Chat Completions API.",
  },
  ollama: {
    label: "Local Ollama (100% Offline)",
    model: "qwen2.5-coder:7b",
    envVar: "OLLAMA_BASE_URL",
    note: "Runs Hunter and Verifier sessions strictly against your local Ollama daemon with zero outbound telemetry.",
  },
};

function ProviderSourceBadge({ status }: { status?: ProviderSecretStatus }) {
  if (!status || !status.configured) {
    return <StatusBadge value="none" label="Not Configured" />;
  }
  if (status.source === "env") {
    return (
      <div className="inline-flex items-center gap-1.5">
        {status.masked_key && (
          <span className="font-mono text-[11px] text-[var(--text-tertiary)]">{status.masked_key}</span>
        )}
        <StatusBadge value="env" label="ENV Override" />
      </div>
    );
  }
  return (
    <div className="inline-flex items-center gap-1.5">
      {status.masked_key && (
        <span className="font-mono text-[11px] text-[var(--text-tertiary)]">{status.masked_key}</span>
      )}
      <StatusBadge value="vault" label="Encrypted Vault" />
    </div>
  );
}

export function SettingsDrawer({ open, settings, onClose, onUpdated }: SettingsDrawerProps) {
  const [provider, setProvider] = useState<LLMProviderId>("none");
  const [model, setModel] = useState("");
  const [ollamaUrl, setOllamaUrl] = useState("http://localhost:11434");
  const [scanner, setScanner] = useState<SecretScannerPref>("auto");
  const [defaultScope, setDefaultScope] = useState<AuditScope>("diff");
  const [defaultBudget, setDefaultBudget] = useState("1.50");
  const [geminiKey, setGeminiKey] = useState("");
  const [anthropicKey, setAnthropicKey] = useState("");
  const [openaiKey, setOpenaiKey] = useState("");
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [saveMsg, setSaveMsg] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<LLMTestResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (settings && open) {
      setProvider(settings.provider);
      setModel(settings.model || PROVIDER_DEFAULTS[settings.provider].model);
      setOllamaUrl(settings.ollama_url || "http://localhost:11434");
      setScanner(settings.default_secret_scanner || "auto");
      setDefaultScope(settings.default_audit_scope || "diff");
      setDefaultBudget(
        typeof settings.default_max_budget_usd === "number"
          ? settings.default_max_budget_usd.toFixed(2)
          : "1.50"
      );
      setGeminiKey("");
      setAnthropicKey("");
      setOpenaiKey("");
      setSaveMsg(null);
      setTestResult(null);
      setError(null);
    }
  }, [settings, open]);

  if (!open) return null;

  const geminiStatus = settings?.providers?.gemini;
  const anthropicStatus = settings?.providers?.anthropic;
  const openaiStatus = settings?.providers?.openai;
  const ollamaStatus = settings?.providers?.ollama;

  function parseBudget(): number {
    const parsed = Number.parseFloat(defaultBudget);
    if (!Number.isFinite(parsed) || parsed < 0.05) return 1.5;
    return Math.min(100, Number(parsed.toFixed(2)));
  }

  function handleProviderChange(next: LLMProviderId) {
    setProvider(next);
    setModel(PROVIDER_DEFAULTS[next].model);
    setTestResult(null);
  }

  async function handleSave(clearKeys = false) {
    setSaving(true);
    setError(null);
    setSaveMsg(null);
    try {
      const updated = await api.updateLLMSettings({
        provider,
        model: model.trim(),
        ollama_url: ollamaUrl.trim() || "http://localhost:11434",
        default_secret_scanner: scanner,
        default_audit_scope: defaultScope,
        default_max_budget_usd: parseBudget(),
        gemini_api_key: geminiKey.trim() || undefined,
        anthropic_api_key: anthropicKey.trim() || undefined,
        openai_api_key: openaiKey.trim() || undefined,
        clear_keys: clearKeys,
      });
      setGeminiKey("");
      setAnthropicKey("");
      setOpenaiKey("");
      onUpdated(updated);
      setSaveMsg(
        clearKeys
          ? "Encrypted vault keys cleared (environment variables, if set, remain active)."
          : "Settings saved. API keys encrypted with Fernet vault."
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save settings");
    } finally {
      setSaving(false);
    }
  }

  async function handleTest() {
    setTesting(true);
    setError(null);
    setTestResult(null);
    try {
      const saved = await api.updateLLMSettings({
        provider,
        model: model.trim(),
        ollama_url: ollamaUrl.trim() || "http://localhost:11434",
        default_secret_scanner: scanner,
        default_audit_scope: defaultScope,
        default_max_budget_usd: parseBudget(),
        gemini_api_key: geminiKey.trim() || undefined,
        anthropic_api_key: anthropicKey.trim() || undefined,
        openai_api_key: openaiKey.trim() || undefined,
      });
      onUpdated(saved);
      const res = await api.testLLMSettings();
      setTestResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Connection test failed");
    } finally {
      setTesting(false);
    }
  }

  const hasVaultKeys =
    geminiStatus?.source === "vault" ||
    anthropicStatus?.source === "vault" ||
    openaiStatus?.source === "vault" ||
    settings?.gemini_key_set ||
    settings?.anthropic_key_set ||
    settings?.openai_key_set;

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/30 backdrop-blur-[1px]">
      <div className="flex h-full w-full max-w-lg flex-col border-l border-[var(--border-strong)] bg-[var(--bg-surface)] shadow-2xl">
        <div className="flex items-center justify-between border-b border-[var(--border-subtle)] px-6 py-4">
          <div className="flex items-center gap-2.5">
            <Cpu className="h-4 w-4 text-[var(--text-secondary)]" strokeWidth={1.6} />
            <div>
              <h2 className="text-[15px] font-semibold tracking-tight text-[var(--text-primary)]">
                Engine, Vault &amp; BYOK LLM Settings
              </h2>
              <p className="text-xs text-[var(--text-secondary)]">
                Encrypted local key vault, Gate 2 scoping/budget, and Gate 1 plugin
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
            aria-label="Close settings"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Active Gate 2 Engine + Vault Security Status */}
          <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-subtle)] p-4 space-y-2.5">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-medium text-[var(--text-secondary)]">
                Active Gate 2 Mode
              </span>
              <StatusBadge
                value={settings?.active_mode ?? "static_heuristic"}
                label={settings?.active_badge ?? "Static Heuristic Fallback (No LLM)"}
              />
            </div>

            <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[var(--border-subtle)] pt-2.5 text-[11px]">
              <span className="inline-flex items-center gap-1.5 text-[var(--text-secondary)]">
                <Shield className="h-3.5 w-3.5 text-[var(--text-tertiary)]" strokeWidth={1.6} />
                Fernet Encrypted Vault (<code className="font-mono">~/.bastion/keys/vault.key</code>)
              </span>
              <span className="font-mono text-[var(--text-tertiary)]">
                {settings?.configured
                  ? `source: ${settings.source}${settings.masked_key ? ` · ${settings.masked_key}` : ""}`
                  : "source: none"}
              </span>
            </div>

            <p className="text-[11px] text-[var(--text-tertiary)] leading-relaxed">
              API keys are never stored in plaintext in SQLite and are automatically scrubbed from SSE logs, tracebacks, and certificates. Environment variables (<code className="font-mono">GEMINI_API_KEY</code>, <code className="font-mono">ANTHROPIC_API_KEY</code>, <code className="font-mono">OPENAI_API_KEY</code>, <code className="font-mono">OLLAMA_BASE_URL</code>) always override local vault entries.
            </p>
          </div>

          {/* Gate 2 Provider Selector */}
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-[var(--text-secondary)] mb-1.5">
                Gate 2 BYOK LLM Provider
              </label>
              <select
                value={provider}
                onChange={(e) => handleProviderChange(e.target.value as LLMProviderId)}
                className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-3 py-2 text-xs text-[var(--text-primary)] focus:outline-none"
              >
                {(Object.keys(PROVIDER_DEFAULTS) as LLMProviderId[]).map((id) => (
                  <option key={id} value={id}>
                    {PROVIDER_DEFAULTS[id].label}
                  </option>
                ))}
              </select>
              <p className="mt-1.5 text-[11px] text-[var(--text-tertiary)]">
                {PROVIDER_DEFAULTS[provider].note}
              </p>
            </div>

            {provider !== "none" && (
              <div>
                <label className="block text-xs font-medium text-[var(--text-secondary)] mb-1.5">
                  Model Identifier
                </label>
                <input
                  type="text"
                  value={model}
                  onChange={(e) => setModel(e.target.value)}
                  placeholder={PROVIDER_DEFAULTS[provider].model}
                  className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-3 py-2 text-xs font-mono text-[var(--text-primary)] focus:outline-none"
                />
              </div>
            )}

            {provider === "gemini" && (
              <div>
                <div className="flex items-center justify-between gap-2 mb-1.5">
                  <label className="text-xs font-medium text-[var(--text-secondary)]">
                    Google Gemini API Key
                  </label>
                  <ProviderSourceBadge status={geminiStatus} />
                </div>
                <input
                  type="password"
                  value={geminiKey}
                  onChange={(e) => setGeminiKey(e.target.value)}
                  disabled={geminiStatus?.source === "env"}
                  placeholder={
                    geminiStatus?.source === "env"
                      ? "Managed via GEMINI_API_KEY environment variable"
                      : geminiStatus?.configured
                      ? "Leave blank to keep encrypted vault key"
                      : "AIza..."
                  }
                  className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-3 py-2 text-xs font-mono text-[var(--text-primary)] disabled:opacity-60 focus:outline-none"
                />
              </div>
            )}

            {provider === "anthropic" && (
              <div>
                <div className="flex items-center justify-between gap-2 mb-1.5">
                  <label className="text-xs font-medium text-[var(--text-secondary)]">
                    Anthropic Claude API Key
                  </label>
                  <ProviderSourceBadge status={anthropicStatus} />
                </div>
                <input
                  type="password"
                  value={anthropicKey}
                  onChange={(e) => setAnthropicKey(e.target.value)}
                  disabled={anthropicStatus?.source === "env"}
                  placeholder={
                    anthropicStatus?.source === "env"
                      ? "Managed via ANTHROPIC_API_KEY environment variable"
                      : anthropicStatus?.configured
                      ? "Leave blank to keep encrypted vault key"
                      : "sk-ant-..."
                  }
                  className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-3 py-2 text-xs font-mono text-[var(--text-primary)] disabled:opacity-60 focus:outline-none"
                />
              </div>
            )}

            {provider === "openai" && (
              <div>
                <div className="flex items-center justify-between gap-2 mb-1.5">
                  <label className="text-xs font-medium text-[var(--text-secondary)]">
                    OpenAI API Key
                  </label>
                  <ProviderSourceBadge status={openaiStatus} />
                </div>
                <input
                  type="password"
                  value={openaiKey}
                  onChange={(e) => setOpenaiKey(e.target.value)}
                  disabled={openaiStatus?.source === "env"}
                  placeholder={
                    openaiStatus?.source === "env"
                      ? "Managed via OPENAI_API_KEY environment variable"
                      : openaiStatus?.configured
                      ? "Leave blank to keep encrypted vault key"
                      : "sk-..."
                  }
                  className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-3 py-2 text-xs font-mono text-[var(--text-primary)] disabled:opacity-60 focus:outline-none"
                />
              </div>
            )}

            {provider === "ollama" && (
              <div>
                <div className="flex items-center justify-between gap-2 mb-1.5">
                  <label className="text-xs font-medium text-[var(--text-secondary)]">
                    Local Ollama Base URL
                  </label>
                  <ProviderSourceBadge status={ollamaStatus} />
                </div>
                <input
                  type="text"
                  value={ollamaUrl}
                  onChange={(e) => setOllamaUrl(e.target.value)}
                  disabled={ollamaStatus?.source === "env"}
                  placeholder="http://localhost:11434"
                  className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-3 py-2 text-xs font-mono text-[var(--text-primary)] disabled:opacity-60 focus:outline-none"
                />
              </div>
            )}
          </div>

          {/* Gate 2 Default Scope & Token/Cost Budgeting */}
          <div className="border-t border-[var(--border-subtle)] pt-5 space-y-3">
            <div className="flex items-center gap-1.5 text-xs font-semibold text-[var(--text-primary)]">
              <Sliders className="h-3.5 w-3.5 text-[var(--text-secondary)]" />
              Gate 2 Default Scope &amp; Token Budget
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[11px] font-medium text-[var(--text-secondary)] mb-1">
                  Default Audit Scope
                </label>
                <select
                  value={defaultScope}
                  onChange={(e) => setDefaultScope(e.target.value as AuditScope)}
                  className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-2.5 py-2 text-xs text-[var(--text-primary)] focus:outline-none"
                >
                  <option value="diff">Diff (PR / Local Changes)</option>
                  <option value="full">Full Repository</option>
                </select>
              </div>
              <div>
                <label className="block text-[11px] font-medium text-[var(--text-secondary)] mb-1">
                  Max LLM Spend Cap (USD)
                </label>
                <input
                  type="number"
                  min={0.05}
                  max={100}
                  step={0.1}
                  value={defaultBudget}
                  onChange={(e) => setDefaultBudget(e.target.value)}
                  className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-2.5 py-2 text-xs font-mono tabular-nums text-[var(--text-primary)] focus:outline-none"
                />
              </div>
            </div>
            <p className="text-[11px] text-[var(--text-tertiary)] leading-relaxed">
              In <code className="font-mono">diff</code> mode, Gate 2 scopes to changed files plus direct local imports. If files exceed budget, security-critical paths (auth, API routes, SQL/ORM, crypto, shell) run first and lower-risk files are recorded as <code className="font-mono">deferred</code> in Cloudflare&apos;s coverage ledger.
            </p>
          </div>

          {/* Gate 1 Pluggable Scanner Default */}
          <div className="border-t border-[var(--border-subtle)] pt-5 space-y-2">
            <div className="flex items-center gap-1.5 text-xs font-semibold text-[var(--text-primary)]">
              <KeyRound className="h-3.5 w-3.5 text-[var(--text-secondary)]" />
              Gate 1 Pluggable Secret Scanner (AGPL-Safe)
            </div>
            <select
              value={scanner}
              onChange={(e) => setScanner(e.target.value as SecretScannerPref)}
              className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-3 py-2 text-xs text-[var(--text-primary)] focus:outline-none"
            >
              <option value="auto">Auto (External TruffleHog -&gt; Gitleaks MIT -&gt; Fallback)</option>
              <option value="trufflehog">TruffleHog (External User-Installed CLI)</option>
              <option value="gitleaks">Gitleaks (MIT License Plugin)</option>
            </select>
            <p className="text-[11px] text-[var(--text-tertiary)] leading-relaxed">
              Both scanners run strictly via external CLI subprocess plugins with zero vendored AGPL code and normalize into identical Bastion finding records.
            </p>
          </div>

          {/* Feedback Banners */}
          {testResult && (
            <div
              className={`flex items-start gap-2 rounded-xl border px-4 py-3 text-xs ${
                testResult.ok
                  ? "border-[var(--status-pass-border)] bg-[var(--status-pass-bg)] text-[var(--status-pass-fg)]"
                  : "border-[var(--status-fail-border)] bg-[var(--status-fail-bg)] text-[var(--status-fail-fg)]"
              }`}
            >
              {testResult.ok ? (
                <CheckCircle2 className="h-4 w-4 shrink-0 mt-0.5" />
              ) : (
                <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
              )}
              <span>{testResult.message}</span>
            </div>
          )}

          {saveMsg && (
            <div className="rounded-xl border border-[var(--status-pass-border)] bg-[var(--status-pass-bg)] px-4 py-2.5 text-xs text-[var(--status-pass-fg)]">
              {saveMsg}
            </div>
          )}

          {error && (
            <div className="rounded-xl border border-[var(--status-fail-border)] bg-[var(--status-fail-bg)] px-4 py-2.5 text-xs text-[var(--status-fail-fg)]">
              {error}
            </div>
          )}
        </div>

        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[var(--border-subtle)] px-6 py-4">
          <div className="flex items-center gap-2">
            {provider !== "none" && (
              <button
                type="button"
                disabled={testing || saving}
                onClick={handleTest}
                className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-3 py-2 text-xs font-medium text-[var(--text-primary)] hover:bg-[var(--bg-hover)] disabled:opacity-50"
              >
                <Activity className="h-3.5 w-3.5" />
                {testing ? "Testing..." : "Test Connection"}
              </button>
            )}
            {hasVaultKeys && (
              <button
                type="button"
                disabled={saving}
                onClick={() => handleSave(true)}
                className="rounded-lg border border-[var(--border-subtle)] px-3 py-2 text-xs text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
              >
                Clear Vault Keys
              </button>
            )}
          </div>

          <button
            type="button"
            disabled={saving}
            onClick={() => handleSave(false)}
            className="rounded-lg bg-[var(--accent-neutral)] px-4 py-2 text-xs font-medium text-[var(--accent-neutral-fg)] hover:opacity-90 disabled:opacity-50"
          >
            {saving ? "Saving..." : "Save Settings"}
          </button>
        </div>
      </div>
    </div>
  );
}
