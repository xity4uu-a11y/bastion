"use client";

import React, { useEffect, useState } from "react";
import {
  Lock,
  RotateCcw,
  ArrowUpRight,
  Layers,
  CheckCircle2,
  AlertCircle,
  AlertTriangle,
  Terminal,
  Play,
  Save,
} from "lucide-react";
import { api } from "@/lib/api";
import type { ArtifactRecord, Project, ReleaseRun, SmokeTestResult } from "@/lib/types";
import { StatusBadge } from "./StatusBadge";

interface ArtifactShieldViewProps {
  project: Project | null;
  latestRun: ReleaseRun | null;
  artifacts: ArtifactRecord[];
  onRefresh: () => Promise<void>;
  onProjectUpdated: (updated: Project) => void;
  onRunWithIntensity: (intensity: Project["default_bla_intensity"]) => void;
}

const INTENSITIES: Array<{
  id: Project["default_bla_intensity"];
  label: string;
  desc: string;
}> = [
  { id: "stealth", label: "Stealth", desc: "Minimal footprint, low overhead" },
  { id: "balanced", label: "Balanced", desc: "Recommended pre-ship shield" },
  { id: "maximum", label: "Maximum", desc: "Deep structural & AST poisoning" },
  { id: "bankrupt", label: "Bankrupt", desc: "Maximum token/cost amplification" },
];

function formatBytes(bytes: number): string {
  if (!bytes) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function extractRunSmoke(run: ReleaseRun | null): SmokeTestResult | null {
  const g3 = run?.gates.find((g) => g.gate_number === 3);
  const raw = g3?.metadata?.smoke_test as Partial<SmokeTestResult> | undefined;
  if (!raw || !raw.status) return null;
  return {
    status: raw.status,
    command: raw.command ?? "",
    exit_code: raw.exit_code ?? null,
    duration_ms: raw.duration_ms ?? 0,
    stdout: raw.stdout ?? "",
    stderr: raw.stderr ?? "",
    tested_mirror: Boolean(raw.tested_mirror),
    message: raw.message ?? "",
  };
}

export function ArtifactShieldView({
  project,
  latestRun,
  artifacts,
  onRefresh,
  onProjectUpdated,
  onRunWithIntensity,
}: ArtifactShieldViewProps) {
  const [intensity, setIntensity] = useState<Project["default_bla_intensity"]>(
    project?.default_bla_intensity ?? "balanced"
  );
  const [smokeCmd, setSmokeCmd] = useState<string>(project?.smoke_test_cmd ?? "");
  const [manualSmoke, setManualSmoke] = useState<SmokeTestResult | null>(null);
  const [savingSmoke, setSavingSmoke] = useState(false);
  const [runningSmoke, setRunningSmoke] = useState(false);
  const [confirmApplyDespiteSmoke, setConfirmApplyDespiteSmoke] = useState(false);
  const [busyAction, setBusyAction] = useState<"apply" | "restore" | null>(null);
  const [feedback, setFeedback] = useState<{ type: "ok" | "err"; text: string } | null>(null);

  const projectId = project?.id;
  const projectDefaultIntensity = project?.default_bla_intensity;
  const projectSmokeCmd = project?.smoke_test_cmd;

  useEffect(() => {
    if (projectId && projectDefaultIntensity) {
      setIntensity(projectDefaultIntensity);
      setSmokeCmd(projectSmokeCmd || "");
      setManualSmoke(null);
      setConfirmApplyDespiteSmoke(false);
    }
  }, [projectId, projectDefaultIntensity, projectSmokeCmd]);

  if (!project) {
    return (
      <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-10 text-center text-xs text-[var(--text-tertiary)]">
        Select a project to inspect discovered build artifacts and BLA Anti-REA hardening controls.
      </div>
    );
  }

  const effectiveSmoke = manualSmoke ?? extractRunSmoke(latestRun);
  const effectiveSmokeStatus = effectiveSmoke?.status ?? project.latest_smoke_status ?? "skipped";
  const smokeFailed = effectiveSmokeStatus === "failed" || effectiveSmokeStatus === "timeout";

  async function handleSaveSmokeCmd() {
    if (!project) return;
    setSavingSmoke(true);
    setFeedback(null);
    try {
      const updated = await api.updateProject(project.id, {
        smoke_test_cmd: smokeCmd.trim(),
      });
      onProjectUpdated(updated);
      setFeedback({ type: "ok", text: "Post-BLA smoke test command saved." });
    } catch (err) {
      setFeedback({
        type: "err",
        text: err instanceof Error ? err.message : "Failed to save smoke test command",
      });
    } finally {
      setSavingSmoke(false);
    }
  }

  async function handleRunSmokeTest() {
    if (!project) return;
    setRunningSmoke(true);
    setFeedback(null);
    setConfirmApplyDespiteSmoke(false);
    try {
      const res = await api.runSmokeTest(project.id, smokeCmd.trim() || undefined);
      setManualSmoke(res);
      if (res.status === "passed") {
        setFeedback({ type: "ok", text: res.message || "Post-BLA smoke verification passed." });
      } else if (res.status === "failed" || res.status === "timeout") {
        setFeedback({
          type: "err",
          text: res.message || "Post-BLA smoke verification failed against .bla-hardened/.",
        });
      }
    } catch (err) {
      setFeedback({
        type: "err",
        text: err instanceof Error ? err.message : "Failed to execute smoke test",
      });
    } finally {
      setRunningSmoke(false);
    }
  }

  async function handleApply() {
    if (!project) return;
    if (smokeFailed && !confirmApplyDespiteSmoke) {
      setConfirmApplyDespiteSmoke(true);
      return;
    }
    setBusyAction("apply");
    setFeedback(null);
    try {
      const res = await api.applyBla(project.id, intensity);
      setFeedback({ type: "ok", text: res.message });
      setConfirmApplyDespiteSmoke(false);
      await onRefresh();
    } catch (err) {
      setFeedback({
        type: "err",
        text: err instanceof Error ? err.message : "Failed to apply BLA mirror",
      });
    } finally {
      setBusyAction(null);
    }
  }

  async function handleRestore() {
    if (!project) return;
    setBusyAction("restore");
    setFeedback(null);
    try {
      const res = await api.restoreBla(project.id);
      setFeedback({ type: "ok", text: res.message });
      await onRefresh();
    } catch (err) {
      setFeedback({
        type: "err",
        text: err instanceof Error ? err.message : "Failed to restore original build outputs",
      });
    } finally {
      setBusyAction(null);
    }
  }

  const verifiedCount = artifacts.filter((a) => a.verified).length;
  const avgDefense =
    artifacts.length > 0
      ? (artifacts.reduce((acc, a) => acc + a.defense_score, 0) / artifacts.length).toFixed(1)
      : "0.0";
  const maxAmp =
    artifacts.length > 0
      ? Math.max(...artifacts.map((a) => a.token_amplification)).toFixed(1)
      : "0.0";

  return (
    <div className="space-y-6">
      {/* Header + Apply/Restore Release Controls */}
      <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-6 space-y-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="flex flex-wrap items-center gap-2.5">
              <h1 className="text-base font-semibold tracking-tight text-[var(--text-primary)]">
                Artifact Shield (BLA)
              </h1>
              <StatusBadge
                value={project.bla_applied ? "applied" : verifiedCount > 0 ? "hardened" : "discovered"}
                label={
                  project.bla_applied
                    ? "Promoted to Release"
                    : verifiedCount > 0
                    ? "Staged in .bla-hardened"
                    : "Unprotected"
                }
              />
              {effectiveSmokeStatus !== "skipped" && (
                <StatusBadge
                  value={effectiveSmokeStatus}
                  label={`Smoke: ${effectiveSmokeStatus}`}
                />
              )}
            </div>
            <p className="mt-1 text-xs text-[var(--text-secondary)] max-w-2xl leading-relaxed">
              BLA runs an audit &rarr; protect &rarr; verify pipeline into{" "}
              <code className="font-mono text-[var(--text-primary)]">.bla-hardened/</code> without modifying source files.
              Validate hardened builds with a Post-BLA smoke test before promoting with{" "}
              <code className="font-mono">--apply</code> or rolling back with{" "}
              <code className="font-mono">--restore</code>.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => onRunWithIntensity(intensity)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-3.5 py-2 text-xs font-medium text-[var(--text-primary)] hover:bg-[var(--bg-hover)] transition-colors"
            >
              <Layers className="h-3.5 w-3.5" />
              Re-Harden Mirror
            </button>

            <button
              type="button"
              disabled={busyAction !== null}
              onClick={handleRestore}
              className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-3.5 py-2 text-xs font-medium text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] disabled:opacity-50 transition-colors"
            >
              <RotateCcw className="h-3.5 w-3.5" />
              {busyAction === "restore" ? "Restoring..." : "Restore (--restore)"}
            </button>

            <button
              type="button"
              disabled={busyAction !== null || artifacts.length === 0}
              onClick={handleApply}
              className={`inline-flex items-center gap-1.5 rounded-lg px-4 py-2 text-xs font-medium hover:opacity-90 disabled:opacity-50 transition-opacity ${
                confirmApplyDespiteSmoke
                  ? "border border-[var(--status-fail-border)] bg-[var(--status-fail-bg)] text-[var(--status-fail-fg)]"
                  : "bg-[var(--accent-neutral)] text-[var(--accent-neutral-fg)]"
              }`}
            >
              <ArrowUpRight className="h-3.5 w-3.5" />
              {busyAction === "apply"
                ? "Promoting..."
                : confirmApplyDespiteSmoke
                ? "Confirm Override & Apply"
                : "Apply to Release (--apply)"}
            </button>
          </div>
        </div>

        {/* Warning Banner Before --apply if Smoke Failed */}
        {smokeFailed && (
          <div className="flex flex-wrap items-start justify-between gap-3 rounded-xl border border-[var(--status-fail-border)] bg-[var(--status-fail-bg)] px-4 py-3 text-xs text-[var(--status-fail-fg)]">
            <div className="flex items-start gap-2.5">
              <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
              <div className="space-y-0.5">
                <div className="font-semibold">
                  Smoke Verification Failed on .bla-hardened/ Build
                </div>
                <div>
                  Promoting with <code className="font-mono">--apply</code> is not recommended until the hardened artifact passes your smoke command or BLA intensity is lowered (e.g., <code className="font-mono">stealth</code>).
                  {confirmApplyDespiteSmoke
                    ? " Click 'Confirm Override & Apply' above to force promotion anyway."
                    : ""}
                </div>
              </div>
            </div>
            {confirmApplyDespiteSmoke && (
              <button
                type="button"
                onClick={() => setConfirmApplyDespiteSmoke(false)}
                className="rounded-md border border-[var(--status-fail-border)] px-2.5 py-1 text-[11px] font-medium hover:opacity-80"
              >
                Cancel
              </button>
            )}
          </div>
        )}

        {/* Intensity Selector */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 border-t border-[var(--border-subtle)] pt-4">
          {INTENSITIES.map((opt) => {
            const active = intensity === opt.id;
            return (
              <button
                key={opt.id}
                type="button"
                onClick={() => setIntensity(opt.id)}
                className={`rounded-xl border px-3.5 py-3 text-left transition-colors ${
                  active
                    ? "border-[var(--text-primary)] bg-[var(--bg-subtle)]"
                    : "border-[var(--border-subtle)] bg-[var(--bg-canvas)] hover:border-[var(--border-strong)]"
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-[var(--text-primary)]">{opt.label}</span>
                  {active && <span className="h-1.5 w-1.5 rounded-full bg-[var(--text-primary)]" />}
                </div>
                <p className="mt-1 text-[11px] text-[var(--text-secondary)]">{opt.desc}</p>
              </button>
            );
          })}
        </div>

        {feedback && (
          <div
            className={`flex items-center gap-2 rounded-xl border px-4 py-3 text-xs ${
              feedback.type === "ok"
                ? "border-[var(--status-pass-border)] bg-[var(--status-pass-bg)] text-[var(--status-pass-fg)]"
                : "border-[var(--status-fail-border)] bg-[var(--status-fail-bg)] text-[var(--status-fail-fg)]"
            }`}
          >
            {feedback.type === "ok" ? (
              <CheckCircle2 className="h-4 w-4 shrink-0" />
            ) : (
              <AlertCircle className="h-4 w-4 shrink-0" />
            )}
            <span>{feedback.text}</span>
          </div>
        )}
      </div>

      {/* Post-BLA Smoke Verification Panel */}
      <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-6 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Terminal className="h-4 w-4 text-[var(--text-secondary)]" strokeWidth={1.6} />
            <div>
              <h2 className="text-sm font-semibold text-[var(--text-primary)]">
                Post-BLA Smoke Verification Hook
              </h2>
              <p className="text-xs text-[var(--text-secondary)]">
                Executes against an isolated copy overlaid with <code className="font-mono">.bla-hardened/</code> and stripped secret env vars to confirm obfuscated outputs still boot cleanly.
              </p>
            </div>
          </div>
          <StatusBadge
            value={effectiveSmokeStatus}
            label={
              effectiveSmokeStatus === "skipped"
                ? "Not Configured"
                : `Smoke ${effectiveSmokeStatus}`
            }
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <input
            type="text"
            value={smokeCmd}
            onChange={(e) => setSmokeCmd(e.target.value)}
            placeholder="e.g. node dist/index.js --health  or  pytest -q"
            className="flex-1 min-w-[240px] rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-3 py-2 text-xs font-mono text-[var(--text-primary)] placeholder:text-[var(--text-tertiary)] focus:outline-none"
          />
          <button
            type="button"
            disabled={savingSmoke}
            onClick={handleSaveSmokeCmd}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-3 py-2 text-xs font-medium text-[var(--text-primary)] hover:bg-[var(--bg-hover)] disabled:opacity-50"
          >
            <Save className="h-3.5 w-3.5" />
            {savingSmoke ? "Saving..." : "Save Command"}
          </button>
          <button
            type="button"
            disabled={runningSmoke || !smokeCmd.trim()}
            onClick={handleRunSmokeTest}
            className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--accent-neutral)] px-3.5 py-2 text-xs font-medium text-[var(--accent-neutral-fg)] hover:opacity-90 disabled:opacity-50"
          >
            <Play className="h-3.5 w-3.5 fill-current" />
            {runningSmoke ? "Running Smoke..." : "Run Smoke Test"}
          </button>
        </div>

        {effectiveSmoke && effectiveSmoke.status !== "skipped" && (
          <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-terminal)] p-4 space-y-2 font-mono text-[11px]">
            <div className="flex flex-wrap items-center justify-between gap-2 text-[var(--text-secondary)]">
              <span>$ {effectiveSmoke.command}</span>
              <span className="tabular-nums text-[var(--text-tertiary)]">
                exit {effectiveSmoke.exit_code ?? "timeout"} · {effectiveSmoke.duration_ms} ms
                {effectiveSmoke.tested_mirror ? " · .bla-hardened overlaid" : " · source tree"}
              </span>
            </div>
            {effectiveSmoke.stdout && (
              <pre className="whitespace-pre-wrap text-[var(--text-primary)] max-h-36 overflow-auto border-t border-[var(--border-subtle)] pt-2">
                {effectiveSmoke.stdout}
              </pre>
            )}
            {effectiveSmoke.stderr && (
              <pre className="whitespace-pre-wrap text-[var(--status-fail-fg)] max-h-36 overflow-auto border-t border-[var(--border-subtle)] pt-2">
                {effectiveSmoke.stderr}
              </pre>
            )}
          </div>
        )}
      </div>

      {/* Summary KPI Row */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5">
          <div className="text-[11px] font-medium uppercase tracking-[0.06em] text-[var(--text-tertiary)]">
            Discovered Artifacts
          </div>
          <div className="mt-2 text-2xl font-semibold tabular-nums text-[var(--text-primary)]">
            {artifacts.length}
          </div>
          <div className="mt-1 text-xs text-[var(--text-secondary)]">
            {verifiedCount} verified against Counter-REA invariants
          </div>
        </div>
        <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5">
          <div className="text-[11px] font-medium uppercase tracking-[0.06em] text-[var(--text-tertiary)]">
            Average Defense Score
          </div>
          <div className="mt-2 text-2xl font-semibold tabular-nums text-[var(--text-primary)]">
            {avgDefense} <span className="text-sm font-normal text-[var(--text-tertiary)]">/ 100</span>
          </div>
          <div className="mt-1 text-xs text-[var(--text-secondary)]">
            Post-hardening verification score
          </div>
        </div>
        <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5">
          <div className="text-[11px] font-medium uppercase tracking-[0.06em] text-[var(--text-tertiary)]">
            Peak Token Amplification
          </div>
          <div className="mt-2 text-2xl font-semibold tabular-nums text-[var(--text-primary)]">
            {maxAmp}x
          </div>
          <div className="mt-1 text-xs text-[var(--text-secondary)]">
            Adversarial LLM reverse-engineering cost multiplier
          </div>
        </div>
      </div>

      {/* Discovered & Hardened Artifacts Table */}
      <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] overflow-hidden">
        <div className="flex items-center justify-between border-b border-[var(--border-subtle)] px-6 py-4">
          <div className="flex items-center gap-2">
            <Lock className="h-4 w-4 text-[var(--text-secondary)]" strokeWidth={1.6} />
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">
              Build Artifacts &amp; Before / After Verification
            </h2>
          </div>
          <span className="text-[11px] font-mono text-[var(--text-tertiary)]">
            dist/, build/, .asar, .wasm, .py/.pyc, binaries, .safetensors/.gguf
          </span>
        </div>

        {artifacts.length === 0 ? (
          <div className="px-6 py-12 text-center text-xs text-[var(--text-tertiary)]">
            No build artifacts discovered yet. Build your project into <code className="font-mono">dist/</code> or{" "}
            <code className="font-mono">build/</code> and re-run Gate 3.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-[var(--border-subtle)] text-[11px] font-medium uppercase tracking-[0.05em] text-[var(--text-tertiary)]">
                  <th className="px-6 py-3">Artifact</th>
                  <th className="px-4 py-3">Format</th>
                  <th className="px-4 py-3">Size (Before &rarr; After)</th>
                  <th className="px-4 py-3">Defense Score</th>
                  <th className="px-4 py-3">Amplification</th>
                  <th className="px-6 py-3 text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-subtle)]">
                {artifacts.map((a) => (
                  <tr key={a.id} className="hover:bg-[var(--bg-hover)]/60 transition-colors">
                    <td className="px-6 py-3.5">
                      <div className="font-mono font-medium text-[var(--text-primary)]">{a.relative_path}</div>
                      {a.mirror_path && (
                        <div className="mt-0.5 text-[11px] font-mono text-[var(--text-tertiary)] truncate max-w-md">
                          mirror: {a.mirror_path}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-3.5 font-mono text-[11px] text-[var(--text-secondary)]">
                      {a.artifact_format}
                    </td>
                    <td className="px-4 py-3.5 font-mono text-[11px] tabular-nums text-[var(--text-secondary)]">
                      {formatBytes(a.input_bytes)}
                      {a.output_bytes > 0 ? ` -> ${formatBytes(a.output_bytes)}` : " -> staged pending"}
                    </td>
                    <td className="px-4 py-3.5">
                      <div className="flex items-center gap-2.5">
                        <div className="h-1.5 w-20 overflow-hidden rounded-full bg-[var(--bg-subtle)]">
                          <div
                            className="h-full rounded-full"
                            style={{
                              width: `${Math.min(100, a.defense_score)}%`,
                              backgroundColor:
                                a.defense_score >= 80
                                  ? "var(--status-pass-fg)"
                                  : a.defense_score >= 50
                                  ? "var(--status-warn-fg)"
                                  : "var(--text-tertiary)",
                            }}
                          />
                        </div>
                        <span className="font-mono tabular-nums text-[var(--text-primary)]">
                          {a.defense_score > 0 ? `${a.defense_score}/100` : "--"}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3.5 font-mono text-[11px] tabular-nums text-[var(--text-secondary)]">
                      {a.token_amplification > 0
                        ? `${a.token_amplification.toFixed(1)}x tok / ${a.cost_amplification.toFixed(1)}x cost`
                        : "--"}
                    </td>
                    <td className="px-6 py-3.5 text-right">
                      <StatusBadge value={a.status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
