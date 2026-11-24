"use client";

import React from "react";
import {
  KeyRound,
  ShieldCheck,
  Lock,
  ArrowRight,
  Play,
  GitBranch,
  FolderOpen,
  Clock,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  GitPullRequest,
} from "lucide-react";
import type {
  AuditScope,
  GateExecution,
  LLMSettings,
  NavTab,
  Project,
  ReleaseRun,
  SecretScannerPref,
} from "@/lib/types";
import { ReadinessRing, StatusBadge } from "./StatusBadge";

interface OverviewViewProps {
  project: Project | null;
  latestRun: ReleaseRun | null;
  runs: ReleaseRun[];
  llmSettings: LLMSettings | null;
  openFindingsCount: number;
  artifactsCount: number;
  starting: boolean;
  onLaunchGate: (options: {
    secret_scanner: SecretScannerPref;
    bla_intensity: string;
    audit_profile: string;
    audit_scope: AuditScope;
    base_ref?: string;
    max_budget_usd: number;
    stop_on_gate1_fail: boolean;
  }) => void;
  onNavigate: (tab: NavTab) => void;
  onSelectRun: (run: ReleaseRun) => void;
  onOpenNewProject: () => void;
  onOpenCicdModal: () => void;
  onOpenSettings: () => void;
}

const DEFAULT_STAGES = [
  {
    gate_number: 1,
    name: "Secret Quarantine",
    subtitle: "External CLI plugin (TruffleHog or MIT Gitleaks)",
    engine: "trufflehog",
    icon: KeyRound,
    targetTab: "findings" as NavTab,
  },
  {
    gate_number: 2,
    name: "Adversarial Source Audit",
    subtitle: "Cloudflare 6-phase Hunter vs. Verifier separation",
    engine: "cloudflare-audit",
    icon: ShieldCheck,
    targetTab: "findings" as NavTab,
  },
  {
    gate_number: 3,
    name: "Anti-REA Shield",
    subtitle: "BLA audit, harden mirror, and post-BLA smoke check",
    engine: "bla",
    icon: Lock,
    targetTab: "shield" as NavTab,
  },
];

function GateIconIndicator({ status }: { status: string }) {
  if (status === "passed") return <CheckCircle2 className="h-4 w-4 text-[var(--status-pass-fg)]" strokeWidth={1.7} />;
  if (status === "warn") return <AlertTriangle className="h-4 w-4 text-[var(--status-warn-fg)]" strokeWidth={1.7} />;
  if (status === "failed") return <XCircle className="h-4 w-4 text-[var(--status-fail-fg)]" strokeWidth={1.7} />;
  return <Clock className="h-4 w-4 text-[var(--text-tertiary)]" strokeWidth={1.7} />;
}

export function OverviewView({
  project,
  latestRun,
  runs,
  llmSettings,
  openFindingsCount,
  artifactsCount,
  starting,
  onLaunchGate,
  onNavigate,
  onSelectRun,
  onOpenNewProject,
  onOpenCicdModal,
  onOpenSettings,
}: OverviewViewProps) {
  const [scanner, setScanner] = React.useState<SecretScannerPref>(
    project?.default_secret_scanner ?? "auto"
  );
  const [intensity, setIntensity] = React.useState<string>(project?.default_bla_intensity ?? "balanced");
  const [profile, setProfile] = React.useState<string>(project?.default_audit_profile ?? "standard");
  const [auditScope, setAuditScope] = React.useState<AuditScope>(
    llmSettings?.default_audit_scope ?? "diff"
  );
  const [baseRef, setBaseRef] = React.useState<string>("");
  const [maxBudget, setMaxBudget] = React.useState<string>(
    typeof llmSettings?.default_max_budget_usd === "number"
      ? llmSettings.default_max_budget_usd.toFixed(2)
      : "1.50"
  );

  React.useEffect(() => {
    if (project) {
      setScanner(project.default_secret_scanner || "auto");
      setIntensity(project.default_bla_intensity);
      setProfile(project.default_audit_profile);
    }
  }, [project]);

  React.useEffect(() => {
    if (llmSettings) {
      setAuditScope(llmSettings.default_audit_scope || "diff");
      setMaxBudget(
        typeof llmSettings.default_max_budget_usd === "number"
          ? llmSettings.default_max_budget_usd.toFixed(2)
          : "1.50"
      );
    }
  }, [llmSettings]);

  if (!project) {
    return (
      <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-12 text-center">
        <FolderOpen className="mx-auto h-8 w-8 text-[var(--text-tertiary)]" strokeWidth={1.4} />
        <h2 className="mt-4 text-base font-semibold text-[var(--text-primary)]">No Repository Registered</h2>
        <p className="mx-auto mt-1.5 max-w-md text-sm text-[var(--text-secondary)]">
          Register any local Git repository or build directory to run Bastion&apos;s 3-stage pre-ship security and anti-reverse-engineering release gate.
        </p>
        <button
          type="button"
          onClick={onOpenNewProject}
          className="mt-6 rounded-lg bg-[var(--accent-neutral)] px-4 py-2 text-xs font-medium text-[var(--accent-neutral-fg)] hover:opacity-90 transition-opacity"
        >
          Register Repository
        </button>
      </div>
    );
  }

  const gateMap = new Map<number, GateExecution>();
  (latestRun?.gates ?? []).forEach((g) => gateMap.set(g.gate_number, g));

  const readinessScore = latestRun ? latestRun.readiness_score : project.latest_readiness_score;
  const decisionLabel =
    latestRun?.status === "passed"
      ? "Ready for Release"
      : latestRun?.status === "failed"
      ? "Release Blocked"
      : latestRun?.status === "running"
      ? "Evaluation in Progress"
      : "Awaiting Gate Run";

  const gate2Exec = gateMap.get(2);
  const gate3Exec = gateMap.get(3);
  const gate2BadgeText =
    (gate2Exec?.metadata?.engine_badge as string | undefined) ||
    llmSettings?.active_badge ||
    "Static Heuristic Fallback (No LLM)";
  const gate2IsLlm =
    gate2Exec ? gate2Exec.mode === "live_llm" : llmSettings?.active_mode === "live_llm";
  const gate3Smoke = (gate3Exec?.metadata?.smoke_test as { status?: string } | undefined)?.status;

  function parsedBudgetUsd(): number {
    const n = Number.parseFloat(maxBudget);
    if (!Number.isFinite(n) || n < 0.05) return 1.5;
    return Math.min(100, Number(n.toFixed(2)));
  }

  return (
    <div className="space-y-6">
      {/* Hero Summary Row */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Release Readiness Card */}
        <div className="lg:col-span-5 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-6 flex items-center gap-6">
          <ReadinessRing score={readinessScore} size={124} />
          <div className="min-w-0 flex-1 space-y-2">
            <div className="text-[11px] font-medium uppercase tracking-[0.06em] text-[var(--text-tertiary)]">
              Release Readiness Score
            </div>
            <div className="text-xl font-semibold tracking-tight text-[var(--text-primary)]">
              {decisionLabel}
            </div>
            <div className="flex flex-wrap items-center gap-2 pt-0.5">
              {latestRun ? (
                <StatusBadge value={latestRun.status} />
              ) : (
                <StatusBadge value="pending" label="Not Run" />
              )}
              {project.bla_applied && <StatusBadge value="applied" label="BLA Promoted" />}
              {project.latest_smoke_status && project.latest_smoke_status !== "skipped" && (
                <StatusBadge
                  value={project.latest_smoke_status}
                  label={`Smoke: ${project.latest_smoke_status}`}
                />
              )}
            </div>
            <p className="text-xs text-[var(--text-secondary)] leading-relaxed pt-1">
              {latestRun
                ? `Run #${latestRun.run_number} · ${openFindingsCount} open finding(s) · ${artifactsCount} build artifact(s)`
                : "Execute all three gates to issue an Ed25519-signed release certificate."}
            </p>
          </div>
        </div>

        {/* Target Repository & Quick Launch Card */}
        <div className="lg:col-span-7 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-6 flex flex-col justify-between gap-5">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="text-lg font-semibold tracking-tight text-[var(--text-primary)] truncate">
                  {project.name}
                </h1>
                {project.is_git_repo && (
                  <span className="inline-flex items-center gap-1 rounded-md border border-[var(--border-subtle)] bg-[var(--bg-subtle)] px-2 py-0.5 text-[11px] font-mono text-[var(--text-secondary)]">
                    <GitBranch className="h-3 w-3" />
                    {latestRun?.git_branch ?? "git"}
                    {latestRun?.git_commit ? ` @ ${latestRun.git_commit}` : ""}
                  </span>
                )}
              </div>
              <p className="mt-1 text-xs font-mono text-[var(--text-tertiary)] truncate" title={project.path}>
                {project.path}
              </p>
              {project.description && (
                <p className="mt-2 text-xs text-[var(--text-secondary)]">{project.description}</p>
              )}
            </div>

            <button
              type="button"
              onClick={onOpenCicdModal}
              className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-3 py-1.5 text-xs font-medium text-[var(--text-primary)] hover:bg-[var(--bg-hover)] transition-colors"
            >
              <GitPullRequest className="h-3.5 w-3.5 text-[var(--text-secondary)]" strokeWidth={1.6} />
              CI/CD Setup
            </button>
          </div>

          <div className="flex flex-wrap items-end justify-between gap-3 border-t border-[var(--border-subtle)] pt-4">
            <div className="flex flex-wrap items-end gap-2.5">
              <div>
                <label className="block text-[11px] font-medium text-[var(--text-tertiary)] mb-1">
                  Gate 1 Scanner
                </label>
                <select
                  value={scanner}
                  onChange={(e) => setScanner(e.target.value as SecretScannerPref)}
                  className="rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-2.5 py-1.5 text-xs text-[var(--text-primary)] focus:outline-none"
                >
                  <option value="auto">Auto</option>
                  <option value="trufflehog">TruffleHog</option>
                  <option value="gitleaks">Gitleaks (MIT)</option>
                </select>
              </div>
              <div>
                <label className="block text-[11px] font-medium text-[var(--text-tertiary)] mb-1">
                  Gate 2 Scope
                </label>
                <select
                  value={auditScope}
                  onChange={(e) => setAuditScope(e.target.value as AuditScope)}
                  className="rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-2.5 py-1.5 text-xs text-[var(--text-primary)] focus:outline-none"
                >
                  <option value="diff">Diff (PR / Local)</option>
                  <option value="full">Full Repo</option>
                </select>
              </div>
              {auditScope === "diff" && (
                <div>
                  <label className="block text-[11px] font-medium text-[var(--text-tertiary)] mb-1">
                    Base Ref
                  </label>
                  <input
                    type="text"
                    value={baseRef}
                    onChange={(e) => setBaseRef(e.target.value)}
                    placeholder="auto"
                    className="w-24 rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-2 py-1.5 text-xs font-mono text-[var(--text-primary)] placeholder:text-[var(--text-tertiary)] focus:outline-none"
                  />
                </div>
              )}
              <div>
                <label className="block text-[11px] font-medium text-[var(--text-tertiary)] mb-1">
                  Budget ($)
                </label>
                <input
                  type="number"
                  min={0.05}
                  max={100}
                  step={0.1}
                  value={maxBudget}
                  onChange={(e) => setMaxBudget(e.target.value)}
                  className="w-20 rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-2 py-1.5 text-xs font-mono tabular-nums text-[var(--text-primary)] focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-[11px] font-medium text-[var(--text-tertiary)] mb-1">
                  Profile
                </label>
                <select
                  value={profile}
                  onChange={(e) => setProfile(e.target.value)}
                  className="rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-2.5 py-1.5 text-xs text-[var(--text-primary)] focus:outline-none"
                >
                  <option value="quick">Quick</option>
                  <option value="standard">Standard</option>
                  <option value="deep">Deep</option>
                </select>
              </div>
              <div>
                <label className="block text-[11px] font-medium text-[var(--text-tertiary)] mb-1">
                  BLA Intensity
                </label>
                <select
                  value={intensity}
                  onChange={(e) => setIntensity(e.target.value)}
                  className="rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-2.5 py-1.5 text-xs text-[var(--text-primary)] focus:outline-none"
                >
                  <option value="stealth">Stealth</option>
                  <option value="balanced">Balanced</option>
                  <option value="maximum">Maximum</option>
                  <option value="bankrupt">Bankrupt</option>
                </select>
              </div>
            </div>

            <button
              type="button"
              disabled={starting || latestRun?.status === "running"}
              onClick={() =>
                onLaunchGate({
                  secret_scanner: scanner,
                  bla_intensity: intensity,
                  audit_profile: profile,
                  audit_scope: auditScope,
                  base_ref: auditScope === "diff" ? baseRef.trim() || undefined : undefined,
                  max_budget_usd: parsedBudgetUsd(),
                  stop_on_gate1_fail: true,
                })
              }
              className="inline-flex items-center gap-2 rounded-lg bg-[var(--accent-neutral)] px-4 py-2 text-xs font-medium text-[var(--accent-neutral-fg)] hover:opacity-90 disabled:opacity-50 transition-opacity"
            >
              <Play className="h-3.5 w-3.5 fill-current" />
              {starting || latestRun?.status === "running" ? "Pipeline Running..." : "Run 3-Stage Release Gate"}
            </button>
          </div>
        </div>
      </div>

      {/* 3-Stage Sequential Pipeline Visualizer */}
      <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-6">
        <div className="flex flex-wrap items-center justify-between gap-2 mb-5">
          <div>
            <h2 className="text-sm font-semibold tracking-tight text-[var(--text-primary)]">
              Three-Stage Pre-Ship Pipeline
            </h2>
            <p className="text-xs text-[var(--text-secondary)] mt-0.5">
              Sequential release gate: Secret Quarantine, Adversarial Audit, and Anti-REA Shield
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={onOpenSettings}
              className="text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
            >
              Configure Vault &amp; LLM
            </button>
            <button
              type="button"
              onClick={() => onNavigate("runner")}
              className="text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
            >
              Open Live Runner &rarr;
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          {DEFAULT_STAGES.map((stage, idx) => {
            const exec = gateMap.get(stage.gate_number);
            const Icon = stage.icon;
            const status = exec?.status ?? "pending";
            return (
              <div key={stage.gate_number} className="relative flex items-stretch">
                <button
                  type="button"
                  onClick={() => onNavigate(stage.targetTab)}
                  className="group w-full text-left rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-canvas)] p-5 hover:border-[var(--border-strong)] transition-colors flex flex-col justify-between gap-4"
                >
                  <div>
                    <div className="flex items-center justify-between gap-2">
                      <span className="inline-flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-[0.06em] text-[var(--text-tertiary)]">
                        <Icon className="h-3.5 w-3.5" strokeWidth={1.6} />
                        Gate {stage.gate_number}
                      </span>
                      <StatusBadge value={status} />
                    </div>
                    <h3 className="mt-2.5 text-[15px] font-semibold text-[var(--text-primary)]">
                      {stage.name}
                    </h3>
                    {stage.gate_number === 2 && (
                      <div className="mt-2 flex flex-wrap items-center gap-1.5">
                        <StatusBadge
                          value={gate2IsLlm ? "live_llm" : "static_heuristic"}
                          label={gate2BadgeText}
                        />
                        {latestRun?.audit_scope && (
                          <span className="rounded-md border border-[var(--border-subtle)] bg-[var(--bg-subtle)] px-1.5 py-0.5 text-[10px] font-mono text-[var(--text-secondary)]">
                            scope:{latestRun.audit_scope}
                          </span>
                        )}
                      </div>
                    )}
                    {stage.gate_number === 3 && gate3Smoke && gate3Smoke !== "skipped" && (
                      <div className="mt-2">
                        <StatusBadge value={gate3Smoke} label={`Smoke: ${gate3Smoke}`} />
                      </div>
                    )}
                    <p className="mt-2 text-xs text-[var(--text-secondary)] leading-relaxed">
                      {exec?.summary || stage.subtitle}
                    </p>
                  </div>

                  <div className="flex items-center justify-between border-t border-[var(--border-subtle)] pt-3 text-[11px] text-[var(--text-tertiary)] tabular-nums">
                    <span className="inline-flex items-center gap-1.5">
                      <GateIconIndicator status={status} />
                      <span>
                        {exec ? `${exec.engine} · ${exec.duration_ms} ms` : "Awaiting execution"}
                      </span>
                    </span>
                    <span className="font-medium text-[var(--text-secondary)] group-hover:text-[var(--text-primary)]">
                      {stage.gate_number === 3
                        ? `${exec?.findings_count ?? artifactsCount} artifacts`
                        : `${exec?.findings_count ?? 0} findings`}
                    </span>
                  </div>
                </button>
                {idx < 2 && (
                  <div className="hidden md:flex items-center justify-center -mr-4 pl-0.5 z-10 pointer-events-none">
                    <ArrowRight className="h-3.5 w-3.5 text-[var(--text-tertiary)]" />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Recent Runs Table */}
      <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] overflow-hidden">
        <div className="flex items-center justify-between border-b border-[var(--border-subtle)] px-6 py-4">
          <h2 className="text-sm font-semibold tracking-tight text-[var(--text-primary)]">
            Recent Gate Runs
          </h2>
          <button
            type="button"
            onClick={() => onNavigate("reports")}
            className="text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
          >
            View Compliance Reports &rarr;
          </button>
        </div>

        {runs.length === 0 ? (
          <div className="px-6 py-10 text-center text-xs text-[var(--text-tertiary)]">
            No release gate runs recorded for this project yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-[var(--border-subtle)] text-[11px] font-medium uppercase tracking-[0.05em] text-[var(--text-tertiary)]">
                  <th className="px-6 py-3">Run</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Score</th>
                  <th className="px-4 py-3">Gates</th>
                  <th className="px-4 py-3">Scope / Profile / BLA</th>
                  <th className="px-6 py-3 text-right">Started</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-subtle)]">
                {runs.slice(0, 6).map((r) => (
                  <tr
                    key={r.id}
                    onClick={() => {
                      onSelectRun(r);
                      onNavigate("runner");
                    }}
                    className="cursor-pointer hover:bg-[var(--bg-hover)] transition-colors"
                  >
                    <td className="px-6 py-3.5 font-mono font-medium text-[var(--text-primary)]">
                      #{r.run_number}
                      <span className="ml-2 text-[var(--text-tertiary)]">{r.git_commit ?? "local"}</span>
                    </td>
                    <td className="px-4 py-3.5">
                      <StatusBadge value={r.status} />
                    </td>
                    <td className="px-4 py-3.5 font-mono tabular-nums text-[var(--text-primary)]">
                      {r.readiness_score}/100
                    </td>
                    <td className="px-4 py-3.5">
                      <div className="flex items-center gap-1.5">
                        {r.gates.map((g) => (
                          <span
                            key={g.id}
                            title={`Gate ${g.gate_number}: ${g.status}`}
                            className="inline-flex items-center gap-1 rounded border border-[var(--border-subtle)] bg-[var(--bg-canvas)] px-1.5 py-0.5 text-[10px] font-mono text-[var(--text-secondary)]"
                          >
                            G{g.gate_number}:{g.status.slice(0, 4)}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3.5 text-[var(--text-secondary)] capitalize">
                      {r.audit_scope || "full"} / {r.audit_profile} / {r.bla_intensity}
                    </td>
                    <td className="px-6 py-3.5 text-right tabular-nums text-[var(--text-tertiary)]">
                      {new Date(r.created_at).toLocaleString()}
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
