"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  Shield,
  LayoutDashboard,
  TerminalSquare,
  AlertOctagon,
  Lock,
  FileCheck2,
  Plus,
  Sun,
  Moon,
  Wrench,
  SlidersHorizontal,
} from "lucide-react";
import { api } from "@/lib/api";
import type {
  ArtifactRecord,
  AuditEvent,
  AuditScope,
  CoverageLedgerEntry,
  Finding,
  GateExecution,
  LLMSettings,
  NavTab,
  Project,
  ReleaseRun,
  SecretScannerPref,
  SystemToolsResponse,
} from "@/lib/types";
import { OverviewView } from "./OverviewView";
import { PipelineRunnerView } from "./PipelineRunnerView";
import { FindingsView } from "./FindingsView";
import { ArtifactShieldView } from "./ArtifactShieldView";
import { ComplianceReportsView } from "./ComplianceReportsView";
import { ProjectModal } from "./ProjectModal";
import { EnvironmentDrawer } from "./EnvironmentDrawer";
import { SettingsDrawer } from "./SettingsDrawer";
import { CicdModal } from "./CicdModal";

const NAV_ITEMS: Array<{
  id: NavTab;
  label: string;
  icon: React.ComponentType<{ className?: string; strokeWidth?: number }>;
}> = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "runner", label: "Pipeline Runner", icon: TerminalSquare },
  { id: "findings", label: "Findings & Triage", icon: AlertOctagon },
  { id: "shield", label: "Artifact Shield", icon: Lock },
  { id: "reports", label: "Compliance Reports", icon: FileCheck2 },
];

export function BastionApp() {
  const [darkMode, setDarkMode] = useState(false);
  const [activeTab, setActiveTab] = useState<NavTab>("overview");
  const [tools, setTools] = useState<SystemToolsResponse | null>(null);
  const [llmSettings, setLlmSettings] = useState<LLMSettings | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string | null>(null);
  const [runs, setRuns] = useState<ReleaseRun[]>([]);
  const [activeRun, setActiveRun] = useState<ReleaseRun | null>(null);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [artifacts, setArtifacts] = useState<ArtifactRecord[]>([]);
  const [ledger, setLedger] = useState<CoverageLedgerEntry[]>([]);
  const [streamConnected, setStreamConnected] = useState(false);
  const [startingRun, setStartingRun] = useState(false);
  const [projectModalOpen, setProjectModalOpen] = useState(false);
  const [envDrawerOpen, setEnvDrawerOpen] = useState(false);
  const [settingsDrawerOpen, setSettingsDrawerOpen] = useState(false);
  const [cicdModalOpen, setCicdModalOpen] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);

  const eventSourceRef = useRef<EventSource | null>(null);

  useEffect(() => {
    const saved = typeof window !== "undefined" ? localStorage.getItem("bastion-theme") : null;
    const prefersDark =
      typeof window !== "undefined" &&
      window.matchMedia &&
      window.matchMedia("(prefers-color-scheme: dark)").matches;
    const initialDark = saved ? saved === "dark" : prefersDark;
    setDarkMode(initialDark);
    document.documentElement.classList.toggle("dark", initialDark);
  }, []);

  function toggleTheme() {
    setDarkMode((prev) => {
      const next = !prev;
      document.documentElement.classList.toggle("dark", next);
      try {
        localStorage.setItem("bastion-theme", next ? "dark" : "light");
      } catch {
        // ignore
      }
      return next;
    });
  }

  const refreshTools = useCallback(async () => {
    try {
      const data = await api.getTools();
      setTools(data);
    } catch {
      // handled via apiError on main load
    }
  }, []);

  const loadProjectData = useCallback(async (projectId: string) => {
    try {
      const [projectRuns, projectFindings, projectArtifacts, projectLedger] = await Promise.all([
        api.listRuns(projectId),
        api.listFindings({ project_id: projectId }),
        api.getProjectArtifacts(projectId),
        api.getProjectLedger(projectId),
      ]);
      setRuns(projectRuns);
      setFindings(projectFindings);
      setArtifacts(projectArtifacts);
      setLedger(projectLedger);
      setActiveRun((prev) => {
        if (prev && prev.project_id === projectId) {
          return projectRuns.find((r) => r.id === prev.id) ?? projectRuns[0] ?? null;
        }
        return projectRuns[0] ?? null;
      });
    } catch (err) {
      setApiError(err instanceof Error ? err.message : "Failed to load project state");
    }
  }, []);

  const refreshAll = useCallback(async () => {
    setApiError(null);
    try {
      const [toolsData, llmData, projList] = await Promise.all([
        api.getTools(),
        api.getLLMSettings(),
        api.listProjects(),
      ]);
      setTools(toolsData);
      setLlmSettings(llmData);
      setProjects(projList);
      const nextProjId =
        selectedProjectId && projList.some((p) => p.id === selectedProjectId)
          ? selectedProjectId
          : projList[0]?.id ?? null;
      setSelectedProjectId(nextProjId);
      if (nextProjId) {
        await loadProjectData(nextProjId);
      }
    } catch (err) {
      setApiError(
        err instanceof Error
          ? `Backend unreachable (${err.message}). Start FastAPI on port 8000.`
          : "Backend unreachable."
      );
    }
  }, [selectedProjectId, loadProjectData]);

  useEffect(() => {
    refreshAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (selectedProjectId) {
      loadProjectData(selectedProjectId);
    }
  }, [selectedProjectId, loadProjectData]);

  const activeRunId = activeRun?.id ?? null;
  const activeRunStatus = activeRun?.status ?? null;

  useEffect(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
      setStreamConnected(false);
    }
    if (!activeRunId || !activeRunStatus) {
      setEvents([]);
      return;
    }

    const runId = activeRunId;
    let cancelled = false;

    if (["passed", "failed", "aborted"].includes(activeRunStatus)) {
      api
        .getRunEvents(runId)
        .then((evs) => {
          if (!cancelled) setEvents(evs);
        })
        .catch(() => undefined);
      return () => {
        cancelled = true;
      };
    }

    setEvents([]);
    const es = new EventSource(api.runStreamUrl(runId));
    eventSourceRef.current = es;

    es.onopen = () => {
      if (!cancelled) setStreamConnected(true);
    };

    es.addEventListener("log", (ev) => {
      try {
        const parsed = JSON.parse((ev as MessageEvent).data) as AuditEvent;
        setEvents((prev) => {
          if (parsed.id && prev.some((item) => item.id === parsed.id)) return prev;
          return [...prev, parsed];
        });
      } catch {
        // ignore malformed frame
      }
    });

    es.addEventListener("gate_update", (ev) => {
      try {
        const gate = JSON.parse((ev as MessageEvent).data) as GateExecution;
        setActiveRun((prev) => {
          if (!prev || prev.id !== runId) return prev;
          const gates = prev.gates.map((g) =>
            g.gate_number === gate.gate_number ? { ...g, ...gate } : g
          );
          return { ...prev, gates };
        });
      } catch {
        // ignore
      }
    });

    es.addEventListener("run_update", (ev) => {
      try {
        const patch = JSON.parse((ev as MessageEvent).data) as Partial<ReleaseRun>;
        setActiveRun((prev) => (prev && prev.id === runId ? { ...prev, ...patch } : prev));
      } catch {
        // ignore
      }
    });

    es.addEventListener("complete", () => {
      es.close();
      setStreamConnected(false);
      if (selectedProjectId) {
        loadProjectData(selectedProjectId);
        api.listProjects().then(setProjects).catch(() => undefined);
      }
    });

    es.onerror = () => {
      setStreamConnected(false);
    };

    return () => {
      cancelled = true;
      es.close();
      eventSourceRef.current = null;
      setStreamConnected(false);
    };
  }, [activeRunId, activeRunStatus, selectedProjectId, loadProjectData]);

  const currentProject = projects.find((p) => p.id === selectedProjectId) ?? null;

  async function handleLaunchGate(options?: {
    secret_scanner?: SecretScannerPref;
    bla_intensity?: string;
    audit_profile?: string;
    audit_scope?: AuditScope;
    base_ref?: string;
    max_budget_usd?: number;
    stop_on_gate1_fail?: boolean;
  }) {
    if (!currentProject) return;
    setStartingRun(true);
    setApiError(null);
    try {
      const created = await api.startRun({
        project_id: currentProject.id,
        secret_scanner: options?.secret_scanner ?? currentProject.default_secret_scanner,
        bla_intensity: options?.bla_intensity ?? currentProject.default_bla_intensity,
        audit_profile: options?.audit_profile ?? currentProject.default_audit_profile,
        audit_scope: options?.audit_scope ?? llmSettings?.default_audit_scope ?? "diff",
        base_ref: options?.base_ref,
        max_budget_usd: options?.max_budget_usd ?? llmSettings?.default_max_budget_usd ?? 1.5,
        smoke_test_cmd: currentProject.smoke_test_cmd || undefined,
        stop_on_gate1_fail: options?.stop_on_gate1_fail ?? true,
      });
      setRuns((prev) => [created, ...prev]);
      setActiveRun(created);
      setActiveTab("runner");
    } catch (err) {
      setApiError(err instanceof Error ? err.message : "Failed to start release gate");
    } finally {
      setStartingRun(false);
    }
  }

  async function handleAbortRun(runId: string) {
    try {
      await api.abortRun(runId);
    } catch (err) {
      setApiError(err instanceof Error ? err.message : "Abort failed");
    }
  }

  async function handleRetryRun(runId: string) {
    try {
      const retried = await api.retryRun(runId);
      setRuns((prev) => [retried, ...prev]);
      setActiveRun(retried);
      setActiveTab("runner");
    } catch (err) {
      setApiError(err instanceof Error ? err.message : "Retry failed");
    }
  }

  const openFindingsCount = findings.filter((f) => !f.resolved).length;

  return (
    <div className="min-h-screen flex flex-col bg-[var(--bg-canvas)] text-[var(--text-primary)]">
      {/* Minimalist Top Bar */}
      <header className="sticky top-0 z-30 border-b border-[var(--border-subtle)] bg-[var(--bg-surface)]/90 backdrop-blur-md">
        <div className="mx-auto flex h-14 max-w-6xl items-center justify-between gap-4 px-4 sm:px-6">
          <div className="flex items-center gap-4 min-w-0">
            <button
              type="button"
              onClick={() => setActiveTab("overview")}
              className="flex items-center gap-2 shrink-0"
            >
              <span className="flex h-7 w-7 items-center justify-center rounded-lg border border-[var(--border-strong)] bg-[var(--bg-subtle)]">
                <Shield className="h-4 w-4 text-[var(--text-primary)]" strokeWidth={1.7} />
              </span>
              <span className="text-[14px] font-semibold tracking-tight text-[var(--text-primary)]">
                Bastion
              </span>
              <span className="rounded border border-[var(--border-subtle)] bg-[var(--bg-subtle)] px-1.5 py-0.5 text-[10px] font-mono text-[var(--text-tertiary)]">
                v2.1
              </span>
            </button>

            <span className="text-[var(--border-strong)] select-none">/</span>

            <div className="flex items-center gap-1.5 min-w-0">
              <select
                aria-label="Select target repository"
                value={selectedProjectId ?? ""}
                onChange={(e) => setSelectedProjectId(e.target.value || null)}
                className="max-w-[230px] truncate rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-canvas)] px-2.5 py-1.5 text-xs font-medium text-[var(--text-primary)] hover:border-[var(--border-strong)] focus:outline-none"
              >
                {projects.length === 0 && <option value="">No projects</option>}
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>

              <button
                type="button"
                onClick={() => setProjectModalOpen(true)}
                title="Register local repository"
                className="inline-flex items-center justify-center rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-canvas)] p-1.5 text-[var(--text-secondary)] hover:border-[var(--border-strong)] hover:text-[var(--text-primary)] transition-colors"
              >
                <Plus className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => setSettingsDrawerOpen(true)}
              className="inline-flex items-center gap-2 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-canvas)] px-2.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] hover:border-[var(--border-strong)] hover:text-[var(--text-primary)] transition-colors"
            >
              <span
                className="h-1.5 w-1.5 rounded-full"
                style={{
                  backgroundColor:
                    llmSettings?.active_mode === "live_llm"
                      ? "var(--status-pass-fg)"
                      : "var(--status-warn-fg)",
                }}
              />
              <SlidersHorizontal className="h-3.5 w-3.5" strokeWidth={1.6} />
              <span className="hidden md:inline">
                {llmSettings?.active_mode === "live_llm"
                  ? `LLM: ${llmSettings.provider}`
                  : "Settings (No LLM)"}
              </span>
            </button>

            <button
              type="button"
              onClick={() => setEnvDrawerOpen(true)}
              className="inline-flex items-center gap-2 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-canvas)] px-2.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] hover:border-[var(--border-strong)] hover:text-[var(--text-primary)] transition-colors"
            >
              <span
                className="h-1.5 w-1.5 rounded-full"
                style={{
                  backgroundColor: tools?.all_live
                    ? "var(--status-pass-fg)"
                    : "var(--status-warn-fg)",
                }}
              />
              <Wrench className="h-3.5 w-3.5" strokeWidth={1.6} />
              <span className="hidden sm:inline">
                {tools ? (tools.all_live ? "Engines Live" : "Toolchain") : "Toolchain"}
              </span>
            </button>

            <button
              type="button"
              onClick={toggleTheme}
              aria-label="Toggle color mode"
              className="inline-flex items-center justify-center rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-canvas)] p-1.5 text-[var(--text-secondary)] hover:border-[var(--border-strong)] hover:text-[var(--text-primary)] transition-colors"
            >
              {darkMode ? <Sun className="h-3.5 w-3.5" /> : <Moon className="h-3.5 w-3.5" />}
            </button>
          </div>
        </div>

        {/* Clean Horizontal Navigation Bar */}
        <div className="mx-auto max-w-6xl px-4 sm:px-6 overflow-x-auto">
          <nav className="flex items-center gap-1 -mb-px" aria-label="Primary navigation">
            {NAV_ITEMS.map((item) => {
              const Icon = item.icon;
              const active = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setActiveTab(item.id)}
                  className={`inline-flex items-center gap-2 border-b-2 px-3 py-2.5 text-xs font-medium whitespace-nowrap transition-colors ${
                    active
                      ? "border-[var(--text-primary)] text-[var(--text-primary)]"
                      : "border-transparent text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                  }`}
                >
                  <Icon className="h-3.5 w-3.5" strokeWidth={1.6} />
                  {item.label}
                  {item.id === "findings" && openFindingsCount > 0 && (
                    <span className="rounded-full bg-[var(--bg-subtle)] border border-[var(--border-subtle)] px-1.5 py-0.2 text-[10px] tabular-nums text-[var(--text-secondary)]">
                      {openFindingsCount}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>
      </header>

      {/* Main Content Container */}
      <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-8 sm:px-6">
        {apiError && (
          <div className="mb-6 flex items-center justify-between rounded-xl border border-[var(--status-fail-border)] bg-[var(--status-fail-bg)] px-4 py-3 text-xs text-[var(--status-fail-fg)]">
            <span>{apiError}</span>
            <button
              type="button"
              onClick={refreshAll}
              className="rounded-md border border-[var(--status-fail-border)] px-2.5 py-1 font-medium hover:opacity-80"
            >
              Retry
            </button>
          </div>
        )}

        {activeTab === "overview" && (
          <OverviewView
            project={currentProject}
            latestRun={runs[0] ?? null}
            runs={runs}
            llmSettings={llmSettings}
            openFindingsCount={openFindingsCount}
            artifactsCount={artifacts.length}
            starting={startingRun}
            onLaunchGate={handleLaunchGate}
            onNavigate={setActiveTab}
            onSelectRun={(r) => setActiveRun(r)}
            onOpenNewProject={() => setProjectModalOpen(true)}
            onOpenCicdModal={() => setCicdModalOpen(true)}
            onOpenSettings={() => setSettingsDrawerOpen(true)}
          />
        )}

        {activeTab === "runner" && (
          <PipelineRunnerView
            project={currentProject}
            run={activeRun}
            events={events}
            streamConnected={streamConnected}
            onStartNewRun={() => handleLaunchGate()}
            onAbortRun={handleAbortRun}
            onRetryRun={handleRetryRun}
          />
        )}

        {activeTab === "findings" && (
          <FindingsView
            project={currentProject}
            findings={findings}
            onFindingUpdated={(updated) =>
              setFindings((prev) => prev.map((f) => (f.id === updated.id ? updated : f)))
            }
          />
        )}

        {activeTab === "shield" && (
          <ArtifactShieldView
            project={currentProject}
            latestRun={runs[0] ?? null}
            artifacts={artifacts}
            onRefresh={async () => {
              await refreshAll();
            }}
            onProjectUpdated={(updated) => {
              setProjects((prev) => prev.map((p) => (p.id === updated.id ? updated : p)));
            }}
            onRunWithIntensity={(intensity) =>
              handleLaunchGate({ bla_intensity: intensity, stop_on_gate1_fail: true })
            }
          />
        )}

        {activeTab === "reports" && (
          <ComplianceReportsView project={currentProject} runs={runs} ledger={ledger} />
        )}
      </main>

      {/* Modals & Drawers */}
      <ProjectModal
        open={projectModalOpen}
        onClose={() => setProjectModalOpen(false)}
        onCreated={(created) => {
          setProjects((prev) => [created, ...prev]);
          setSelectedProjectId(created.id);
        }}
      />

      <EnvironmentDrawer
        open={envDrawerOpen}
        tools={tools}
        onClose={() => setEnvDrawerOpen(false)}
        onRefresh={refreshTools}
      />

      <SettingsDrawer
        open={settingsDrawerOpen}
        settings={llmSettings}
        onClose={() => setSettingsDrawerOpen(false)}
        onUpdated={(next) => setLlmSettings(next)}
      />

      <CicdModal
        open={cicdModalOpen}
        project={currentProject}
        onClose={() => setCicdModalOpen(false)}
      />
    </div>
  );
}
