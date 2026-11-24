"use client";

import React, { useEffect, useRef, useState } from "react";
import { Play, Square, RotateCcw, Copy, Check, Terminal } from "lucide-react";
import type { AuditEvent, Project, ReleaseRun } from "@/lib/types";
import { StatusBadge } from "./StatusBadge";

interface PipelineRunnerViewProps {
  project: Project | null;
  run: ReleaseRun | null;
  events: AuditEvent[];
  streamConnected: boolean;
  onStartNewRun: () => void;
  onAbortRun: (runId: string) => void;
  onRetryRun: (runId: string) => void;
}

const LEVEL_COLORS: Record<AuditEvent["level"], string> = {
  info: "text-[var(--text-secondary)]",
  success: "text-[var(--status-pass-fg)]",
  warn: "text-[var(--status-warn-fg)]",
  error: "text-[var(--status-fail-fg)]",
};

export function PipelineRunnerView({
  project,
  run,
  events,
  streamConnected,
  onStartNewRun,
  onAbortRun,
  onRetryRun,
}: PipelineRunnerViewProps) {
  const [gateFilter, setGateFilter] = useState<number | "all">("all");
  const [autoScroll, setAutoScroll] = useState(true);
  const [copied, setCopied] = useState(false);
  const terminalRef = useRef<HTMLDivElement | null>(null);

  const filteredEvents = events.filter((ev) =>
    gateFilter === "all" ? true : ev.gate_number === gateFilter
  );

  useEffect(() => {
    if (autoScroll && terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [filteredEvents.length, autoScroll]);

  function copyLogs() {
    const text = filteredEvents
      .map(
        (e) =>
          `[${new Date(e.timestamp).toLocaleTimeString()}] [G${e.gate_number}] [${e.level.toUpperCase()}] ${e.message}`
      )
      .join("\n");
    navigator.clipboard.writeText(text).catch(() => undefined);
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  }

  const isRunning = run?.status === "running" || run?.status === "queued";

  return (
    <div className="space-y-6">
      {/* Header & Controls */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] px-6 py-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-base font-semibold tracking-tight text-[var(--text-primary)]">
              Live Pipeline Runner
            </h1>
            {run && <StatusBadge value={run.status} />}
            {streamConnected && (
              <span className="inline-flex items-center gap-1.5 text-[11px] text-[var(--status-run-fg)]">
                <span className="h-1.5 w-1.5 rounded-full bg-[var(--status-run-fg)] animate-pulse" />
                SSE Connected
              </span>
            )}
          </div>
          <p className="mt-0.5 text-xs text-[var(--text-secondary)]">
            {run
              ? `Run #${run.run_number} for ${run.project_name || project?.name} · Readiness ${run.readiness_score}/100`
              : "Trigger a sequential 3-stage run to stream real-time logs from Gate 1, Cloudflare Audit, and BLA."}
          </p>
        </div>

        <div className="flex items-center gap-2">
          {isRunning && run ? (
            <button
              type="button"
              onClick={() => onAbortRun(run.id)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--status-fail-border)] bg-[var(--status-fail-bg)] px-3.5 py-2 text-xs font-medium text-[var(--status-fail-fg)] hover:opacity-90 transition-opacity"
            >
              <Square className="h-3.5 w-3.5 fill-current" />
              Abort Run
            </button>
          ) : (
            <>
              {run && (
                <button
                  type="button"
                  onClick={() => onRetryRun(run.id)}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-3.5 py-2 text-xs font-medium text-[var(--text-primary)] hover:bg-[var(--bg-hover)] transition-colors"
                >
                  <RotateCcw className="h-3.5 w-3.5" />
                  Retry Run
                </button>
              )}
              <button
                type="button"
                disabled={!project}
                onClick={onStartNewRun}
                className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--accent-neutral)] px-4 py-2 text-xs font-medium text-[var(--accent-neutral-fg)] hover:opacity-90 disabled:opacity-50 transition-opacity"
              >
                <Play className="h-3.5 w-3.5 fill-current" />
                Start New Run
              </button>
            </>
          )}
        </div>
      </div>

      {/* Stage Progress Cards */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        {[1, 2, 3].map((num) => {
          const gate = run?.gates.find((g) => g.gate_number === num);
          const labels = [
            `Secret Quarantine (${gate?.engine ?? "TruffleHog / Gitleaks"})`,
            "Adversarial Audit (Cloudflare)",
            "Anti-REA Shield (BLA)",
          ];
          const status = gate?.status ?? "pending";
          const progressWidth =
            status === "passed" || status === "warn" || status === "failed"
              ? "100%"
              : status === "running"
              ? "62%"
              : "0%";
          const barColor =
            status === "passed"
              ? "var(--status-pass-fg)"
              : status === "warn"
              ? "var(--status-warn-fg)"
              : status === "failed"
              ? "var(--status-fail-fg)"
              : "var(--status-run-fg)";

          const g2Badge =
            num === 2 && gate
              ? (gate.metadata?.engine_badge as string | undefined) ||
                (gate.mode === "live_llm"
                  ? "Multi-Agent LLM"
                  : "Static Heuristic Fallback (No LLM)")
              : null;

          return (
            <div
              key={num}
              className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5 space-y-3"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-[11px] font-medium uppercase tracking-[0.06em] text-[var(--text-tertiary)]">
                  Stage {num}
                </span>
                <div className="flex items-center gap-1.5">
                  {gate && num !== 2 && (
                    <span className="rounded border border-[var(--border-subtle)] bg-[var(--bg-subtle)] px-1.5 py-0.5 text-[10px] font-mono text-[var(--text-secondary)]">
                      {gate.mode}
                    </span>
                  )}
                  <StatusBadge value={status} />
                </div>
              </div>

              <div className="text-sm font-semibold text-[var(--text-primary)]">{labels[num - 1]}</div>

              {g2Badge && (
                <div>
                  <StatusBadge
                    value={gate?.mode === "live_llm" ? "live_llm" : "static_heuristic"}
                    label={g2Badge}
                  />
                </div>
              )}

              <div className="h-1 w-full overflow-hidden rounded-full bg-[var(--bg-subtle)]">
                <div
                  className="h-full rounded-full transition-all duration-500"
                  style={{ width: progressWidth, backgroundColor: barColor }}
                />
              </div>

              <p className="text-xs text-[var(--text-secondary)] min-h-[2rem]">
                {gate?.summary || "Waiting for previous gate to complete."}
              </p>

              <div className="flex items-center justify-between text-[11px] font-mono tabular-nums text-[var(--text-tertiary)] border-t border-[var(--border-subtle)] pt-2.5">
                <span>Duration: {gate ? `${gate.duration_ms} ms` : "--"}</span>
                <span>Blocking: {gate?.blocking_count ?? 0}</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Real-Time SSE Log Terminal */}
      <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border-subtle)] px-5 py-3">
          <div className="flex items-center gap-2">
            <Terminal className="h-4 w-4 text-[var(--text-secondary)]" strokeWidth={1.6} />
            <span className="text-xs font-semibold text-[var(--text-primary)]">
              Execution Stream
            </span>
            <span className="text-[11px] font-mono text-[var(--text-tertiary)] tabular-nums">
              ({filteredEvents.length} lines)
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="inline-flex rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-canvas)] p-0.5 text-[11px]">
              {(["all", 1, 2, 3] as const).map((tab) => (
                <button
                  key={String(tab)}
                  type="button"
                  onClick={() => setGateFilter(tab)}
                  className={`rounded-md px-2.5 py-1 font-medium transition-colors ${
                    gateFilter === tab
                      ? "bg-[var(--bg-surface)] text-[var(--text-primary)] shadow-xs"
                      : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                  }`}
                >
                  {tab === "all" ? "All Gates" : `Gate ${tab}`}
                </button>
              ))}
            </div>

            <label className="inline-flex items-center gap-1.5 text-[11px] text-[var(--text-secondary)] select-none cursor-pointer">
              <input
                type="checkbox"
                checked={autoScroll}
                onChange={(e) => setAutoScroll(e.target.checked)}
                className="rounded border-[var(--border-strong)]"
              />
              Auto-scroll
            </label>

            <button
              type="button"
              onClick={copyLogs}
              className="inline-flex items-center gap-1 rounded-lg border border-[var(--border-subtle)] px-2.5 py-1 text-[11px] font-medium text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
            >
              {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
              {copied ? "Copied" : "Copy"}
            </button>
          </div>
        </div>

        <div
          ref={terminalRef}
          className="h-[420px] overflow-y-auto bg-[var(--bg-terminal)] p-4 font-mono text-[12px] leading-relaxed"
        >
          {filteredEvents.length === 0 ? (
            <div className="flex h-full items-center justify-center text-xs text-[var(--text-tertiary)]">
              No execution output yet. Start a release gate run to stream live telemetry.
            </div>
          ) : (
            <div className="space-y-1">
              {filteredEvents.map((ev, index) => (
                <div
                  key={`${ev.id}-${index}`}
                  className="grid grid-cols-[76px_48px_1fr] gap-2 rounded px-1.5 py-0.5 hover:bg-[var(--bg-hover)]/60"
                >
                  <span className="text-[11px] text-[var(--text-tertiary)] tabular-nums">
                    {new Date(ev.timestamp).toLocaleTimeString([], {
                      hour12: false,
                      hour: "2-digit",
                      minute: "2-digit",
                      second: "2-digit",
                    })}
                  </span>
                  <span className="text-[11px] font-semibold text-[var(--text-tertiary)]">
                    {ev.gate_number === 0 ? "CORE" : `GATE${ev.gate_number}`}
                  </span>
                  <span className={`break-words ${LEVEL_COLORS[ev.level] ?? "text-[var(--text-primary)]"}`}>
                    {ev.message}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
