"use client";

import React, { useEffect, useMemo, useState } from "react";
import {
  Search,
  Download,
  X,
  CheckCircle2,
  RotateCcw,
  FileCode2,
  ShieldAlert,
  KeyRound,
  UserCheck,
} from "lucide-react";
import { api } from "@/lib/api";
import type { Finding, FindingCodeContext, Project } from "@/lib/types";
import { StatusBadge } from "./StatusBadge";

interface FindingsViewProps {
  project: Project | null;
  findings: Finding[];
  onFindingUpdated: (updated: Finding) => void;
}

export function FindingsView({ project, findings, onFindingUpdated }: FindingsViewProps) {
  const [gateFilter, setGateFilter] = useState<"all" | 1 | 2>("all");
  const [verdictFilter, setVerdictFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<"all" | "open" | "resolved">("all");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<Finding | null>(null);
  const [codeContext, setCodeContext] = useState<FindingCodeContext | null>(null);
  const [loadingCtx, setLoadingCtx] = useState(false);
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return findings.filter((f) => {
      if (gateFilter !== "all" && f.gate_number !== gateFilter) return false;
      if (verdictFilter !== "all" && f.verdict !== verdictFilter) return false;
      if (severityFilter !== "all" && f.severity !== severityFilter) return false;
      if (statusFilter === "open" && f.resolved) return false;
      if (statusFilter === "resolved" && !f.resolved) return false;
      if (
        q &&
        !f.title.toLowerCase().includes(q) &&
        !f.file_path.toLowerCase().includes(q) &&
        !f.detector_or_class.toLowerCase().includes(q)
      ) {
        return false;
      }
      return true;
    });
  }, [findings, gateFilter, verdictFilter, severityFilter, statusFilter, search]);

  useEffect(() => {
    if (!selected) {
      setCodeContext(null);
      return;
    }
    setNote(selected.resolution_note || "");
    setLoadingCtx(true);
    api
      .getFindingContext(selected.id)
      .then((ctx) => setCodeContext(ctx))
      .catch(() => setCodeContext(null))
      .finally(() => setLoadingCtx(false));
  }, [selected]);

  async function toggleResolved(finding: Finding, targetState: boolean) {
    setSaving(true);
    try {
      const updated = await api.updateFinding(finding.id, {
        resolved: targetState,
        resolution_note: note,
      });
      onFindingUpdated(updated);
      setSelected(updated);
    } finally {
      setSaving(false);
    }
  }

  const confirmedCount = findings.filter((f) => f.verdict === "confirmed" && !f.resolved).length;
  const needsValCount = findings.filter((f) => f.verdict === "needs_validation" && !f.resolved).length;
  const secretCount = findings.filter((f) => f.gate_number === 1 && !f.resolved).length;

  return (
    <div className="space-y-6">
      {/* Header + Stats */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] px-6 py-4">
        <div>
          <h1 className="text-base font-semibold tracking-tight text-[var(--text-primary)]">
            Findings & Triage
          </h1>
          <p className="mt-0.5 text-xs text-[var(--text-secondary)]">
            {secretCount} secret(s) · {confirmedCount} confirmed · {needsValCount} needs validation
          </p>
        </div>

        <a
          href={api.sarifExportUrl(project?.id)}
          download="bastion-findings.sarif.json"
          className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-3.5 py-2 text-xs font-medium text-[var(--text-primary)] hover:bg-[var(--bg-hover)] transition-colors"
        >
          <Download className="h-3.5 w-3.5" />
          Export SARIF
        </a>
      </div>

      {/* Filters Bar */}
      <div className="flex flex-wrap items-center gap-3 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] px-5 py-3.5">
        <div className="relative flex-1 min-w-[220px]">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--text-tertiary)]" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter by title, file path, or detector..."
            className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] pl-9 pr-3 py-1.5 text-xs text-[var(--text-primary)] placeholder:text-[var(--text-tertiary)] focus:outline-none"
          />
        </div>

        <select
          value={String(gateFilter)}
          onChange={(e) =>
            setGateFilter(e.target.value === "all" ? "all" : (Number(e.target.value) as 1 | 2))
          }
          className="rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-2.5 py-1.5 text-xs text-[var(--text-primary)]"
        >
          <option value="all">All Engines</option>
          <option value="1">Gate 1: TruffleHog</option>
          <option value="2">Gate 2: Cloudflare Audit</option>
        </select>

        <select
          value={verdictFilter}
          onChange={(e) => setVerdictFilter(e.target.value)}
          className="rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-2.5 py-1.5 text-xs text-[var(--text-primary)]"
        >
          <option value="all">All Verdicts</option>
          <option value="confirmed">Confirmed</option>
          <option value="needs_validation">Needs Validation</option>
          <option value="hardening_note">Hardening Note</option>
        </select>

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-2.5 py-1.5 text-xs text-[var(--text-primary)]"
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="unrated">Unrated</option>
        </select>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value as "all" | "open" | "resolved")}
          className="rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-2.5 py-1.5 text-xs text-[var(--text-primary)]"
        >
          <option value="all">Open & Resolved</option>
          <option value="open">Open Only</option>
          <option value="resolved">Resolved Only</option>
        </select>
      </div>

      {/* Findings Table */}
      <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] overflow-hidden">
        {filtered.length === 0 ? (
          <div className="px-6 py-12 text-center text-xs text-[var(--text-tertiary)]">
            No findings match the current filter selection.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-[var(--border-subtle)] text-[11px] font-medium uppercase tracking-[0.05em] text-[var(--text-tertiary)]">
                  <th className="px-6 py-3">Engine</th>
                  <th className="px-4 py-3">Finding</th>
                  <th className="px-4 py-3">Location</th>
                  <th className="px-4 py-3">Verdict</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-6 py-3 text-right">State</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-subtle)]">
                {filtered.map((f) => (
                  <tr
                    key={f.id}
                    onClick={() => setSelected(f)}
                    className="cursor-pointer hover:bg-[var(--bg-hover)] transition-colors"
                  >
                    <td className="px-6 py-3.5 whitespace-nowrap">
                      <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-[var(--text-secondary)]">
                        {f.gate_number === 1 ? (
                          <KeyRound className="h-3.5 w-3.5" strokeWidth={1.6} />
                        ) : (
                          <ShieldAlert className="h-3.5 w-3.5" strokeWidth={1.6} />
                        )}
                        {f.gate_number === 1 ? "TruffleHog" : "Cloudflare"}
                      </span>
                    </td>
                    <td className="px-4 py-3.5 max-w-md">
                      <div className="font-medium text-[var(--text-primary)] truncate">{f.title}</div>
                      <div className="mt-0.5 text-[11px] font-mono text-[var(--text-tertiary)] truncate">
                        {f.detector_or_class}
                        {f.gate_number === 1 && f.verified !== null
                          ? ` · ${f.verified ? "verified live" : "unverified"}`
                          : ""}
                      </div>
                    </td>
                    <td className="px-4 py-3.5 font-mono text-[11px] text-[var(--text-secondary)] whitespace-nowrap">
                      {f.file_path}:{f.line_number}
                    </td>
                    <td className="px-4 py-3.5">
                      <StatusBadge value={f.verdict} />
                    </td>
                    <td className="px-4 py-3.5">
                      <StatusBadge value={f.severity} />
                    </td>
                    <td className="px-6 py-3.5 text-right">
                      {f.resolved ? (
                        <StatusBadge value="resolved" />
                      ) : (
                        <span className="text-[11px] text-[var(--text-tertiary)]">Open</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Slide-Over Code Diff / Context Drawer */}
      {selected && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/30 backdrop-blur-[1px]">
          <div className="flex h-full w-full max-w-2xl flex-col border-l border-[var(--border-strong)] bg-[var(--bg-surface)] shadow-2xl">
            <div className="flex items-start justify-between gap-4 border-b border-[var(--border-subtle)] px-6 py-4">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <StatusBadge value={selected.verdict} />
                  <StatusBadge value={selected.severity} />
                  {selected.resolved && <StatusBadge value="resolved" />}
                </div>
                <h2 className="mt-2 text-[15px] font-semibold text-[var(--text-primary)]">
                  {selected.title}
                </h2>
                <p className="mt-0.5 text-xs font-mono text-[var(--text-tertiary)]">
                  {selected.file_path}:{selected.line_number} · {selected.fingerprint}
                </p>
              </div>
              <button
                type="button"
                onClick={() => setSelected(null)}
                className="rounded-lg p-1.5 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-6 space-y-5">
              {/* Hunter vs Verifier Separation Proof */}
              {(selected.hunter_agent_id || selected.verifier_agent_id) && (
                <div className="flex flex-wrap items-center gap-3 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-subtle)] px-4 py-3 text-xs">
                  <UserCheck className="h-4 w-4 text-[var(--text-secondary)]" />
                  <span className="text-[var(--text-secondary)]">
                    Hunter: <code className="text-[var(--text-primary)]">{selected.hunter_agent_id}</code>
                  </span>
                  <span className="text-[var(--text-tertiary)]">/</span>
                  <span className="text-[var(--text-secondary)]">
                    Independent Verifier:{" "}
                    <code className="text-[var(--text-primary)]">{selected.verifier_agent_id}</code>
                  </span>
                </div>
              )}

              {/* Root Cause / Description */}
              <div className="space-y-1.5">
                <div className="text-[11px] font-semibold uppercase tracking-[0.06em] text-[var(--text-tertiary)]">
                  Analysis & Root Cause
                </div>
                <p className="text-xs leading-relaxed text-[var(--text-primary)]">
                  {selected.root_cause || selected.description}
                </p>
              </div>

              {/* Blockers if Needs Validation */}
              {selected.blockers.length > 0 && (
                <div className="rounded-xl border border-[var(--status-warn-border)] bg-[var(--status-warn-bg)] p-4 space-y-1.5">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.06em] text-[var(--status-warn-fg)]">
                    Validation Blockers
                  </div>
                  <ul className="list-disc pl-4 space-y-1 text-xs text-[var(--text-primary)]">
                    {selected.blockers.map((b, i) => (
                      <li key={i}>{b}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Source Context Block */}
              <div className="space-y-2">
                <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-[var(--text-tertiary)]">
                  <FileCode2 className="h-3.5 w-3.5" />
                  Source Context ({selected.file_path})
                </div>
                <div className="overflow-x-auto rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-terminal)] font-mono text-[12px]">
                  {loadingCtx ? (
                    <div className="p-4 text-xs text-[var(--text-tertiary)]">Loading source context...</div>
                  ) : codeContext && codeContext.exists ? (
                    <div className="py-2">
                      {codeContext.lines.map((line) => (
                        <div
                          key={line.line_number}
                          className={`grid grid-cols-[48px_1fr] px-3 py-0.5 ${
                            line.highlight
                              ? "bg-[var(--status-fail-bg)] text-[var(--text-primary)]"
                              : "text-[var(--text-secondary)]"
                          }`}
                        >
                          <span className="select-none text-right pr-3 text-[11px] text-[var(--text-tertiary)] tabular-nums">
                            {line.line_number}
                          </span>
                          <span className="whitespace-pre">{line.content || " "}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-4 text-xs text-[var(--text-tertiary)]">
                      Source file not accessible in current working tree.
                    </div>
                  )}
                </div>
              </div>

              {/* Suggested Code Fix Diff */}
              {(selected.remediation || selected.fixed_code) && (
                <div className="space-y-2">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.06em] text-[var(--text-tertiary)]">
                    Smallest Effective Remediation
                  </div>
                  {selected.remediation && (
                    <p className="text-xs leading-relaxed text-[var(--text-secondary)]">
                      {selected.remediation}
                    </p>
                  )}
                  {selected.fixed_code && (
                    <div className="overflow-x-auto rounded-xl border border-[var(--status-pass-border)] bg-[var(--status-pass-bg)] p-3.5 font-mono text-[12px] text-[var(--text-primary)]">
                      {selected.fixed_code.split("\n").map((ln, idx) => (
                        <div key={idx} className="whitespace-pre">
                          <span className="select-none text-[var(--status-pass-fg)] mr-2">+</span>
                          {ln}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Trace Path */}
              {selected.trace.length > 0 && (
                <div className="space-y-2">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.06em] text-[var(--text-tertiary)]">
                    Boundary Trace
                  </div>
                  <div className="space-y-1.5">
                    {selected.trace.map((step, idx) => (
                      <div
                        key={idx}
                        className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-canvas)] px-3.5 py-2 text-xs"
                      >
                        <div className="flex items-center justify-between font-mono text-[11px]">
                          <span className="uppercase text-[var(--text-tertiary)]">{step.kind}</span>
                          <span className="text-[var(--text-secondary)]">
                            {step.file}:{step.line} ({step.scope})
                          </span>
                        </div>
                        <div className="mt-1 text-[var(--text-primary)]">{step.description}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Triage Resolution Note */}
              <div className="space-y-1.5 border-t border-[var(--border-subtle)] pt-4">
                <label className="block text-[11px] font-semibold uppercase tracking-[0.06em] text-[var(--text-tertiary)]">
                  Triage Note
                </label>
                <textarea
                  rows={2}
                  value={note}
                  onChange={(e) => setNote(e.target.value)}
                  placeholder="Document remediation PR, key rotation timestamp, or accepted risk..."
                  className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-3 py-2 text-xs text-[var(--text-primary)] placeholder:text-[var(--text-tertiary)] focus:outline-none"
                />
              </div>
            </div>

            <div className="flex items-center justify-between border-t border-[var(--border-subtle)] px-6 py-4">
              <button
                type="button"
                onClick={() => setSelected(null)}
                className="rounded-lg border border-[var(--border-strong)] px-3.5 py-2 text-xs font-medium text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
              >
                Close
              </button>

              {selected.resolved ? (
                <button
                  type="button"
                  disabled={saving}
                  onClick={() => toggleResolved(selected, false)}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-4 py-2 text-xs font-medium text-[var(--text-primary)] hover:bg-[var(--bg-hover)]"
                >
                  <RotateCcw className="h-3.5 w-3.5" />
                  Reopen Finding
                </button>
              ) : (
                <button
                  type="button"
                  disabled={saving}
                  onClick={() => toggleResolved(selected, true)}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--accent-neutral)] px-4 py-2 text-xs font-medium text-[var(--accent-neutral-fg)] hover:opacity-90 disabled:opacity-50"
                >
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  {saving ? "Saving..." : "Mark Resolved"}
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
