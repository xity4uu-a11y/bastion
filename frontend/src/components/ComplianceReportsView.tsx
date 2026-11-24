"use client";

import React, { useEffect, useState } from "react";
import {
  FileCheck2,
  FileJson,
  FileText,
  Download,
  BookOpenCheck,
  ShieldCheck,
  Upload,
  KeyRound,
  CheckCircle2,
  XCircle,
} from "lucide-react";
import { api } from "@/lib/api";
import type {
  CertificateVerifyResponse,
  CoverageLedgerEntry,
  Project,
  PublicKeyResponse,
  ReleaseRun,
} from "@/lib/types";
import { StatusBadge } from "./StatusBadge";

interface ComplianceReportsViewProps {
  project: Project | null;
  runs: ReleaseRun[];
  ledger: CoverageLedgerEntry[];
}

export function ComplianceReportsView({ project, runs, ledger }: ComplianceReportsViewProps) {
  const [selectedRunId, setSelectedRunId] = useState<string | null>(runs[0]?.id ?? null);
  const [certPreview, setCertPreview] = useState<Record<string, unknown> | null>(null);
  const [loadingPreview, setLoadingPreview] = useState(false);

  // Ed25519 Certificate Verification state
  const [hostPubKey, setHostPubKey] = useState<PublicKeyResponse | null>(null);
  const [customPubKey, setCustomPubKey] = useState("");
  const [verifyFileName, setVerifyFileName] = useState<string | null>(null);
  const [verifyResult, setVerifyResult] = useState<CertificateVerifyResponse | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [dragActive, setDragActive] = useState(false);

  useEffect(() => {
    api.getPublicKey().then(setHostPubKey).catch(() => undefined);
  }, []);

  useEffect(() => {
    if (!selectedRunId && runs.length > 0) {
      setSelectedRunId(runs[0].id);
    } else if (selectedRunId && !runs.some((r) => r.id === selectedRunId)) {
      setSelectedRunId(runs[0]?.id ?? null);
    }
  }, [runs, selectedRunId]);

  useEffect(() => {
    if (!selectedRunId) {
      setCertPreview(null);
      return;
    }
    setLoadingPreview(true);
    api
      .getCertificateJson(selectedRunId)
      .then((data) => setCertPreview(data))
      .catch(() => setCertPreview(null))
      .finally(() => setLoadingPreview(false));
  }, [selectedRunId]);

  async function verifyJsonText(text: string, label: string) {
    setVerifying(true);
    setVerifyError(null);
    setVerifyResult(null);
    setVerifyFileName(label);
    try {
      const parsed = JSON.parse(text) as Record<string, unknown>;
      const res = await api.verifyCertificate(parsed, customPubKey.trim() || undefined);
      setVerifyResult(res);
    } catch (err) {
      setVerifyError(err instanceof Error ? err.message : "Invalid JSON certificate file");
    } finally {
      setVerifying(false);
    }
  }

  function handleFileSelected(file: File | null) {
    if (!file) return;
    file
      .text()
      .then((txt) => verifyJsonText(txt, file.name))
      .catch(() => setVerifyError("Failed to read uploaded file."));
  }

  function handleDownloadHostPublicKey() {
    if (!hostPubKey) return;
    const blob = new Blob([hostPubKey.public_key_pem], { type: "application/x-pem-file" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "ed25519_public.pem";
    a.click();
    URL.revokeObjectURL(url);
  }

  const activeRun = runs.find((r) => r.id === selectedRunId) ?? null;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] px-6 py-4">
        <div>
          <h1 className="text-base font-semibold tracking-tight text-[var(--text-primary)]">
            Compliance Reports & Ed25519 Certificates
          </h1>
          <p className="mt-0.5 text-xs text-[var(--text-secondary)]">
            Asymmetrically signed release attestations, tamper/expiry verifier, and additive coverage ledger
          </p>
        </div>

        {activeRun && (
          <div className="flex flex-wrap items-center gap-2">
            <a
              href={api.certificateUrl(activeRun.id, "json")}
              download
              className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-3 py-1.5 text-xs font-medium text-[var(--text-primary)] hover:bg-[var(--bg-hover)]"
            >
              <FileJson className="h-3.5 w-3.5" />
              Signed JSON
            </a>
            <a
              href={api.certificateUrl(activeRun.id, "md")}
              download
              className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-3 py-1.5 text-xs font-medium text-[var(--text-primary)] hover:bg-[var(--bg-hover)]"
            >
              <FileText className="h-3.5 w-3.5" />
              Markdown
            </a>
            <a
              href={api.certificateUrl(activeRun.id, "pdf")}
              download
              className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--accent-neutral)] px-3.5 py-1.5 text-xs font-medium text-[var(--accent-neutral-fg)] hover:opacity-90"
            >
              <Download className="h-3.5 w-3.5" />
              PDF Certificate
            </a>
          </div>
        )}
      </div>

      {/* Verify Release Certificate (Ed25519 Drag-and-Drop) */}
      <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-6 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-[var(--text-secondary)]" strokeWidth={1.6} />
            <div>
              <h2 className="text-sm font-semibold text-[var(--text-primary)]">
                Verify Certificate (Ed25519 Tamper & Expiry Check)
              </h2>
              <p className="text-xs text-[var(--text-secondary)]">
                Drop any Bastion <code className="font-mono">.json</code> certificate to cryptographically verify its Ed25519 signature and expiration window
              </p>
            </div>
          </div>

          {hostPubKey && (
            <button
              type="button"
              onClick={handleDownloadHostPublicKey}
              className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)]"
            >
              <KeyRound className="h-3.5 w-3.5" />
              Public Key ({hostPubKey.key_fingerprint.slice(0, 20)}...)
            </button>
          )}
        </div>

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
          <label
            onDragOver={(e) => {
              e.preventDefault();
              setDragActive(true);
            }}
            onDragLeave={() => setDragActive(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragActive(false);
              handleFileSelected(e.dataTransfer.files?.[0] ?? null);
            }}
            className={`lg:col-span-7 flex flex-col items-center justify-center rounded-xl border border-dashed px-6 py-7 text-center cursor-pointer transition-colors ${
              dragActive
                ? "border-[var(--text-primary)] bg-[var(--bg-subtle)]"
                : "border-[var(--border-strong)] bg-[var(--bg-canvas)] hover:bg-[var(--bg-subtle)]/60"
            }`}
          >
            <input
              type="file"
              accept=".json,application/json"
              className="hidden"
              onChange={(e) => handleFileSelected(e.target.files?.[0] ?? null)}
            />
            <Upload className="h-5 w-5 text-[var(--text-tertiary)]" strokeWidth={1.6} />
            <div className="mt-2 text-xs font-medium text-[var(--text-primary)]">
              {verifying
                ? "Verifying Ed25519 signature..."
                : verifyFileName
                ? `Uploaded: ${verifyFileName} (click or drop to verify another)`
                : "Drop a signed Release Certificate (.json) here, or click to browse"}
            </div>
            <div className="mt-1 text-[11px] text-[var(--text-tertiary)]">
              Also available offline via CLI:{" "}
              <code className="font-mono">bastion verify cert.json --pubkey ed25519_public.pem</code>
            </div>
            {certPreview && (
              <button
                type="button"
                onClick={(e) => {
                  e.preventDefault();
                  verifyJsonText(JSON.stringify(certPreview), `Selected Run #${activeRun?.run_number ?? ""}`);
                }}
                className="mt-3 rounded-lg border border-[var(--border-strong)] bg-[var(--bg-surface)] px-3 py-1 text-[11px] font-medium text-[var(--text-primary)] hover:bg-[var(--bg-hover)]"
              >
                Verify Currently Selected Run Certificate
              </button>
            )}
          </label>

          <div className="lg:col-span-5 flex flex-col">
            <label className="text-[11px] font-medium text-[var(--text-secondary)] mb-1.5">
              Optional Trusted Public Key PEM (defaults to host ~/.bastion/keys/ed25519_public.pem)
            </label>
            <textarea
              rows={4}
              value={customPubKey}
              onChange={(e) => setCustomPubKey(e.target.value)}
              placeholder="-----BEGIN PUBLIC KEY-----&#10;...&#10;-----END PUBLIC KEY-----"
              className="flex-1 rounded-xl border border-[var(--border-strong)] bg-[var(--bg-canvas)] p-3 font-mono text-[11px] text-[var(--text-primary)] placeholder:text-[var(--text-tertiary)] focus:outline-none"
            />
          </div>
        </div>

        {verifyError && (
          <div className="rounded-xl border border-[var(--status-fail-border)] bg-[var(--status-fail-bg)] px-4 py-3 text-xs text-[var(--status-fail-fg)]">
            {verifyError}
          </div>
        )}

        {verifyResult && (
          <div
            className={`rounded-xl border p-4 space-y-2 ${
              verifyResult.valid
                ? "border-[var(--status-pass-border)] bg-[var(--status-pass-bg)]"
                : "border-[var(--status-fail-border)] bg-[var(--status-fail-bg)]"
            }`}
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                {verifyResult.valid ? (
                  <CheckCircle2 className="h-4 w-4 text-[var(--status-pass-fg)]" />
                ) : (
                  <XCircle className="h-4 w-4 text-[var(--status-fail-fg)]" />
                )}
                <span className="text-xs font-semibold text-[var(--text-primary)]">
                  {verifyResult.valid
                    ? "Cryptographically Valid Ed25519 Release Certificate"
                    : `Verification Failed (${verifyResult.status.replace(/_/g, " ").toUpperCase()})`}
                </span>
              </div>
              <StatusBadge value={verifyResult.status} />
            </div>

            <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-3 text-[11px] font-mono text-[var(--text-secondary)] pt-1">
              <div>Cert ID: {verifyResult.certificate_id ?? "N/A"}</div>
              <div>Key FP: {verifyResult.key_fingerprint ?? "N/A"}</div>
              <div>Expires: {verifyResult.expires_at ? new Date(verifyResult.expires_at).toLocaleDateString() : "N/A"}</div>
            </div>

            {verifyResult.errors.length > 0 && (
              <ul className="list-disc pl-5 text-xs text-[var(--status-fail-fg)] space-y-0.5 pt-1">
                {verifyResult.errors.map((err, i) => (
                  <li key={i}>{err}</li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>

      {/* Runs History + Certificate Preview */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        <div className="lg:col-span-7 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] overflow-hidden">
          <div className="border-b border-[var(--border-subtle)] px-6 py-4">
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">
              Run History ({runs.length})
            </h2>
          </div>

          {runs.length === 0 ? (
            <div className="px-6 py-12 text-center text-xs text-[var(--text-tertiary)]">
              No completed runs for {project?.name ?? "this project"} yet.
            </div>
          ) : (
            <div className="divide-y divide-[var(--border-subtle)]">
              {runs.map((r) => {
                const isSelected = r.id === selectedRunId;
                const g2 = r.gates.find((g) => g.gate_number === 2);
                const g2Badge =
                  (g2?.metadata?.engine_badge as string | undefined) ||
                  (r.summary?.gate2_engine_badge as string | undefined) ||
                  "Static Heuristic Fallback (No LLM)";
                const g2IsLlm = g2?.mode === "live_llm";

                return (
                  <div
                    key={r.id}
                    onClick={() => setSelectedRunId(r.id)}
                    className={`cursor-pointer px-6 py-4 transition-colors ${
                      isSelected ? "bg-[var(--bg-subtle)]" : "hover:bg-[var(--bg-hover)]/60"
                    }`}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-xs font-semibold text-[var(--text-primary)]">
                          Run #{r.run_number}
                        </span>
                        <StatusBadge value={r.status} />
                        <StatusBadge
                          value={g2IsLlm ? "live_llm" : "static_heuristic"}
                          label={g2Badge}
                        />
                      </div>
                      <span className="font-mono text-xs tabular-nums text-[var(--text-primary)]">
                        {r.readiness_score}/100
                      </span>
                    </div>

                    <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-[11px] text-[var(--text-tertiary)]">
                      <div className="flex items-center gap-2 font-mono">
                        <span>{r.git_branch ?? "local"}</span>
                        <span>@</span>
                        <span>{r.git_commit ?? "uncommitted"}</span>
                        <span>·</span>
                        <span>{r.audit_profile} / {r.bla_intensity}</span>
                      </div>
                      <span className="tabular-nums">{new Date(r.created_at).toLocaleString()}</span>
                    </div>

                    <div className="mt-2.5 flex flex-wrap items-center gap-2">
                      {r.gates.map((g) => (
                        <span
                          key={g.id}
                          className="rounded-md border border-[var(--border-subtle)] bg-[var(--bg-surface)] px-2 py-0.5 text-[11px] text-[var(--text-secondary)]"
                        >
                          G{g.gate_number} {g.name}: <strong className="capitalize">{g.status}</strong>
                        </span>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Signed Release Certificate Inspector */}
        <div className="lg:col-span-5 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] flex flex-col overflow-hidden">
          <div className="flex items-center justify-between border-b border-[var(--border-subtle)] px-5 py-4">
            <div className="flex items-center gap-2">
              <FileCheck2 className="h-4 w-4 text-[var(--text-secondary)]" strokeWidth={1.6} />
              <h2 className="text-sm font-semibold text-[var(--text-primary)]">
                Ed25519 Signed Payload
              </h2>
            </div>
            {activeRun && (
              <StatusBadge
                value={activeRun.status === "passed" ? "approved" : "hold"}
                label={activeRun.status === "passed" ? "APPROVED" : "HOLD"}
              />
            )}
          </div>

          <div className="flex-1 overflow-auto bg-[var(--bg-terminal)] p-4 font-mono text-[11px] leading-relaxed text-[var(--text-secondary)] max-h-[460px]">
            {loadingPreview ? (
              <div>Signing Ed25519 certificate...</div>
            ) : certPreview ? (
              <pre className="whitespace-pre-wrap break-all">
                {JSON.stringify(certPreview, null, 2)}
              </pre>
            ) : (
              <div>Select a run to inspect its Ed25519-signed release certificate.</div>
            )}
          </div>
        </div>
      </div>

      {/* Additive Coverage Ledger */}
      <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] overflow-hidden">
        <div className="flex items-center justify-between border-b border-[var(--border-subtle)] px-6 py-4">
          <div className="flex items-center gap-2">
            <BookOpenCheck className="h-4 w-4 text-[var(--text-secondary)]" strokeWidth={1.6} />
            <div>
              <h2 className="text-sm font-semibold text-[var(--text-primary)]">
                Additive Coverage Ledger ({ledger.length} units)
              </h2>
              <p className="text-xs text-[var(--text-secondary)]">
                Cross-run Cloudflare audit coverage tracking unchanged vs. changed source boundaries
              </p>
            </div>
          </div>
        </div>

        {ledger.length === 0 ? (
          <div className="px-6 py-10 text-center text-xs text-[var(--text-tertiary)]">
            Coverage ledger populates automatically after Gate 2 completes.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-[var(--border-subtle)] text-[11px] font-medium uppercase tracking-[0.05em] text-[var(--text-tertiary)]">
                  <th className="px-6 py-3">Surface / Attack Class</th>
                  <th className="px-4 py-3">Boundary</th>
                  <th className="px-4 py-3">Prior State</th>
                  <th className="px-4 py-3">Hunter / Verifier</th>
                  <th className="px-6 py-3 text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-subtle)]">
                {ledger.map((u) => (
                  <tr key={u.id} className="hover:bg-[var(--bg-hover)]/60">
                    <td className="px-6 py-3">
                      <div className="font-medium text-[var(--text-primary)]">{u.attack_class}</div>
                      <div className="text-[11px] font-mono text-[var(--text-tertiary)]">
                        {u.surface} · {u.subsystem}
                      </div>
                    </td>
                    <td className="px-4 py-3 font-mono text-[11px] text-[var(--text-secondary)]">
                      {u.boundary}
                    </td>
                    <td className="px-4 py-3 font-mono text-[11px] text-[var(--text-secondary)]">
                      {u.prior_status}
                    </td>
                    <td className="px-4 py-3 font-mono text-[11px] text-[var(--text-secondary)]">
                      {u.hunter_agent_id ?? "--"}
                      {u.verifier_agent_id ? ` / ${u.verifier_agent_id}` : ""}
                    </td>
                    <td className="px-6 py-3 text-right">
                      <StatusBadge value={u.status} />
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
