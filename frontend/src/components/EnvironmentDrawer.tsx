"use client";

import React, { useState } from "react";
import { X, RefreshCw, Copy, Check, Terminal, KeyRound } from "lucide-react";
import type { SystemToolsResponse } from "@/lib/types";
import { StatusBadge } from "./StatusBadge";

interface EnvironmentDrawerProps {
  open: boolean;
  tools: SystemToolsResponse | null;
  onClose: () => void;
  onRefresh: () => Promise<void>;
}

export function EnvironmentDrawer({ open, tools, onClose, onRefresh }: EnvironmentDrawerProps) {
  const [refreshing, setRefreshing] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  if (!open) return null;

  async function handleRefresh() {
    setRefreshing(true);
    try {
      await onRefresh();
    } finally {
      setRefreshing(false);
    }
  }

  function copyText(key: string, text: string) {
    navigator.clipboard.writeText(text).catch(() => undefined);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  }

  const items = tools
    ? [tools.trufflehog, tools.gitleaks, tools.cloudflare_skill, tools.bla, tools.node, tools.git]
    : [];

  const psCmd = `powershell -ExecutionPolicy Bypass -File "${tools?.setup_ps1_path ?? "./setup.ps1"}"`;
  const shCmd = `bash "${tools?.setup_sh_path ?? "./setup.sh"}"`;

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/30 backdrop-blur-[1px]">
      <div className="flex h-full w-full max-w-lg flex-col border-l border-[var(--border-strong)] bg-[var(--bg-surface)] shadow-2xl">
        <div className="flex items-center justify-between border-b border-[var(--border-subtle)] px-6 py-4">
          <div>
            <h2 className="text-[15px] font-semibold tracking-tight text-[var(--text-primary)]">
              Local Security Toolchain
            </h2>
            <p className="text-xs text-[var(--text-secondary)] mt-0.5">
              External CLI plugins and Ed25519 signing identity
            </p>
          </div>
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={handleRefresh}
              className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border-strong)] px-2.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] transition-colors"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />
              Re-check
            </button>
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg p-1.5 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] transition-colors"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {tools?.ed25519_key_fingerprint && (
            <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-subtle)] p-4 space-y-1.5">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-[var(--text-primary)]">
                <KeyRound className="h-3.5 w-3.5 text-[var(--text-secondary)]" />
                Ed25519 Signing Identity
              </div>
              <div className="text-[11px] font-mono text-[var(--text-primary)]">
                {tools.ed25519_key_fingerprint}
              </div>
              <div className="text-[11px] font-mono text-[var(--text-tertiary)] truncate" title={tools.ed25519_public_key_path}>
                Public key: {tools.ed25519_public_key_path}
              </div>
            </div>
          )}

          <div className="space-y-2.5">
            {items.map((tool) => (
              <div
                key={tool.name}
                className="rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-canvas)] p-4"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-medium text-[var(--text-primary)]">{tool.name}</span>
                  <StatusBadge
                    value={tool.mode}
                    label={tool.mode === "live" ? "Live Plugin" : "Not Installed"}
                  />
                </div>
                <p className="mt-1.5 text-xs text-[var(--text-secondary)] leading-relaxed">
                  {tool.details}
                </p>
                {(tool.version || tool.path) && (
                  <div className="mt-2.5 space-y-1 border-t border-[var(--border-subtle)] pt-2 text-[11px] font-mono text-[var(--text-tertiary)]">
                    {tool.version && <div>Version: {tool.version}</div>}
                    {tool.path && <div className="truncate" title={tool.path}>Path: {tool.path}</div>}
                  </div>
                )}
              </div>
            ))}
          </div>

          <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-subtle)] p-4 space-y-3">
            <div className="flex items-center gap-2 text-xs font-semibold text-[var(--text-primary)]">
              <Terminal className="h-3.5 w-3.5 text-[var(--text-secondary)]" />
              One-Click Environment Setup Scripts
            </div>
            <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
              Installs external user-owned TruffleHog, Cloudflare Security Audit Skill, and BLA CLIs. You can also install MIT-licensed Gitleaks as a drop-in Gate 1 plugin.
            </p>

            <div className="space-y-2">
              <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-2.5">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[11px] font-medium text-[var(--text-secondary)]">Windows (PowerShell)</span>
                  <button
                    type="button"
                    onClick={() => copyText("ps", psCmd)}
                    className="inline-flex items-center gap-1 text-[11px] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                  >
                    {copiedKey === "ps" ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                    {copiedKey === "ps" ? "Copied" : "Copy"}
                  </button>
                </div>
                <code className="block text-[11px] text-[var(--text-primary)] break-all">{psCmd}</code>
              </div>

              <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-2.5">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[11px] font-medium text-[var(--text-secondary)]">macOS / Linux (Bash)</span>
                  <button
                    type="button"
                    onClick={() => copyText("sh", shCmd)}
                    className="inline-flex items-center gap-1 text-[11px] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                  >
                    {copiedKey === "sh" ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                    {copiedKey === "sh" ? "Copied" : "Copy"}
                  </button>
                </div>
                <code className="block text-[11px] text-[var(--text-primary)] break-all">{shCmd}</code>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
