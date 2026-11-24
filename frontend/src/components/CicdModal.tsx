"use client";

import React, { useEffect, useState } from "react";
import { X, GitPullRequest, Copy, Check, Download, Box, Wrench } from "lucide-react";
import { api } from "@/lib/api";
import type { CicdMode, CicdWorkflowResponse, Project } from "@/lib/types";

interface CicdModalProps {
  open: boolean;
  project: Project | null;
  onClose: () => void;
}

const DEFAULT_IMAGE = "ghcr.io/<org>/bastion-cli:latest";

export function CicdModal({ open, project, onClose }: CicdModalProps) {
  const [mode, setMode] = useState<CicdMode>("container");
  const [image, setImage] = useState<string>(DEFAULT_IMAGE);
  const [workflow, setWorkflow] = useState<CicdWorkflowResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!open || !project) return;
    let active = true;
    const timer = setTimeout(() => {
      setLoading(true);
      api
        .getGithubActionsWorkflow(project.id, mode, mode === "container" ? image : undefined)
        .then((res) => {
          if (active) setWorkflow(res);
        })
        .catch(() => {
          if (active) setWorkflow(null);
        })
        .finally(() => {
          if (active) setLoading(false);
        });
    }, 120);
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [open, project, mode, image]);

  if (!open || !project) return null;

  function handleCopy() {
    if (!workflow) return;
    navigator.clipboard.writeText(workflow.yaml_content).catch(() => undefined);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  }

  function handleDownload() {
    if (!workflow) return;
    const blob = new Blob([workflow.yaml_content], { type: "text/yaml;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "bastion-gate.yml";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/35 backdrop-blur-[2px] p-4">
      <div className="flex max-h-[88vh] w-full max-w-3xl flex-col rounded-2xl border border-[var(--border-strong)] bg-[var(--bg-surface)] shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between border-b border-[var(--border-subtle)] px-6 py-4">
          <div className="flex items-center gap-2.5">
            <GitPullRequest className="h-4 w-4 text-[var(--text-secondary)]" strokeWidth={1.6} />
            <div>
              <h2 className="text-[15px] font-semibold tracking-tight text-[var(--text-primary)]">
                CI/CD Pull Request Gate Setup
              </h2>
              <p className="text-xs text-[var(--text-secondary)]">
                Save as <code className="font-mono text-[var(--text-primary)]">.github/workflows/bastion-gate.yml</code> in {project.name}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
            aria-label="Close CI/CD modal"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Mode Switcher: Published Container vs Self-Built Dockerfile.cli */}
        <div className="border-b border-[var(--border-subtle)] bg-[var(--bg-subtle)] px-6 py-3.5 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="inline-flex rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] p-0.5">
              <button
                type="button"
                onClick={() => setMode("container")}
                className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                  mode === "container"
                    ? "bg-[var(--accent-neutral)] text-[var(--accent-neutral-fg)]"
                    : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                }`}
              >
                <Box className="h-3.5 w-3.5" />
                Published Container
              </button>
              <button
                type="button"
                onClick={() => setMode("self-built")}
                className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                  mode === "self-built"
                    ? "bg-[var(--accent-neutral)] text-[var(--accent-neutral-fg)]"
                    : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                }`}
              >
                <Wrench className="h-3.5 w-3.5" />
                Self-Built (./Dockerfile.cli)
              </button>
            </div>

            {mode === "container" ? (
              <div className="flex items-center gap-2 flex-1 min-w-[220px] max-w-sm">
                <label className="text-[11px] font-medium text-[var(--text-tertiary)] shrink-0">
                  Image:
                </label>
                <input
                  type="text"
                  value={image}
                  onChange={(e) => setImage(e.target.value)}
                  className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-2.5 py-1 text-xs font-mono text-[var(--text-primary)] focus:outline-none"
                />
              </div>
            ) : (
              <span className="text-[11px] text-[var(--text-secondary)]">
                Builds non-root <code className="font-mono">Dockerfile.cli</code> (MIT Gitleaks, Node 22 + BLA, Cloudflare validators)
              </span>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-x-5 gap-y-1 text-[11px] font-mono text-[var(--text-secondary)]">
            <span>Exit 0: All gates passed</span>
            <span>Exit 10: Gate 1 secret blocked</span>
            <span>Exit 20: Gate 2 high/critical vuln</span>
            <span>Exit 30: Gate 3 BLA / smoke failed</span>
          </div>
        </div>

        <div className="flex-1 overflow-auto bg-[var(--bg-terminal)] p-5 font-mono text-[11.5px] leading-relaxed text-[var(--text-primary)]">
          {loading ? (
            <div className="text-[var(--text-tertiary)]">Generating GitHub Actions workflow...</div>
          ) : workflow ? (
            <pre className="whitespace-pre">{workflow.yaml_content}</pre>
          ) : (
            <div className="text-[var(--status-fail-fg)]">Unable to generate workflow YAML.</div>
          )}
        </div>

        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[var(--border-subtle)] px-6 py-4">
          <span className="text-xs text-[var(--text-tertiary)]">
            AGPL-clean default (<code className="font-mono">--scanner gitleaks</code>, <code className="font-mono">--scope diff</code>) · uploads SARIF &amp; Ed25519 certificate artifacts.
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleCopy}
              disabled={!workflow}
              className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-3.5 py-2 text-xs font-medium text-[var(--text-primary)] hover:bg-[var(--bg-hover)]"
            >
              {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
              {copied ? "Copied" : "Copy YAML"}
            </button>
            <button
              type="button"
              onClick={handleDownload}
              disabled={!workflow}
              className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--accent-neutral)] px-4 py-2 text-xs font-medium text-[var(--accent-neutral-fg)] hover:opacity-90"
            >
              <Download className="h-3.5 w-3.5" />
              Download Workflow
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
