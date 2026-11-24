"use client";

import React, { useState } from "react";
import { FolderGit2, X, CheckCircle2, AlertCircle } from "lucide-react";
import { api } from "@/lib/api";
import type { Project, SecretScannerPref } from "@/lib/types";

interface ProjectModalProps {
  open: boolean;
  onClose: () => void;
  onCreated: (project: Project) => void;
}

export function ProjectModal({ open, onClose, onCreated }: ProjectModalProps) {
  const [name, setName] = useState("");
  const [path, setPath] = useState("");
  const [description, setDescription] = useState("");
  const [scanner, setScanner] = useState<SecretScannerPref>("auto");
  const [intensity, setIntensity] = useState<Project["default_bla_intensity"]>("balanced");
  const [profile, setProfile] = useState<Project["default_audit_profile"]>("standard");
  const [smokeTestCmd, setSmokeTestCmd] = useState("");
  const [inspectInfo, setInspectInfo] = useState<{
    exists: boolean;
    is_git_repo: boolean;
    git_branch: string | null;
    git_commit: string | null;
  } | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!open) return null;

  async function handleInspect() {
    if (!path.trim()) return;
    setError(null);
    try {
      const info = await api.inspectPath(path.trim());
      setInspectInfo(info);
      if (!name.trim() && info.suggested_name) {
        setName(info.suggested_name);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to inspect path");
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim() || !path.trim()) {
      setError("Project name and local directory path are required.");
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const created = await api.createProject({
        name: name.trim(),
        path: path.trim(),
        description: description.trim(),
        default_secret_scanner: scanner,
        default_bla_intensity: intensity,
        default_audit_profile: profile,
        smoke_test_cmd: smokeTestCmd.trim(),
      });
      setName("");
      setPath("");
      setDescription("");
      setSmokeTestCmd("");
      setInspectInfo(null);
      onCreated(created);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to register project");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/35 backdrop-blur-[2px] p-4">
      <div className="w-full max-w-lg rounded-2xl border border-[var(--border-strong)] bg-[var(--bg-surface)] shadow-xl">
        <div className="flex items-center justify-between border-b border-[var(--border-subtle)] px-6 py-4">
          <div className="flex items-center gap-2.5">
            <FolderGit2 className="h-4 w-4 text-[var(--text-secondary)]" strokeWidth={1.6} />
            <h2 className="text-[15px] font-semibold tracking-tight text-[var(--text-primary)]">
              Register Local Repository
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] transition-colors"
            aria-label="Close modal"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4 p-6">
          <div>
            <label className="block text-xs font-medium text-[var(--text-secondary)] mb-1.5">
              Local Git Repository or Build Directory
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={path}
                onChange={(e) => {
                  setPath(e.target.value);
                  setInspectInfo(null);
                }}
                placeholder="C:\Users\you\projects\my-app or /path/to/repo"
                className="flex-1 rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-3 py-2 text-sm font-mono text-[var(--text-primary)] placeholder:text-[var(--text-tertiary)] focus:outline-none focus:ring-2 focus:ring-neutral-400/30"
              />
              <button
                type="button"
                onClick={handleInspect}
                className="rounded-lg border border-[var(--border-strong)] bg-[var(--bg-subtle)] px-3 py-2 text-xs font-medium text-[var(--text-primary)] hover:bg-[var(--bg-hover)] transition-colors"
              >
                Verify Path
              </button>
            </div>
            {inspectInfo && (
              <div className="mt-2 flex items-center gap-2 text-xs">
                {inspectInfo.exists ? (
                  <>
                    <CheckCircle2 className="h-3.5 w-3.5 text-[var(--status-pass-fg)]" />
                    <span className="text-[var(--text-secondary)]">
                      Directory found
                      {inspectInfo.is_git_repo
                        ? ` · Git (${inspectInfo.git_branch ?? "HEAD"} @ ${inspectInfo.git_commit ?? "uncommitted"})`
                        : " · Filesystem build directory"}
                    </span>
                  </>
                ) : (
                  <>
                    <AlertCircle className="h-3.5 w-3.5 text-[var(--status-fail-fg)]" />
                    <span className="text-[var(--status-fail-fg)]">Directory not found on local host</span>
                  </>
                )}
              </div>
            )}
          </div>

          <div>
            <label className="block text-xs font-medium text-[var(--text-secondary)] mb-1.5">
              Project Name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Payments Core API"
              className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-3 py-2 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-tertiary)] focus:outline-none focus:ring-2 focus:ring-neutral-400/30"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-[var(--text-secondary)] mb-1.5">
              Description (Optional)
            </label>
            <input
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Release boundary notes or target artifact type"
              className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-3 py-2 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-tertiary)] focus:outline-none focus:ring-2 focus:ring-neutral-400/30"
            />
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="block text-xs font-medium text-[var(--text-secondary)] mb-1.5">
                Gate 1 Scanner
              </label>
              <select
                value={scanner}
                onChange={(e) => setScanner(e.target.value as SecretScannerPref)}
                className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-2.5 py-2 text-xs text-[var(--text-primary)] focus:outline-none"
              >
                <option value="auto">Auto</option>
                <option value="trufflehog">TruffleHog</option>
                <option value="gitleaks">Gitleaks (MIT)</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-[var(--text-secondary)] mb-1.5">
                Audit Profile
              </label>
              <select
                value={profile}
                onChange={(e) => setProfile(e.target.value as Project["default_audit_profile"])}
                className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-2.5 py-2 text-xs text-[var(--text-primary)] focus:outline-none"
              >
                <option value="quick">Quick</option>
                <option value="standard">Standard</option>
                <option value="deep">Deep</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-[var(--text-secondary)] mb-1.5">
                BLA Intensity
              </label>
              <select
                value={intensity}
                onChange={(e) => setIntensity(e.target.value as Project["default_bla_intensity"])}
                className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-2.5 py-2 text-xs text-[var(--text-primary)] focus:outline-none"
              >
                <option value="stealth">Stealth</option>
                <option value="balanced">Balanced</option>
                <option value="maximum">Maximum</option>
                <option value="bankrupt">Bankrupt</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-[var(--text-secondary)] mb-1.5">
              Post-BLA Smoke Test Command (Optional)
            </label>
            <input
              type="text"
              value={smokeTestCmd}
              onChange={(e) => setSmokeTestCmd(e.target.value)}
              placeholder="e.g. node dist/index.js --health or pytest -q"
              className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-canvas)] px-3 py-2 text-xs font-mono text-[var(--text-primary)] placeholder:text-[var(--text-tertiary)] focus:outline-none focus:ring-2 focus:ring-neutral-400/30"
            />
          </div>

          {error && (
            <div className="rounded-lg border border-[var(--status-fail-border)] bg-[var(--status-fail-bg)] px-3 py-2 text-xs text-[var(--status-fail-fg)]">
              {error}
            </div>
          )}

          <div className="flex items-center justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-[var(--border-strong)] px-4 py-2 text-xs font-medium text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="rounded-lg bg-[var(--accent-neutral)] px-4 py-2 text-xs font-medium text-[var(--accent-neutral-fg)] hover:opacity-90 disabled:opacity-50 transition-opacity"
            >
              {submitting ? "Registering..." : "Add Repository"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
