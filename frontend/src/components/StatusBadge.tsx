"use client";

import React from "react";

type Tone = "pass" | "warn" | "fail" | "run" | "neutral";

const TONE_MAP: Record<string, Tone> = {
  passed: "pass",
  pass: "pass",
  approved: "pass",
  valid: "pass",
  live: "pass",
  live_llm: "pass",
  applied: "pass",
  hardened: "pass",
  verified: "pass",
  covered: "pass",
  resolved: "pass",
  env: "pass",
  vault: "pass",
  warn: "warn",
  needs_validation: "warn",
  deferred: "warn",
  static_heuristic: "warn",
  simulation: "warn",
  simulation_fallback: "warn",
  medium: "warn",
  restored: "warn",
  candidate: "warn",
  failed: "fail",
  fail: "fail",
  timeout: "fail",
  hold: "fail",
  tampered: "fail",
  expired: "fail",
  invalid_signature: "fail",
  invalid_format: "fail",
  critical: "fail",
  high: "fail",
  confirmed: "fail",
  running: "run",
  queued: "run",
  in_progress: "run",
  pending: "neutral",
  skipped: "neutral",
  out_of_scope: "neutral",
  aborted: "neutral",
  none: "neutral",
  discovered: "neutral",
  low: "neutral",
  informational: "neutral",
  unrated: "neutral",
  hardening_note: "neutral",
  rejected: "neutral",
};

const TONE_STYLES: Record<Tone, React.CSSProperties> = {
  pass: {
    color: "var(--status-pass-fg)",
    backgroundColor: "var(--status-pass-bg)",
    borderColor: "var(--status-pass-border)",
  },
  warn: {
    color: "var(--status-warn-fg)",
    backgroundColor: "var(--status-warn-bg)",
    borderColor: "var(--status-warn-border)",
  },
  fail: {
    color: "var(--status-fail-fg)",
    backgroundColor: "var(--status-fail-bg)",
    borderColor: "var(--status-fail-border)",
  },
  run: {
    color: "var(--status-run-fg)",
    backgroundColor: "var(--status-run-bg)",
    borderColor: "var(--status-run-border)",
  },
  neutral: {
    color: "var(--text-secondary)",
    backgroundColor: "var(--bg-subtle)",
    borderColor: "var(--border-subtle)",
  },
};

export function StatusBadge({
  value,
  label,
  toneOverride,
}: {
  value: string;
  label?: string;
  toneOverride?: Tone;
}) {
  const key = value.toLowerCase();
  const tone: Tone = toneOverride ?? TONE_MAP[key] ?? "neutral";
  const text = label ?? value.replace(/_/g, " ");

  return (
    <span
      style={TONE_STYLES[tone]}
      className="inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-medium tracking-[0.01em] whitespace-nowrap"
    >
      <span
        className="h-1.5 w-1.5 rounded-full shrink-0"
        style={{ backgroundColor: "currentColor", opacity: tone === "neutral" ? 0.5 : 0.9 }}
      />
      {text}
    </span>
  );
}

export function ReadinessRing({ score, size = 128 }: { score: number | null; size?: number }) {
  const numeric = score ?? 0;
  const stroke = 7;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (Math.max(0, Math.min(100, numeric)) / 100) * circumference;

  const strokeColor =
    score === null
      ? "var(--border-strong)"
      : numeric >= 85
      ? "var(--status-pass-fg)"
      : numeric >= 60
      ? "var(--status-warn-fg)"
      : "var(--status-fail-fg)";

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="var(--border-subtle)"
          strokeWidth={stroke}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={strokeColor}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={score === null ? circumference : offset}
          style={{ transition: "stroke-dashoffset 450ms ease" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-semibold tracking-tight tabular-nums text-[var(--text-primary)]">
          {score === null ? "--" : numeric}
        </span>
        <span className="text-[11px] font-medium uppercase tracking-[0.06em] text-[var(--text-tertiary)]">
          / 100
        </span>
      </div>
    </div>
  );
}
