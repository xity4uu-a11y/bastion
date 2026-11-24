from __future__ import annotations

import datetime as dt
import uuid
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _uuid() -> str:
    return uuid.uuid4().hex[:12]


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    path: Mapped[str] = mapped_column(String(1024), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    default_secret_scanner: Mapped[str] = mapped_column(String(32), default="auto")
    default_bla_intensity: Mapped[str] = mapped_column(String(32), default="balanced")
    default_audit_profile: Mapped[str] = mapped_column(String(32), default="standard")
    smoke_test_cmd: Mapped[str] = mapped_column(Text, default="")
    bla_applied: Mapped[bool] = mapped_column(Boolean, default=False)
    bla_backup_dir: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    runs: Mapped[list["ReleaseRun"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    ledger_entries: Mapped[list["CoverageLedgerEntry"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class ReleaseRun(Base):
    __tablename__ = "release_runs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    run_number: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[str] = mapped_column(String(32), default="queued")
    current_gate: Mapped[int] = mapped_column(Integer, default=0)
    readiness_score: Mapped[int] = mapped_column(Integer, default=0)
    git_commit: Mapped[str | None] = mapped_column(String(64), nullable=True)
    git_branch: Mapped[str | None] = mapped_column(String(128), nullable=True)
    git_dirty: Mapped[bool] = mapped_column(Boolean, default=False)
    secret_scanner: Mapped[str] = mapped_column(String(32), default="auto")
    bla_intensity: Mapped[str] = mapped_column(String(32), default="balanced")
    audit_profile: Mapped[str] = mapped_column(String(32), default="standard")
    audit_scope: Mapped[str] = mapped_column(String(16), default="full")
    base_ref: Mapped[str] = mapped_column(String(128), default="")
    max_budget_usd: Mapped[float] = mapped_column(Float, default=1.50)
    smoke_test_cmd: Mapped[str] = mapped_column(Text, default="")
    simulation_used: Mapped[bool] = mapped_column(Boolean, default=False)
    output_dir: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    summary_json: Mapped[str] = mapped_column(Text, default="{}")
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    project: Mapped["Project"] = relationship(back_populates="runs")
    gates: Mapped[list["GateExecution"]] = relationship(
        back_populates="run", cascade="all, delete-orphan", order_by="GateExecution.gate_number"
    )
    findings: Mapped[list["Finding"]] = relationship(back_populates="run", cascade="all, delete-orphan")
    artifacts: Mapped[list["ArtifactRecord"]] = relationship(back_populates="run", cascade="all, delete-orphan")
    events: Mapped[list["AuditEvent"]] = relationship(
        back_populates="run", cascade="all, delete-orphan", order_by="AuditEvent.id"
    )


class GateExecution(Base):
    __tablename__ = "gate_executions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    run_id: Mapped[str] = mapped_column(ForeignKey("release_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    gate_number: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    engine: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    mode: Mapped[str] = mapped_column(String(32), default="live")
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    blocking_count: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[str] = mapped_column(Text, default="")
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    run: Mapped["ReleaseRun"] = relationship(back_populates="gates")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    run_id: Mapped[str] = mapped_column(ForeignKey("release_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    gate_number: Mapped[int] = mapped_column(Integer, nullable=False)
    source_engine: Mapped[str] = mapped_column(String(64), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    detector_or_class: Mapped[str] = mapped_column(String(160), default="")
    file_path: Mapped[str] = mapped_column(String(1024), default="")
    line_number: Mapped[int] = mapped_column(Integer, default=1)
    verified: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    redacted_secret: Mapped[str | None] = mapped_column(String(256), nullable=True)
    git_commit: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verdict: Mapped[str] = mapped_column(String(48), default="confirmed")
    severity: Mapped[str] = mapped_column(String(32), default="medium")
    confidence: Mapped[str] = mapped_column(String(32), default="high")
    hunter_agent_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verifier_agent_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    root_cause: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    fixed_code: Mapped[str] = mapped_column(Text, default="")
    trace_json: Mapped[str] = mapped_column(Text, default="[]")
    evidence_json: Mapped[str] = mapped_column(Text, default="[]")
    blockers_json: Mapped[str] = mapped_column(Text, default="[]")
    resolved: Mapped[bool] = mapped_column(Boolean, default=False)
    resolution_note: Mapped[str] = mapped_column(Text, default="")
    resolved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    run: Mapped["ReleaseRun"] = relationship(back_populates="findings")


class CoverageLedgerEntry(Base):
    __tablename__ = "coverage_ledger_entries"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    last_run_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    coverage_id: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    surface: Mapped[str] = mapped_column(String(160), nullable=False)
    boundary: Mapped[str] = mapped_column(String(160), nullable=False)
    subsystem: Mapped[str] = mapped_column(String(160), nullable=False)
    attack_class: Mapped[str] = mapped_column(String(160), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="planned")
    prior_status: Mapped[str] = mapped_column(String(64), default="new")
    wave: Mapped[int] = mapped_column(Integer, default=1)
    hunter_agent_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verifier_agent_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_hash: Mapped[str] = mapped_column(String(64), default="")
    unit_json: Mapped[str] = mapped_column(Text, default="{}")
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    project: Mapped["Project"] = relationship(back_populates="ledger_entries")


class ArtifactRecord(Base):
    __tablename__ = "artifact_records"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    run_id: Mapped[str] = mapped_column(ForeignKey("release_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    relative_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    artifact_format: Mapped[str] = mapped_column(String(64), default="unknown")
    category: Mapped[str] = mapped_column(String(64), default="build")
    input_bytes: Mapped[int] = mapped_column(Integer, default=0)
    output_bytes: Mapped[int] = mapped_column(Integer, default=0)
    mirror_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    intensity: Mapped[str] = mapped_column(String(32), default="balanced")
    status: Mapped[str] = mapped_column(String(32), default="discovered")
    defense_score: Mapped[float] = mapped_column(Float, default=0.0)
    token_amplification: Mapped[float] = mapped_column(Float, default=0.0)
    cost_amplification: Mapped[float] = mapped_column(Float, default=0.0)
    before_exposure_score: Mapped[float] = mapped_column(Float, default=0.0)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    run: Mapped["ReleaseRun"] = relationship(back_populates="artifacts")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("release_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    gate_number: Mapped[int] = mapped_column(Integer, default=0)
    level: Mapped[str] = mapped_column(String(16), default="info")
    message: Mapped[str] = mapped_column(Text, nullable=False)
    timestamp: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    run: Mapped["ReleaseRun"] = relationship(back_populates="events")
