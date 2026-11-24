from __future__ import annotations

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from app.config import PROJECT_ROOT, settings
from app.database import SessionLocal, init_db
from app.models import Project
from app.routers import findings, projects, runs, system
from app.services.vault import ensure_vault_master_key, migrate_plaintext_app_settings


def _seed_sample_project() -> None:
    sample_dir = (PROJECT_ROOT / "sample-target").resolve()
    if not sample_dir.exists():
        return
    with SessionLocal() as db:
        existing = db.scalar(select(Project).limit(1))
        if existing is None:
            db.add(
                Project(
                    name="acme-payments-gateway (Sample)",
                    path=str(sample_dir),
                    description="Built-in sample Git repository with dist/ build artifacts for testing all 3 Bastion gates.",
                    default_secret_scanner="auto",
                    default_bla_intensity="balanced",
                    default_audit_profile="standard",
                    smoke_test_cmd="node -e \"const m=require('./dist/index.js'); if(m.computeLicenseTier(10,8,3).tier!=='team') process.exit(1); console.log('smoke ok');\"",
                )
            )
            db.commit()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    ensure_vault_master_key()
    init_db()
    with SessionLocal() as db:
        migrate_plaintext_app_settings(db)
    _seed_sample_project()
    yield


app = FastAPI(
    title="Bastion Pre-Ship Security & Anti-REA Release Gate",
    version=settings.version,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(system.router)
app.include_router(projects.router)
app.include_router(runs.router)
app.include_router(findings.router)
