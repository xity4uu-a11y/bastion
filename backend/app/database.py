from __future__ import annotations

from collections.abc import Generator
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings

connect_args = {"check_same_thread": False} if settings.resolved_db_url.startswith("sqlite") else {}

engine = create_engine(
    settings.resolved_db_url,
    connect_args=connect_args,
    future=True,
)

if settings.resolved_db_url.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.execute("PRAGMA secure_delete=ON;")
        cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def _ensure_sqlite_migrations() -> None:
    """In-place additive column migrations preserving existing v1/v2.0 SQLite databases."""
    if not settings.resolved_db_url.startswith("sqlite"):
        return
    migrations: list[tuple[str, str, str]] = [
        ("projects", "default_secret_scanner", "VARCHAR(32) NOT NULL DEFAULT 'auto'"),
        ("projects", "smoke_test_cmd", "TEXT NOT NULL DEFAULT ''"),
        ("release_runs", "secret_scanner", "VARCHAR(32) NOT NULL DEFAULT 'auto'"),
        ("release_runs", "audit_scope", "VARCHAR(16) NOT NULL DEFAULT 'full'"),
        ("release_runs", "base_ref", "VARCHAR(128) NOT NULL DEFAULT ''"),
        ("release_runs", "max_budget_usd", "REAL NOT NULL DEFAULT 1.5"),
        ("release_runs", "smoke_test_cmd", "TEXT NOT NULL DEFAULT ''"),
    ]
    with engine.begin() as conn:
        for table, column, col_def in migrations:
            cols = {
                row[1]
                for row in conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
            }
            if cols and column not in cols:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}"))


def init_db() -> None:
    from app import models  # noqa: F401
    from app.services.vault import migrate_plaintext_app_settings

    Base.metadata.create_all(bind=engine)
    _ensure_sqlite_migrations()
    with SessionLocal() as db:
        migrate_plaintext_app_settings(db)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
