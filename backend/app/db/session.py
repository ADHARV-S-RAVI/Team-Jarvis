"""SQLAlchemy 2 database engine, SQLite PRAGMAs, and session management."""

from __future__ import annotations

from collections.abc import Generator
from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from backend.app.config import get_settings


def _configure_sqlite_pragmas(dbapi_connection: Any, _connection_record: Any) -> None:
    """Enforce SQLite foreign keys, busy timeout, and WAL mode where supported."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA busy_timeout=5000")
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
    except Exception:
        # In-memory SQLite does not use WAL; ignore safely.
        pass
    cursor.close()


def create_db_engine(database_url: str | None = None) -> Engine:
    """Create a configured SQLAlchemy engine for SQLite or PostgreSQL."""
    url = database_url or get_settings().database_url
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://") :]
    connect_args: dict[str, Any] = {}
    if url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    engine = create_engine(url, connect_args=connect_args, future=True)
    if url.startswith("sqlite"):
        event.listen(engine, "connect", _configure_sqlite_pragmas)
    return engine


_engine = create_db_engine()
SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False, expire_on_commit=False)


def ensure_database_schema(engine: Engine | None = None) -> None:
    """Create missing database tables idempotently (essential for serverless cold starts)."""
    from backend.app.db.models import Base

    Base.metadata.create_all(bind=engine or _engine)


def get_engine() -> Engine:
    """Return the default SQLAlchemy engine."""
    return _engine


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a transactional SQLAlchemy session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
