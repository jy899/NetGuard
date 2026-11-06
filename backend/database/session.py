"""SQLAlchemy engine, session factory and declarative base."""
from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from backend.core.config import DATA_DIR, get_settings


class Base(DeclarativeBase):
    pass


def build_engine(database_url: str) -> Engine:
    connect_args = {}
    if database_url.startswith("sqlite"):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        connect_args["check_same_thread"] = False
    engine = create_engine(database_url, connect_args=connect_args)

    if engine.dialect.name == "sqlite":
        # SQLite ignores foreign keys unless explicitly enabled per connection.
        @event.listens_for(engine, "connect")
        def _enable_foreign_keys(dbapi_connection, _record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        @event.listens_for(engine, "checkout")
        def _keep_foreign_keys(dbapi_connection, _record, _proxy):
            # A pooled connection must never be handed out with enforcement off (a migration may have turned it
            # off); otherwise deleting a network would leave its devices behind for the next network to reuse.
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


engine = build_engine(get_settings().database_url)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding one session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
