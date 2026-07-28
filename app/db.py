"""Async DB engine + session for netplex-support.

SQLite dev fallback by default (DATABASE_URL=sqlite+aiosqlite:///./netplex_support.db); a real
deployment points DATABASE_URL at async Postgres. init_db() creates tables on app startup.
"""
from __future__ import annotations

import os

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///./netplex_support.db")


class Base(DeclarativeBase):
    """SQLAlchemy 2.x declarative base."""


engine = create_async_engine(DATABASE_URL, future=True)
SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db() -> None:
    """Create all tables (idempotent). Called from the FastAPI lifespan on startup."""
    # import models so they register on Base.metadata before create_all
    from app import models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_add_missing_columns)


# Lightweight, additive-only "migration" for columns added to an EXISTING table after
# it was first created. There is no Alembic in this repo (init_db has only ever done
# create_all, which creates missing TABLES but never retrofits a COLUMN onto a table
# that already exists) - without this, a box that already has a live `tickets` table
# from before the §5.3 `attachments`/`diagnostic_json` columns were added would 500 on
# every write the moment code that references them ran, since create_all is a silent
# no-op for a table SQLAlchemy already sees as present. ALTER TABLE ... ADD COLUMN is
# additive and safe (no data loss, no lock beyond the DDL itself, both SQLite via
# aiosqlite and Postgres support this exact statement shape); a column that already
# exists raises, which is caught and ignored so this stays idempotent across restarts.
_ADDITIVE_COLUMNS = {
    "tickets": [
        ("attachments", "TEXT"),
        ("diagnostic_json", "TEXT"),
    ],
}


def _add_missing_columns(sync_conn) -> None:
    from sqlalchemy import inspect, text

    inspector = inspect(sync_conn)
    existing_tables = set(inspector.get_table_names())
    for table, columns in _ADDITIVE_COLUMNS.items():
        if table not in existing_tables:
            continue  # create_all above just made it WITH these columns already
        existing_cols = {c["name"] for c in inspector.get_columns(table)}
        for name, coltype in columns:
            if name in existing_cols:
                continue
            try:
                sync_conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {coltype}"))
            except Exception:  # noqa: BLE001 - additive migration must never block startup
                pass


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """Expose the session factory (lets tests swap the engine if needed)."""
    return SessionLocal


async def get_session():
    """FastAPI dependency yielding an AsyncSession."""
    async with SessionLocal() as session:
        yield session
