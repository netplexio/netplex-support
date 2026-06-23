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


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """Expose the session factory (lets tests swap the engine if needed)."""
    return SessionLocal


async def get_session():
    """FastAPI dependency yielding an AsyncSession."""
    async with SessionLocal() as session:
        yield session
