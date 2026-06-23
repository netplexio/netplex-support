"""Shared test fixtures: an isolated in-memory SQLite engine + an httpx ASGI client.

Each test module gets its own engine (shared in-memory connection pool) so tickets persist across
requests within a test but never leak between modules. We override app.db.get_session.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app import db as app_db
from app.db import Base, get_session
from app.main import app


@pytest_asyncio.fixture
async def engine():
    eng = create_async_engine(
        "sqlite+aiosqlite://",  # in-memory
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    import app.models  # noqa: F401 — register tables

    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def client(engine):
    TestSession = async_sessionmaker(engine, expire_on_commit=False)

    async def _override():
        async with TestSession() as session:
            yield session

    app.dependency_overrides[get_session] = _override
    # disable real init_db lifespan (it uses the prod engine); we already made tables
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c, TestSession
    app.dependency_overrides.clear()


@pytest.fixture
def reset_rate_limit():
    """Clear the in-memory diagnostics rate-limit state between tests."""
    from app.routers import diagnostics

    diagnostics._hits.clear()
    yield
    diagnostics._hits.clear()
