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
    """Clear the in-memory rate-limit state between tests.

    _hits moved from app.routers.diagnostics (a private per-module dict) to the
    shared app.ratelimit module 2026-07-27, when app.routers.licensing started using
    the SAME primitive for /license/verify - see app/ratelimit.py."""
    from app import ratelimit

    ratelimit._hits.clear()
    yield
    ratelimit._hits.clear()


# /diagnostics/forward is authenticated (fail-closed). Configure a known token for
# every test by default so existing forward tests work; auth tests override it.
TEST_FORWARD_TOKEN = "test-fwd-token"
FORWARD_HEADERS = {"Authorization": f"Bearer {TEST_FORWARD_TOKEN}"}

# /tickets/admin/* is operator-only (fail-closed on ADMIN_API_TOKENS). Same pattern.
TEST_ADMIN_TOKEN = "test-admin-token"
ADMIN_HEADERS = {"Authorization": f"Bearer {TEST_ADMIN_TOKEN}"}

# /diagnostics/email is authenticated (fail-closed) — P3 tickets chain, 2026-07-28.
# Same pattern as FORWARD_INTAKE_TOKENS/ADMIN_API_TOKENS above.
TEST_EMAIL_TOKEN = "test-email-token"
EMAIL_HEADERS = {"Authorization": f"Bearer {TEST_EMAIL_TOKEN}"}


@pytest.fixture(autouse=True)
def _configure_forward_token():
    from app.config import settings

    prev = settings.FORWARD_INTAKE_TOKENS
    settings.FORWARD_INTAKE_TOKENS = TEST_FORWARD_TOKEN
    yield
    settings.FORWARD_INTAKE_TOKENS = prev


@pytest.fixture(autouse=True)
def _configure_admin_token():
    from app.config import settings

    prev = settings.ADMIN_API_TOKENS
    settings.ADMIN_API_TOKENS = TEST_ADMIN_TOKEN
    yield
    settings.ADMIN_API_TOKENS = prev


@pytest.fixture(autouse=True)
def _configure_email_token():
    from app.config import settings

    prev = settings.EMAIL_INTAKE_SECRETS
    settings.EMAIL_INTAKE_SECRETS = TEST_EMAIL_TOKEN
    yield
    settings.EMAIL_INTAKE_SECRETS = prev
