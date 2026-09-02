"""W15.4 / W15.8 - /api/v1/tickets/admin/queue was an unauthenticated `TODO: admin auth`
that handed the full triage queue (every ticket, reporter tiers, contacts) to anyone.
These tests fail without the fail-closed admin bearer gate.
"""
from __future__ import annotations

import pytest

from tests.conftest import ADMIN_HEADERS, TEST_ADMIN_TOKEN

pytestmark = pytest.mark.asyncio

_URL = "/api/v1/tickets/admin/queue"


async def test_missing_token_rejected(client):
    c, _ = client
    r = await c.get(_URL)  # no Authorization header
    assert r.status_code == 401, r.text


async def test_bad_token_rejected(client):
    c, _ = client
    r = await c.get(_URL, headers={"Authorization": "Bearer wrong-token"})
    assert r.status_code == 401, r.text


async def test_good_token_accepted(client):
    c, _ = client
    r = await c.get(_URL, headers=ADMIN_HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert "tickets" in body and "count" in body


async def test_unconfigured_is_fail_closed(client):
    """No admin token configured on the server ⇒ endpoint disabled (503), never open."""
    from app.config import settings

    prev = settings.ADMIN_API_TOKENS
    settings.ADMIN_API_TOKENS = ""
    try:
        c, _ = client
        r = await c.get(_URL, headers=ADMIN_HEADERS)
        assert r.status_code == 503, r.text
    finally:
        settings.ADMIN_API_TOKENS = prev


async def test_token_rotation(client):
    """Comma-separated admin tokens both validate (rollover window)."""
    from app.config import settings

    prev = settings.ADMIN_API_TOKENS
    settings.ADMIN_API_TOKENS = f"old-admin,{TEST_ADMIN_TOKEN}"
    try:
        c, _ = client
        for tok in ("old-admin", TEST_ADMIN_TOKEN):
            r = await c.get(_URL, headers={"Authorization": f"Bearer {tok}"})
            assert r.status_code == 200, f"{tok}: {r.text}"
    finally:
        settings.ADMIN_API_TOKENS = prev
