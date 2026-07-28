"""Email intake (P3 tickets chain, 2026-07-28) — replaces the previous dead stub
(ingest_email_stub raised NotImplementedError and was never even registered as a
route). Also covers the CORS wiring added so netplex.io's marketing site can call
the public /diagnostics/web intake cross-origin (item 3 of the same chain).

Paired API+UI case: the UI half lives in netplex-verification's Playwright spec
(tests/playwright/specs/tickets-chain-52.spec.ts), which drives netplex.io's real
support.html form and forwards its network call to a REAL local instance of this
same app (not a canned mock) — this file is the direct, real-app-code half.
"""
from __future__ import annotations

import pytest

from tests.conftest import EMAIL_HEADERS

pytestmark = pytest.mark.asyncio


async def test_email_intake_disabled_when_no_secret_configured(client):
    """Fail-CLOSED (rule: never an open unauthenticated ingest): with
    EMAIL_INTAKE_SECRETS unset, the route must refuse everything with 503, exactly
    like /diagnostics/forward's FORWARD_INTAKE_TOKENS posture."""
    from app.config import settings

    prev = settings.EMAIL_INTAKE_SECRETS
    settings.EMAIL_INTAKE_SECRETS = ""
    try:
        c, _ = client
        r = await c.post("/api/v1/diagnostics/email", json={
            "from_email": "someone@example.com", "subject": "hi", "body": "help",
        })
        assert r.status_code == 503
    finally:
        settings.EMAIL_INTAKE_SECRETS = prev


async def test_email_intake_rejects_missing_or_wrong_token(client):
    c, _ = client
    body = {"from_email": "someone@example.com", "subject": "hi", "body": "help"}

    r = await c.post("/api/v1/diagnostics/email", json=body)  # no Authorization header
    assert r.status_code == 401

    r = await c.post("/api/v1/diagnostics/email", json=body,
                      headers={"Authorization": "Bearer wrong-token"})
    assert r.status_code == 401


async def test_email_intake_creates_real_ticket(client):
    """The real (previously impossible) path: a correctly-authenticated inbound-mail
    payload creates a genuine ticket, source='email' — the value models.py has always
    documented ("web|email|forward|app") but which had zero callers before this fix."""
    c, TestSession = client
    r = await c.post("/api/v1/diagnostics/email", json={
        "from_email": "customer@example.com",
        "subject": "CSR1000v boot loop after import",
        "body": "It boots into a loop after I import the qcow2.",
    }, headers=EMAIL_HEADERS)
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["accepted"] is True
    assert body["ticket_id"].startswith("NPX-")

    from sqlalchemy import select
    from app.models import Ticket

    async with TestSession() as session:
        t = (await session.execute(select(Ticket).where(Ticket.id == body["ticket_id"]))).scalar_one()
        assert t.source == "email"
        assert t.contact == "customer@example.com"
        assert t.identified is True
        assert t.title == "CSR1000v boot loop after import"


async def test_email_intake_rate_limited_per_ip(client, reset_rate_limit):
    """A misconfigured forwarding worker retrying a bounce shouldn't be able to flood
    ticket creation just because it holds a valid secret — same IP-based ceiling as
    /diagnostics/web (WEB_INTAKE_RATE_PER_MIN)."""
    from app.config import settings

    prev = settings.WEB_INTAKE_RATE_PER_MIN
    settings.WEB_INTAKE_RATE_PER_MIN = 2
    try:
        c, _ = client
        body = {"from_email": "a@example.com", "subject": "s", "body": "b"}
        statuses = []
        for _ in range(4):
            r = await c.post("/api/v1/diagnostics/email", json=body, headers=EMAIL_HEADERS)
            statuses.append(r.status_code)
        assert 429 in statuses, f"expected a 429 among {statuses} once the per-IP budget is exhausted"
    finally:
        settings.WEB_INTAKE_RATE_PER_MIN = prev


# ── CORS (item 3: netplex.io's support form must be able to call /diagnostics/web) ──

async def test_web_intake_cors_allows_netplexio_origin(client):
    """A browser preflight from the real netplex.io origin must be allowed — without
    this, the marketing site's fetch() to this endpoint is silently blocked by the
    BROWSER regardless of the route's own auth/rate-limit posture, leaving only a
    bare mailto: link with no ticket tracking (the exact gap this chain closes)."""
    c, _ = client
    r = await c.options("/api/v1/diagnostics/web", headers={
        "Origin": "https://netplex.io",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type",
    })
    assert r.headers.get("access-control-allow-origin") == "https://netplex.io", (
        f"netplex.io's own marketing-site origin is not CORS-allowed on the public "
        f"intake route (headers={dict(r.headers)})"
    )


async def test_web_intake_cors_rejects_unrelated_origin(client):
    """CORS is scoped to REAL, named origins, not '*' — a bearer-gated route staying
    unreachable to a browser with no token is the real protection; this just confirms
    the origin allow-list itself is not accidentally wide open."""
    c, _ = client
    r = await c.options("/api/v1/diagnostics/web", headers={
        "Origin": "https://evil.example.com",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type",
    })
    assert r.headers.get("access-control-allow-origin") is None
