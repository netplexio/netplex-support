"""Ticket store: get_ticket + admin queue priority ordering."""
from __future__ import annotations

import pytest
from tests.conftest import ADMIN_HEADERS, FORWARD_HEADERS

pytestmark = pytest.mark.asyncio


async def test_get_ticket_roundtrip_and_404(client):
    c, _ = client
    r = await c.post("/api/v1/diagnostics/forward", json={"title": "t", "severity": "s2_broken"}, headers=FORWARD_HEADERS)
    tid = r.json()["ticket_id"]

    got = await c.get(f"/api/v1/tickets/{tid}")
    assert got.status_code == 200
    assert got.json()["id"] == tid

    missing = await c.get("/api/v1/tickets/SUP-NOPE00")
    assert missing.status_code == 404


async def test_claim_lookup_404_clean(client):
    c, _ = client
    r = await c.get("/api/v1/tickets/claim/whatever")
    assert r.status_code == 404


async def test_admin_queue_ordered_by_priority(client):
    """reporter_tier is self-asserted with no license_token in both cases below, so
    (2026-07-27 P2 fix) it floors to 'associate' regardless of the claimed value -
    the ordering guarantee this test proves comes from SEVERITY here, not tier. See
    test_diagnostics.py's test_forward_with_verified_license_token_elevates_tier for
    tier-driven priority (which requires a genuinely verified token)."""
    c, _ = client
    # low: s4 cosmetic, self-asserted "associate" → 2 × 1 × 1 = 2
    await c.post("/api/v1/diagnostics/forward", json={
        "fingerprint": "low", "title": "nit", "severity": "s4_cosmetic", "reporter_tier": "associate",
    }, headers=FORWARD_HEADERS)
    # high: s1 crash, self-asserted "architect" (NOT trusted without a verified
    # license_token - floors to associate too) → 16 × 1 × 1 = 16
    await c.post("/api/v1/diagnostics/forward", json={
        "fingerprint": "high", "title": "crash", "severity": "s1_crash", "reporter_tier": "architect",
    }, headers=FORWARD_HEADERS)
    q = await c.get("/api/v1/tickets/admin/queue", headers=ADMIN_HEADERS)
    tickets = q.json()["tickets"]
    assert q.json()["count"] == 2
    assert tickets[0]["title"] == "crash"
    assert tickets[0]["priority_score"] == 16
    assert tickets[-1]["title"] == "nit"
    assert tickets[0]["priority_score"] > tickets[-1]["priority_score"]
