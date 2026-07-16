"""Diagnostics intake: forward dedupe, web intake + rate limit."""
from __future__ import annotations

import pytest
from tests.conftest import ADMIN_HEADERS, FORWARD_HEADERS

pytestmark = pytest.mark.asyncio


async def test_forward_creates_ticket(client):
    c, _ = client
    r = await c.post("/api/v1/diagnostics/forward", json={
        "kind": "crash", "fingerprint": "fp-abc", "title": "boom",
        "severity": "s1_crash", "reporter_tier": "architect",
    }, headers=FORWARD_HEADERS)
    assert r.status_code == 202
    body = r.json()
    assert body["accepted"] is True
    assert body["ticket_id"].startswith("NPX-")
    assert body["occurrences"] == 1
    # s1_crash(16) × occ(1) × architect(4) = 64
    assert body["priority_score"] == 64


async def test_forward_same_fingerprint_dedupes(client):
    c, _ = client
    r1 = await c.post("/api/v1/diagnostics/forward", json={
        "fingerprint": "dup-1", "title": "x", "severity": "s2_broken",
    }, headers=FORWARD_HEADERS)
    r2 = await c.post("/api/v1/diagnostics/forward", json={
        "fingerprint": "dup-1", "title": "x again", "severity": "s2_broken",
    }, headers=FORWARD_HEADERS)
    assert r1.json()["ticket_id"] == r2.json()["ticket_id"]
    assert r2.json()["occurrences"] == 2

    # only one row in the admin queue for that fingerprint
    q = await c.get("/api/v1/tickets/admin/queue", headers=ADMIN_HEADERS)
    ids = [t["id"] for t in q.json()["tickets"]]
    assert ids.count(r1.json()["ticket_id"]) == 1
    assert q.json()["count"] == 1


async def test_web_intake_creates_ticket(client, reset_rate_limit):
    c, _ = client
    r = await c.post("/api/v1/diagnostics/web", json={"title": "site bug", "body": "hi"})
    assert r.status_code == 202
    tid = r.json()["ticket_id"]
    got = await c.get(f"/api/v1/tickets/{tid}")
    assert got.status_code == 200
    assert got.json()["source"] == "web"


async def test_web_intake_rate_limited(client, reset_rate_limit):
    c, _ = client
    codes = []
    for i in range(12):
        r = await c.post("/api/v1/diagnostics/web", json={"title": f"spam {i}"})
        codes.append(r.status_code)
    assert codes.count(202) == 10  # limit is 10/min
    assert 429 in codes
