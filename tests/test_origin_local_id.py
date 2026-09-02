"""T13a (2026-08-30 war-room) - a forwarded report now carries the box's own local
ticket id (`origin_local_id`) through to the persisted row, and it's resolvable via a
dedicated admin lookup, closing the old "only fingerprint + install_id" ambiguity.

API-only by design - no UI surface. This is a backend ticket-forwarding internal
(one server persisting a field on another server's forwarded payload); there is no
button or page a person clicks to exercise it. Per this org's testing rule, a UI
Playwright case is required only when the touched code has a UI surface - this repo's
diagnostics/tickets routers don't.
"""
from __future__ import annotations

import pytest
from tests.conftest import ADMIN_HEADERS, FORWARD_HEADERS

pytestmark = pytest.mark.asyncio


async def test_forward_persists_origin_local_id(client):
    c, _ = client
    r = await c.post("/api/v1/diagnostics/forward", json={
        "kind": "crash", "fingerprint": "fp-origin-1", "title": "boom",
        "severity": "s1_crash", "install_id": "install-42",
        "origin_local_id": "NPX-DEADBEEF0001",
    }, headers=FORWARD_HEADERS)
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["origin_local_id"] == "NPX-DEADBEEF0001"
    tid = body["ticket_id"]

    got = await c.get(f"/api/v1/tickets/{tid}")
    assert got.status_code == 200
    assert got.json()["origin_local_id"] == "NPX-DEADBEEF0001"


async def test_forward_without_origin_local_id_stays_none(client):
    """Older/unpatched boxes that don't send the field yet must not error - the field
    is optional, and its absence just means no origin_local_id lookup is possible for
    that row (same as before this fix, not a regression)."""
    c, _ = client
    r = await c.post("/api/v1/diagnostics/forward", json={
        "kind": "crash", "fingerprint": "fp-origin-2", "title": "boom",
        "severity": "s1_crash",
    }, headers=FORWARD_HEADERS)
    assert r.status_code == 202, r.text
    assert r.json()["origin_local_id"] is None


async def test_lookup_by_origin_local_id_resolves_ambiguous_fingerprint(client):
    """The actual bug this closes: one box (one install_id) files TWO DIFFERENT
    reports (different fingerprints, so no dedupe merges them) - before T13a, a
    forwarded report could only be resolved back to the reporting box via
    (fingerprint, install_id), so distinguishing "which of this box's several reports
    is this" required scanning every ticket for that install_id by hand. Now the
    box's own local id resolves directly and unambiguously to the one row."""
    c, _ = client
    r1 = await c.post("/api/v1/diagnostics/forward", json={
        "kind": "crash", "fingerprint": "fp-box9-a", "title": "first crash",
        "severity": "s1_crash", "install_id": "box-9",
        "origin_local_id": "NPX-BOX9REPORTA",
    }, headers=FORWARD_HEADERS)
    r2 = await c.post("/api/v1/diagnostics/forward", json={
        "kind": "bug", "fingerprint": "fp-box9-b", "title": "second, unrelated bug",
        "severity": "s3_degraded", "install_id": "box-9",
        "origin_local_id": "NPX-BOX9REPORTB",
    }, headers=FORWARD_HEADERS)
    tid1, tid2 = r1.json()["ticket_id"], r2.json()["ticket_id"]
    assert tid1 != tid2

    got_a = await c.get("/api/v1/tickets/admin/by-origin/NPX-BOX9REPORTA", headers=ADMIN_HEADERS)
    assert got_a.status_code == 200, got_a.text
    assert got_a.json()["id"] == tid1
    assert got_a.json()["title"] == "first crash"

    got_b = await c.get("/api/v1/tickets/admin/by-origin/NPX-BOX9REPORTB", headers=ADMIN_HEADERS)
    assert got_b.status_code == 200, got_b.text
    assert got_b.json()["id"] == tid2
    assert got_b.json()["title"] == "second, unrelated bug"


async def test_lookup_by_origin_local_id_requires_admin_auth(client):
    c, _ = client
    r = await c.get("/api/v1/tickets/admin/by-origin/NPX-WHATEVER")
    assert r.status_code == 401


async def test_lookup_by_unknown_origin_local_id_404s_cleanly(client):
    c, _ = client
    r = await c.get("/api/v1/tickets/admin/by-origin/NPX-NEVERSEEN", headers=ADMIN_HEADERS)
    assert r.status_code == 404
