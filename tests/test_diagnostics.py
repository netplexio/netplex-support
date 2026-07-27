"""Diagnostics intake: forward dedupe, web intake + rate limit."""
from __future__ import annotations

import base64
import hashlib
import json
import time

import pytest
from nacl.signing import SigningKey

from app.crypto.signing import sign_manifest
from tests.conftest import ADMIN_HEADERS, FORWARD_HEADERS

pytestmark = pytest.mark.asyncio


async def test_forward_creates_ticket(client):
    """A self-asserted reporter_tier with NO license_token must NOT be trusted
    (adversarial sweep 2026-07-27, P2 fix) - it floors to 'associate' regardless of
    what the caller claims, closing the priority_score-inflation queue-jump. See
    test_forward_with_verified_license_token_elevates_tier below for the positive
    path (a GENUINE token legitimately elevates the tier)."""
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
    # s1_crash(16) × occ(1) × associate(1) = 16 - the self-asserted "architect" claim
    # (which would have been 16×1×4=64) is NOT trusted without a verified token.
    assert body["priority_score"] == 16, (
        f"REGRESSION: a self-asserted reporter_tier with no license_token was "
        f"trusted (priority_score={body['priority_score']}, expected 16) - the "
        f"queue-jump the 2026-07-27 fix closed is back"
    )


async def test_forward_with_verified_license_token_elevates_tier(client, monkeypatch):
    """The POSITIVE path: a genuine, cryptographically-verified license_token DOES
    correctly elevate reporter_tier (and populates license_id_hash) - proves the fix
    isn't just "always floor to associate", it's "only trust a VERIFIED claim"."""
    from app.config import settings
    sk = SigningKey.generate()
    pub_b64 = base64.b64encode(bytes(sk.verify_key)).decode("ascii")
    prev_key = settings.LICENSE_PUBLIC_KEY
    settings.LICENSE_PUBLIC_KEY = pub_b64
    try:
        claims = {"tier": "architect", "expires_at": int(time.time()) + 3600, "customer_ref": "cust-1"}
        token = json.dumps(sign_manifest(claims, bytes(sk)))

        c, _ = client
        r = await c.post("/api/v1/diagnostics/forward", json={
            "kind": "crash", "fingerprint": "fp-verified", "title": "boom",
            "severity": "s1_crash", "reporter_tier": "associate",  # self-assertion ignored either way
            "license_token": token,
        }, headers=FORWARD_HEADERS)
        assert r.status_code == 202
        body = r.json()
        # s1_crash(16) × occ(1) × architect(4) = 64 - the VERIFIED tier from the token,
        # not the self-asserted "associate" in the request body.
        assert body["priority_score"] == 64, (
            f"a verified license_token should elevate priority_score to 64, got "
            f"{body['priority_score']}"
        )

        got = await c.get(f"/api/v1/tickets/{body['ticket_id']}", headers=ADMIN_HEADERS)
        assert got.json()["reporter_tier"] == "architect"
    finally:
        settings.LICENSE_PUBLIC_KEY = prev_key


async def test_forward_with_invalid_license_token_does_not_elevate_tier(client):
    """A malformed/unsigned/tampered license_token must NOT elevate the tier either -
    fail closed, not fail open."""
    c, _ = client
    r = await c.post("/api/v1/diagnostics/forward", json={
        "fingerprint": "fp-bad-token", "title": "boom", "severity": "s1_crash",
        "reporter_tier": "master", "license_token": "not-even-json",
    }, headers=FORWARD_HEADERS)
    assert r.status_code == 202
    # s1_crash(16) × occ(1) × associate(1) = 16, NOT master's 16×1×5=80
    assert r.json()["priority_score"] == 16


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
