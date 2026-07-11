"""Auth + rate-limit on /api/v1/diagnostics/forward (the box→central hop).

The forward intake was previously unauthenticated and unthrottled; these lock in the
2026-07-11 hardening: Bearer token (fail-closed when unconfigured) + per-install rate
limit. The autouse conftest fixture configures a token by default; tests that need the
unconfigured/absent cases override settings.FORWARD_INTAKE_TOKENS within the test.
"""
from __future__ import annotations

import pytest

from tests.conftest import FORWARD_HEADERS, TEST_FORWARD_TOKEN

pytestmark = pytest.mark.asyncio

_REPORT = {"kind": "crash", "fingerprint": "auth-fp", "title": "boom", "severity": "s1_crash"}


async def test_good_token_accepted(client):
    c, _ = client
    r = await c.post("/api/v1/diagnostics/forward", json=_REPORT, headers=FORWARD_HEADERS)
    assert r.status_code == 202, r.text


async def test_missing_token_rejected(client):
    c, _ = client
    r = await c.post("/api/v1/diagnostics/forward", json=_REPORT)  # no header
    assert r.status_code == 401, r.text


async def test_bad_token_rejected(client):
    c, _ = client
    r = await c.post("/api/v1/diagnostics/forward", json=_REPORT,
                     headers={"Authorization": "Bearer wrong-token"})
    assert r.status_code == 401, r.text


async def test_unconfigured_is_fail_closed(client):
    """No token configured on the server ⇒ endpoint disabled (503), never open."""
    from app.config import settings
    prev = settings.FORWARD_INTAKE_TOKENS
    settings.FORWARD_INTAKE_TOKENS = ""
    try:
        c, _ = client
        r = await c.post("/api/v1/diagnostics/forward", json=_REPORT, headers=FORWARD_HEADERS)
        assert r.status_code == 503, r.text
    finally:
        settings.FORWARD_INTAKE_TOKENS = prev


async def test_token_rotation(client):
    """Comma-separated tokens both validate (rollover window)."""
    from app.config import settings
    prev = settings.FORWARD_INTAKE_TOKENS
    settings.FORWARD_INTAKE_TOKENS = f"old-tok,{TEST_FORWARD_TOKEN}"
    try:
        c, _ = client
        for tok in ("old-tok", TEST_FORWARD_TOKEN):
            r = await c.post("/api/v1/diagnostics/forward", json=_REPORT,
                             headers={"Authorization": f"Bearer {tok}"})
            assert r.status_code == 202, f"{tok}: {r.text}"
    finally:
        settings.FORWARD_INTAKE_TOKENS = prev


async def test_per_install_rate_limit(client, reset_rate_limit):
    """One install exceeding the budget gets 429; a different install is unaffected."""
    from app.config import settings
    prev = settings.INTAKE_RATE_PER_MIN
    settings.INTAKE_RATE_PER_MIN = 3
    try:
        c, _ = client
        codes = []
        for i in range(5):
            r = await c.post("/api/v1/diagnostics/forward",
                             json={**_REPORT, "fingerprint": f"rl-{i}", "install_id": "box-A"},
                             headers=FORWARD_HEADERS)
            codes.append(r.status_code)
        assert codes.count(202) == 3, codes
        assert codes.count(429) == 2, codes
        # a different install is not throttled by box-A's budget
        r = await c.post("/api/v1/diagnostics/forward",
                         json={**_REPORT, "fingerprint": "rl-b", "install_id": "box-B"},
                         headers=FORWARD_HEADERS)
        assert r.status_code == 202, r.text
    finally:
        settings.INTAKE_RATE_PER_MIN = prev
