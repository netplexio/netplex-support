"""License verify: valid / tampered / expired / untrusted-key.

Uses EPHEMERAL keypairs generated in-test (never committed). Signs with the repo's
app.crypto.signing.sign_manifest and verifies via the /license/verify endpoint by injecting a
TrustStore built from the ephemeral public key.
"""
from __future__ import annotations

import base64
import json
import time

import pytest
from nacl.signing import SigningKey

from app.crypto.signing import TrustStore, sign_manifest
from app.routers.licensing import _verify_token

pytestmark = pytest.mark.asyncio


def _keypair():
    sk = SigningKey.generate()
    pub_b64 = base64.b64encode(bytes(sk.verify_key)).decode("ascii")
    return sk, pub_b64


def _trust_for(pub_b64: str) -> TrustStore:
    return TrustStore.from_keys([{"public_key": pub_b64, "status": "active"}])


def _make_token(sk, *, tier="architect", expires_in=3600, customer_ref="cust-1"):
    claims = {
        "tier": tier,
        "expires_at": int(time.time()) + expires_in,
        "customer_ref": customer_ref,
    }
    signed = sign_manifest(claims, bytes(sk))
    return json.dumps(signed)


async def test_valid_token():
    sk, pub = _keypair()
    res = _verify_token(_make_token(sk), _trust_for(pub))
    assert res.valid is True
    assert res.tier == "architect"
    assert res.expires_at is not None


async def test_tampered_token_invalid():
    sk, pub = _keypair()
    signed = sign_manifest(
        {"tier": "associate", "expires_at": int(time.time()) + 3600, "customer_ref": "c"},
        bytes(sk),
    )
    signed["tier"] = "master"  # tamper after signing
    res = _verify_token(json.dumps(signed), _trust_for(pub))
    assert res.valid is False
    assert res.reason == "bad-signature"


async def test_expired_token_invalid():
    sk, pub = _keypair()
    res = _verify_token(_make_token(sk, expires_in=-10), _trust_for(pub))
    assert res.valid is False
    assert res.reason == "expired"


async def test_untrusted_key_invalid():
    sk_signer, _ = _keypair()
    _, pub_other = _keypair()  # trust store holds a DIFFERENT key
    res = _verify_token(_make_token(sk_signer), _trust_for(pub_other))
    assert res.valid is False
    assert res.reason == "unknown-key"


async def test_issue_still_gated(client):
    c, _ = client
    r = await c.post("/api/v1/license/issue", json={"tier": "architect", "customer_ref": "c"})
    assert r.status_code == 501


# ── SECURITY regressions (adversarial sweep 2026-07-27, P1) ────────────────────────
# /license/verify previously had NO auth, NO rate limit, and an unbounded `token`
# field - an anonymous caller could push arbitrary amounts of data through
# json.loads() as fast as the network allowed.

async def test_oversized_token_rejected(client):
    """VerifyRequest.token now has max_length=4096 (matches ForwardedReport.
    license_token's cap for the same kind of signed-JSON-token payload) - previously
    unbounded, unlike every other field in this codebase."""
    c, _ = client
    r = await c.post("/api/v1/license/verify", json={"token": "x" * 5000})
    assert r.status_code == 422, (
        f"REGRESSION: an oversized (5000-char) token was accepted (status "
        f"{r.status_code}) - the max_length=4096 cap is gone"
    )


async def test_verify_is_rate_limited(client, reset_rate_limit):
    """A caller hammering /verify past LICENSE_VERIFY_RATE_PER_MIN gets 429 - this
    endpoint has no auth by design (public-key verification), so the rate limit is
    its ONLY anti-abuse control. It had none at all before this fix."""
    from app.config import settings
    prev = settings.LICENSE_VERIFY_RATE_PER_MIN
    settings.LICENSE_VERIFY_RATE_PER_MIN = 3
    try:
        c, _ = client
        codes = []
        for _ in range(5):
            r = await c.post("/api/v1/license/verify", json={"token": "not-even-json"})
            codes.append(r.status_code)
        # Every call returns 200 with valid=False for a malformed token (that's the
        # correct, non-throttled shape of a bad token) UNTIL the rate limit kicks in.
        assert 429 in codes, f"REGRESSION: no 429 seen after exceeding the budget: {codes}"
        assert codes.count(429) >= 2, codes
    finally:
        settings.LICENSE_VERIFY_RATE_PER_MIN = prev


async def test_body_size_limit_enforced_without_content_length(client):
    """SECURITY regression: the global body-size guard (app/main.py's
    _BodySizeLimitASGI) must reject an oversized body even with NO Content-Length
    header (chunked/streamed) - the exact bypass the audit found, live-verified to
    have let an unauthenticated caller push a multi-MB body through /license/verify
    with zero credentials before this fix. Send a generator as `content=` so httpx
    cannot compute Content-Length up front (mirrors real chunked transfer-encoding)."""
    async def _chunks():
        yield b'{"token": "' + b"x" * (128 * 1024) + b'"}'

    c, _ = client
    r = await c.post("/api/v1/license/verify", content=_chunks())
    assert r.status_code == 413, (
        f"REGRESSION: a body with no Content-Length header bypassed the size guard "
        f"(got {r.status_code}, expected 413)"
    )
