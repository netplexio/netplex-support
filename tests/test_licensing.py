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
