"""License token registration pipeline (app/routers/licensing.py's /register + /registered).

Same offline-sign-then-upload shape as tests/test_releases.py, applied to license tokens
(mirroring tools/mint_license.py's real output shape). /issue stays permanently 501
(tests/test_licensing.py::test_issue_still_gated already covers that; this file does not
duplicate it, only re-affirms /publish-equivalent behaviour isn't accidentally relaxed).
"""
from __future__ import annotations

import base64
import copy
import json
import time

import pytest
from nacl.signing import SigningKey

from app.crypto.signing import key_id_for, sign_manifest
from tests.conftest import ADMIN_HEADERS

pytestmark = pytest.mark.asyncio

_REGISTER_URL = "/api/v1/license/register"
_REGISTERED_URL = "/api/v1/license/registered/{customer_ref}"
_ISSUE_URL = "/api/v1/license/issue"


def _keypair():
    sk = SigningKey.generate()
    pub_b64 = base64.b64encode(bytes(sk.verify_key)).decode("ascii")
    return sk, pub_b64


def _claims(*, tier="architect", customer_ref="acme-corp", expires_in=3650 * 86400):
    return {
        "tier": tier,
        "customer_ref": customer_ref,
        "buyer_id": customer_ref,
        "license_id": f"lic-{customer_ref}",
        "fingerprint": "any",
        "expires_at": int(time.time()) + expires_in,
    }


def _mint(sk, **claim_kwargs) -> str:
    """Mirrors tools/mint_license.py's output shape: a signed dict, JSON-stringified."""
    signed = sign_manifest(_claims(**claim_kwargs), bytes(sk))
    return json.dumps(signed)


@pytest.fixture(autouse=True)
def _configure_license_key():
    from app.config import settings

    sk, pub_b64 = _keypair()
    prev_key = settings.LICENSE_PUBLIC_KEY
    prev_json = settings.LICENSE_TRUST_STORE_JSON
    settings.LICENSE_PUBLIC_KEY = pub_b64
    settings.LICENSE_TRUST_STORE_JSON = ""
    try:
        yield sk, pub_b64
    finally:
        settings.LICENSE_PUBLIC_KEY = prev_key
        settings.LICENSE_TRUST_STORE_JSON = prev_json


async def test_register_requires_admin_auth(client, _configure_license_key):
    sk, _ = _configure_license_key
    token = _mint(sk)
    c, _ = client
    r = await c.post(_REGISTER_URL, json={"token": token})  # no Authorization header
    assert r.status_code == 401, r.text


async def test_valid_token_registered_then_looked_up(client, _configure_license_key):
    sk, pub_b64 = _configure_license_key
    token = _mint(sk, tier="enterprise", customer_ref="globex")

    c, _ = client
    r = await c.post(_REGISTER_URL, json={"token": token}, headers=ADMIN_HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["accepted"] is True
    assert body["customer_ref"] == "globex"
    assert body["tier"] == "enterprise"
    assert body["key_id"] == key_id_for(bytes(sk.verify_key))

    look = await c.get(_REGISTERED_URL.format(customer_ref="globex"), headers=ADMIN_HEADERS)
    assert look.status_code == 200, look.text
    got = look.json()
    assert got["tier"] == "enterprise"
    assert got["customer_ref"] == "globex"
    assert json.loads(got["token"])["signature"]["sig"] == json.loads(token)["signature"]["sig"]


async def test_registered_lookup_requires_admin_auth(client, _configure_license_key):
    c, _ = client
    r = await c.get(_REGISTERED_URL.format(customer_ref="globex"))
    assert r.status_code == 401, r.text


async def test_registered_lookup_404_when_never_registered(client, _configure_license_key):
    c, _ = client
    r = await c.get(_REGISTERED_URL.format(customer_ref="nobody-here"), headers=ADMIN_HEADERS)
    assert r.status_code == 404, r.text


async def test_re_registering_updates_latest_lookup(client, _configure_license_key):
    sk, _ = _configure_license_key
    c, _ = client
    old = _mint(sk, tier="professional", customer_ref="acme")
    new = _mint(sk, tier="enterprise", customer_ref="acme")

    r1 = await c.post(_REGISTER_URL, json={"token": old}, headers=ADMIN_HEADERS)
    assert r1.status_code == 200, r1.text
    r2 = await c.post(_REGISTER_URL, json={"token": new}, headers=ADMIN_HEADERS)
    assert r2.status_code == 200, r2.text

    look = await c.get(_REGISTERED_URL.format(customer_ref="acme"), headers=ADMIN_HEADERS)
    assert look.json()["tier"] == "enterprise"


async def test_forged_token_rejected(client, _configure_license_key):
    sk, _ = _configure_license_key
    signed = json.loads(_mint(sk))
    tampered = copy.deepcopy(signed)
    tampered["tier"] = "master"  # tamper after signing
    c, _ = client
    r = await c.post(_REGISTER_URL, json={"token": json.dumps(tampered)}, headers=ADMIN_HEADERS)
    assert r.status_code == 400, r.text
    assert "bad-signature" in r.text


async def test_unknown_key_id_rejected(client):
    from app.config import settings

    other_sk, _ = _keypair()
    token = _mint(other_sk)  # signed by a key not in the trust store

    prev = settings.LICENSE_PUBLIC_KEY
    settings.LICENSE_PUBLIC_KEY = ""
    try:
        c, _ = client
        r = await c.post(_REGISTER_URL, json={"token": token}, headers=ADMIN_HEADERS)
    finally:
        settings.LICENSE_PUBLIC_KEY = prev
    assert r.status_code == 400, r.text
    assert "unknown-key" in r.text


async def test_revoked_key_id_rejected(client):
    from app.config import settings

    sk, pub_b64 = _keypair()
    token = _mint(sk)

    prev = settings.LICENSE_TRUST_STORE_JSON
    settings.LICENSE_TRUST_STORE_JSON = json.dumps([{"public_key": pub_b64, "status": "revoked"}])
    try:
        c, _ = client
        r = await c.post(_REGISTER_URL, json={"token": token}, headers=ADMIN_HEADERS)
    finally:
        settings.LICENSE_TRUST_STORE_JSON = prev
    assert r.status_code == 400, r.text
    assert "revoked-key" in r.text


async def test_expired_token_rejected(client, _configure_license_key):
    sk, _ = _configure_license_key
    token = _mint(sk, expires_in=-10)  # already expired
    c, _ = client
    r = await c.post(_REGISTER_URL, json={"token": token}, headers=ADMIN_HEADERS)
    assert r.status_code == 400, r.text
    assert "expired" in r.text


async def test_malformed_token_rejected(client, _configure_license_key):
    c, _ = client
    r = await c.post(_REGISTER_URL, json={"token": "not-json-at-all"}, headers=ADMIN_HEADERS)
    assert r.status_code == 400, r.text


async def test_issue_stays_permanently_gated(client):
    """/issue must remain 501 — server-side license minting is a permanent architectural
    boundary (key custody), not something /register relaxes."""
    c, _ = client
    r = await c.post(_ISSUE_URL, json={"tier": "architect", "customer_ref": "c"})
    assert r.status_code == 501, r.text
    assert "register" in r.text  # points callers at the real (offline-mint-then-register) path
