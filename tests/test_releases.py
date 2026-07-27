"""Release manifest upload/serve pipeline (app/routers/releases.py).

Proves the receiving end of the offline-sign-then-upload workflow (docs/SECURITY-BLOCKERS.md
#3, docs/KEY-GENERATION-RUNBOOK.md §6): a manifest signed OFFLINE (here, with an EPHEMERAL
test keypair generated in-process — never committed, never the real production key) is
accepted only if its signature verifies, then served back by channel. Forged signatures,
unknown key_ids, and revoked key_ids are all rejected. Server-side signing (/publish) stays
permanently 501 — that invariant must never regress.
"""
from __future__ import annotations

import base64
import copy

import pytest
from nacl.signing import SigningKey

from app.crypto.signing import key_id_for, sign_manifest
from tests.conftest import ADMIN_HEADERS

pytestmark = pytest.mark.asyncio

_MANIFEST_URL = "/api/v1/releases/manifest/{channel}"
_UPLOAD_URL = "/api/v1/releases/upload"
_PUBLISH_URL = "/api/v1/releases/publish"


def _keypair():
    sk = SigningKey.generate()
    pub_b64 = base64.b64encode(bytes(sk.verify_key)).decode("ascii")
    return sk, pub_b64


def _manifest(channel="stable", version="1.0.0"):
    return {
        "version": version,
        "channel": channel,
        "services": {"api-gateway": "sha256:abc123"},
        "migrations": [],
    }


@pytest.fixture(autouse=True)
def _configure_signing_key():
    """Default: a single ephemeral signing key configured as the active trust store, so
    most tests don't need to fiddle with settings themselves. Tests that need a DIFFERENT
    trust-store shape (revoked key, unknown key, empty store) override it locally."""
    from app.config import settings

    sk, pub_b64 = _keypair()
    prev_key = settings.SIGNING_PUBLIC_KEY
    prev_json = settings.SIGNING_TRUST_STORE_JSON
    settings.SIGNING_PUBLIC_KEY = pub_b64
    settings.SIGNING_TRUST_STORE_JSON = ""
    try:
        yield sk, pub_b64
    finally:
        settings.SIGNING_PUBLIC_KEY = prev_key
        settings.SIGNING_TRUST_STORE_JSON = prev_json


async def test_manifest_404_before_any_upload(client, _configure_signing_key):
    c, _ = client
    r = await c.get(_MANIFEST_URL.format(channel="stable"))
    assert r.status_code == 404, r.text


async def test_unknown_channel_404s(client, _configure_signing_key):
    c, _ = client
    r = await c.get(_MANIFEST_URL.format(channel="nightly-bogus"))
    assert r.status_code == 404, r.text


async def test_upload_requires_admin_auth(client, _configure_signing_key):
    sk, _ = _configure_signing_key
    signed = sign_manifest(_manifest(), bytes(sk))
    c, _ = client
    r = await c.post(_UPLOAD_URL, json={"manifest": signed})  # no Authorization header
    assert r.status_code == 401, r.text


async def test_valid_manifest_accepted_and_then_served(client, _configure_signing_key):
    sk, pub_b64 = _configure_signing_key
    signed = sign_manifest(_manifest(channel="stable", version="2.4.0"), bytes(sk))

    c, _ = client
    up = await c.post(_UPLOAD_URL, json={"manifest": signed}, headers=ADMIN_HEADERS)
    assert up.status_code == 200, up.text
    body = up.json()
    assert body["accepted"] is True
    assert body["channel"] == "stable"
    assert body["version"] == "2.4.0"
    assert body["key_id"] == key_id_for(bytes(sk.verify_key))

    got = await c.get(_MANIFEST_URL.format(channel="stable"))
    assert got.status_code == 200, got.text
    served = got.json()
    assert served["version"] == "2.4.0"
    assert served["signature"]["key_id"] == key_id_for(bytes(sk.verify_key))
    assert served["signature"]["sig"] == signed["signature"]["sig"]

    # a different, never-uploaded channel is still 404
    other = await c.get(_MANIFEST_URL.format(channel="beta"))
    assert other.status_code == 404, other.text


async def test_second_upload_becomes_the_latest_served(client, _configure_signing_key):
    sk, _ = _configure_signing_key
    c, _ = client
    first = sign_manifest(_manifest(channel="canary", version="1.0.0"), bytes(sk))
    second = sign_manifest(_manifest(channel="canary", version="1.0.1"), bytes(sk))

    r1 = await c.post(_UPLOAD_URL, json={"manifest": first}, headers=ADMIN_HEADERS)
    assert r1.status_code == 200, r1.text
    r2 = await c.post(_UPLOAD_URL, json={"manifest": second}, headers=ADMIN_HEADERS)
    assert r2.status_code == 200, r2.text

    got = await c.get(_MANIFEST_URL.format(channel="canary"))
    assert got.json()["version"] == "1.0.1"


async def test_forged_signature_rejected(client, _configure_signing_key):
    sk, _ = _configure_signing_key
    signed = sign_manifest(_manifest(), bytes(sk))
    tampered = copy.deepcopy(signed)
    tampered["version"] = "9.9.9"  # tamper AFTER signing — signature no longer matches

    c, _ = client
    r = await c.post(_UPLOAD_URL, json={"manifest": tampered}, headers=ADMIN_HEADERS)
    assert r.status_code == 400, r.text
    assert "bad-signature" in r.text

    # and it must not have been stored
    got = await c.get(_MANIFEST_URL.format(channel="stable"))
    assert got.status_code == 404, got.text


async def test_unknown_key_id_rejected(client):
    """A manifest signed by a key the server's trust store has never heard of."""
    from app.config import settings

    other_sk, _other_pub = _keypair()
    signed = sign_manifest(_manifest(), bytes(other_sk))  # signed by a key NOT in the trust store

    prev = settings.SIGNING_PUBLIC_KEY
    settings.SIGNING_PUBLIC_KEY = ""  # empty trust store: every key_id is unknown
    try:
        c, _ = client
        r = await c.post(_UPLOAD_URL, json={"manifest": signed}, headers=ADMIN_HEADERS)
    finally:
        settings.SIGNING_PUBLIC_KEY = prev
    assert r.status_code == 400, r.text
    assert "unknown-key" in r.text


async def test_revoked_key_id_rejected(client):
    """A manifest signed by a key the server's trust store explicitly marks revoked
    (rotation/revocation — docs/KEY-GENERATION-RUNBOOK.md §8)."""
    import json as _json

    from app.config import settings

    sk, pub_b64 = _keypair()
    signed = sign_manifest(_manifest(), bytes(sk))

    prev = settings.SIGNING_TRUST_STORE_JSON
    settings.SIGNING_TRUST_STORE_JSON = _json.dumps(
        [{"public_key": pub_b64, "status": "revoked"}]
    )
    try:
        c, _ = client
        r = await c.post(_UPLOAD_URL, json={"manifest": signed}, headers=ADMIN_HEADERS)
    finally:
        settings.SIGNING_TRUST_STORE_JSON = prev
    assert r.status_code == 400, r.text
    assert "revoked-key" in r.text


async def test_next_status_key_is_accepted_during_rotation_overlap(client):
    """A 'next' (incoming, not yet promoted to active) key still verifies — the rotation
    overlap window from KEY-GENERATION-RUNBOOK.md §7."""
    import json as _json

    from app.config import settings

    sk, pub_b64 = _keypair()
    signed = sign_manifest(_manifest(channel="beta"), bytes(sk))

    prev = settings.SIGNING_TRUST_STORE_JSON
    settings.SIGNING_TRUST_STORE_JSON = _json.dumps([{"public_key": pub_b64, "status": "next"}])
    try:
        c, _ = client
        r = await c.post(_UPLOAD_URL, json={"manifest": signed}, headers=ADMIN_HEADERS)
    finally:
        settings.SIGNING_TRUST_STORE_JSON = prev
    assert r.status_code == 200, r.text


async def test_missing_or_invalid_channel_rejected(client, _configure_signing_key):
    sk, _ = _configure_signing_key
    c, _ = client

    no_channel = {"version": "1.0.0", "services": {}, "migrations": []}
    signed = sign_manifest(no_channel, bytes(sk))
    r = await c.post(_UPLOAD_URL, json={"manifest": signed}, headers=ADMIN_HEADERS)
    assert r.status_code == 400, r.text

    bogus_channel = sign_manifest(_manifest(channel="nightly-bogus"), bytes(sk))
    r2 = await c.post(_UPLOAD_URL, json={"manifest": bogus_channel}, headers=ADMIN_HEADERS)
    assert r2.status_code == 400, r2.text


async def test_publish_stays_permanently_gated(client):
    """The old unconditional 501 on /publish must still be there — server-side signing
    is a permanent architectural boundary, not a temporary block that /upload relaxes."""
    c, _ = client
    r = await c.post(_PUBLISH_URL)
    assert r.status_code == 501, r.text
    assert "upload" in r.text  # points callers at the real (offline-sign-then-upload) path


async def test_unconfigured_trust_store_is_fail_closed_not_open(client):
    """No SIGNING_PUBLIC_KEY / SIGNING_TRUST_STORE_JSON configured at all (the real
    pre-key production default, per docker-compose.yml) ⇒ every upload is rejected as
    unknown-key, never silently accepted."""
    from app.config import settings

    sk, _ = _keypair()
    signed = sign_manifest(_manifest(), bytes(sk))

    prev_key = settings.SIGNING_PUBLIC_KEY
    prev_json = settings.SIGNING_TRUST_STORE_JSON
    settings.SIGNING_PUBLIC_KEY = ""
    settings.SIGNING_TRUST_STORE_JSON = ""
    try:
        c, _ = client
        r = await c.post(_UPLOAD_URL, json={"manifest": signed}, headers=ADMIN_HEADERS)
    finally:
        settings.SIGNING_PUBLIC_KEY = prev_key
        settings.SIGNING_TRUST_STORE_JSON = prev_json
    assert r.status_code == 400, r.text
    assert "unknown-key" in r.text
