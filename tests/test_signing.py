"""Crypto primitives — sign/verify, key-id, dual-trust, rotation, revocation, tamper.

Uses EPHEMERAL keypairs generated per test — no private key is ever committed or stored.
Run: python -m pytest netplex-support/tests/test_signing.py
"""
import base64
import sys
import os

import pytest

pytest.importorskip("nacl")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nacl.signing import SigningKey  # noqa: E402
from app.crypto.signing import (  # noqa: E402
    sign_manifest, verify_manifest, key_id_for, canonical_bytes, TrustStore,
)


def _keypair():
    sk = SigningKey.generate()
    return bytes(sk), bytes(sk.verify_key)


def _trust(pubs):  # pubs: list[(pub_bytes, status)]
    return TrustStore.from_keys([{"public_key": base64.b64encode(p).decode(), "status": s} for p, s in pubs])


MANIFEST = {"version": "1.4.2", "channel": "stable",
            "services": {"api-gateway": "sha256:abc"}, "migrations": []}


def test_sign_then_verify_roundtrips():
    seed, pub = _keypair()
    signed = sign_manifest(MANIFEST, seed)
    assert signed["signature"]["alg"] == "ed25519"
    assert signed["signature"]["key_id"] == key_id_for(pub)
    ok, reason = verify_manifest(signed, _trust([(pub, "active")]))
    assert ok and reason == key_id_for(pub)


def test_next_key_is_trusted_dual_trust():
    seed, pub = _keypair()
    signed = sign_manifest(MANIFEST, seed)
    ok, _ = verify_manifest(signed, _trust([(pub, "next")]))
    assert ok  # a 'next' (incoming) key verifies during the overlap window


def test_revoked_key_is_rejected():
    seed, pub = _keypair()
    signed = sign_manifest(MANIFEST, seed)
    ok, reason = verify_manifest(signed, _trust([(pub, "revoked")]))
    assert not ok and reason == "revoked-key"


def test_unknown_key_is_rejected():
    seed, _pub = _keypair()
    other_seed, other_pub = _keypair()
    signed = sign_manifest(MANIFEST, seed)            # signed by key A
    ok, reason = verify_manifest(signed, _trust([(other_pub, "active")]))  # trust only key B
    assert not ok and reason == "unknown-key"


def test_tampered_payload_fails():
    seed, pub = _keypair()
    signed = sign_manifest(MANIFEST, seed)
    signed["version"] = "9.9.9"                       # tamper after signing
    ok, reason = verify_manifest(signed, _trust([(pub, "active")]))
    assert not ok and reason == "bad-signature"


def test_missing_signature_fails():
    ok, reason = verify_manifest(MANIFEST, _trust([(_keypair()[1], "active")]))
    assert not ok and reason == "no-signature"


def test_canonical_bytes_ignore_signature_field():
    a = canonical_bytes({"x": 1, "signature": {"sig": "z"}})
    b = canonical_bytes({"x": 1})
    assert a == b  # signature field excluded from the signed payload


def test_rotation_overlap_then_retire():
    # old key signs; box trusts {old:active, new:next} → ok. After rotation, old becomes revoked.
    old_seed, old_pub = _keypair()
    _new_seed, new_pub = _keypair()
    signed = sign_manifest(MANIFEST, old_seed)
    ok, _ = verify_manifest(signed, _trust([(old_pub, "active"), (new_pub, "next")]))
    assert ok
    ok2, reason = verify_manifest(signed, _trust([(old_pub, "revoked"), (new_pub, "active")]))
    assert not ok2 and reason == "revoked-key"
