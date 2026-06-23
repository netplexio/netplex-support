"""Crypto primitives for release/license signing & verification.

PUBLIC-key verification is safe to run anywhere (server, box).
PRIVATE-key signing is OFFLINE only — see tools/sign_release.py and the hard rule in
docs/SECURITY-BLOCKERS.md. No private key is ever stored in this repo or on the server.
"""
from .signing import (
    key_id_for, canonical_bytes, sign_manifest, verify_manifest,
    TrustStore, SignatureError,
)

__all__ = [
    "key_id_for", "canonical_bytes", "sign_manifest", "verify_manifest",
    "TrustStore", "SignatureError",
]
