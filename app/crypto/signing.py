"""ed25519 manifest signing + verification (key-id aware, dual-trust, revocation).

Design: docs/SECURITY-BLOCKERS.md gates #1-#3.
- A signed manifest carries `signature = {alg, key_id, sig}` (sig over the canonical bytes of the
  manifest WITHOUT its signature field).
- A box ships a baked-in **trust store**: key_id → {public_key, status} where status ∈
  {active, next, revoked}. Verification accepts active/next, rejects revoked/unknown.
- key_id = first 16 hex of sha256(public_key_bytes) - stable, lets manifests name their signer
  and lets us rotate (add a `next` key) and revoke without bricking boxes.

Only `verify_manifest` (public-key) is used server/box side. Signing needs the private key and is
done OFFLINE (tools/sign_release.py).
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Optional

try:
    from nacl.signing import SigningKey, VerifyKey
    from nacl.exceptions import BadSignatureError
except Exception:  # pragma: no cover - import guard
    SigningKey = VerifyKey = None  # type: ignore
    BadSignatureError = Exception  # type: ignore


ALG = "ed25519"


class SignatureError(Exception):
    """Raised when signing/verification cannot proceed (not the same as 'invalid signature')."""


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def key_id_for(public_key: bytes) -> str:
    """Stable short id for a public key (first 16 hex of sha256)."""
    return hashlib.sha256(public_key).hexdigest()[:16]


def canonical_bytes(manifest: dict) -> bytes:
    """Deterministic bytes to sign/verify: the manifest minus its `signature`, canonical JSON
    (sorted keys, no whitespace, UTF-8). Both signer and verifier MUST agree on this."""
    payload = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_manifest(manifest: dict, private_key: bytes, *, key_id: Optional[str] = None) -> dict:
    """OFFLINE: return a copy of `manifest` with a `signature` block. `private_key` is the 32-byte
    ed25519 seed. Never call this on the server with a production key."""
    if SigningKey is None:
        raise SignatureError("PyNaCl not available")
    sk = SigningKey(private_key)
    kid = key_id or key_id_for(bytes(sk.verify_key))
    out = dict(manifest)
    out.pop("signature", None)
    sig = sk.sign(canonical_bytes(out)).signature
    out["signature"] = {"alg": ALG, "key_id": kid, "sig": _b64e(sig)}
    return out


class TrustStore:
    """Baked-in set of trusted public keys. entries: key_id → {public_key(b64), status}."""

    def __init__(self, entries: dict[str, dict]):
        self._e = entries

    @classmethod
    def from_keys(cls, keys: list[dict]) -> "TrustStore":
        """keys: [{public_key(b64), status}] → indexed by computed key_id."""
        out = {}
        for k in keys:
            pub = _b64d(k["public_key"])
            out[key_id_for(pub)] = {"public_key": k["public_key"], "status": k.get("status", "active")}
        return cls(out)

    def status_of(self, key_id: str) -> Optional[str]:
        e = self._e.get(key_id)
        return e["status"] if e else None

    def public_key(self, key_id: str) -> Optional[bytes]:
        e = self._e.get(key_id)
        return _b64d(e["public_key"]) if e else None


def trust_store_from_settings(trust_store_json: str, single_public_key: str) -> TrustStore:
    """Build a TrustStore the way every settings-backed caller in this service does it:
    prefer a full multi-key JSON trust store (rotation/revocation - KEY-GENERATION-
    RUNBOOK.md §7-8) when configured, else fall back to a single key treated as
    `status: "active"`. Both unset → an empty store (verification always fails closed
    with reason "unknown-key", never silently "open"). Takes plain strings (not the
    `settings` object) so it stays a pure crypto-module function with no app.config
    import - callers pass `settings.X_TRUST_STORE_JSON` / `settings.X_PUBLIC_KEY`."""
    raw = (trust_store_json or "").strip()
    if raw:
        try:
            keys = json.loads(raw)
        except (ValueError, TypeError):
            keys = []
        if isinstance(keys, list):
            return TrustStore.from_keys(keys)
        return TrustStore.from_keys([])
    if single_public_key:
        return TrustStore.from_keys([{"public_key": single_public_key, "status": "active"}])
    return TrustStore.from_keys([])


def verify_manifest(manifest: dict, trust: TrustStore) -> tuple[bool, str]:
    """Verify a signed manifest against the trust store.

    Returns (ok, reason). ok=True only if the signing key is known, NOT revoked (active/next),
    and the signature matches the canonical payload.
    """
    if VerifyKey is None:
        return False, "crypto-unavailable"
    sigblock = manifest.get("signature")
    if not isinstance(sigblock, dict):
        return False, "no-signature"
    if sigblock.get("alg") != ALG:
        return False, f"bad-alg:{sigblock.get('alg')}"
    kid = sigblock.get("key_id", "")
    status = trust.status_of(kid)
    if status is None:
        return False, "unknown-key"
    if status == "revoked":
        return False, "revoked-key"
    if status not in ("active", "next"):
        return False, f"bad-status:{status}"
    pub = trust.public_key(kid)
    try:
        VerifyKey(pub).verify(canonical_bytes(manifest), _b64d(sigblock["sig"]))
    except BadSignatureError:
        return False, "bad-signature"
    except Exception as exc:  # malformed sig etc.
        return False, f"verify-error:{exc}"
    return True, kid
