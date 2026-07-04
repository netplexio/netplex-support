#!/usr/bin/env python3
"""Leak attribution — recover the buyer from a leaked licence token or a build artifact.

Every signed token carries `buyer_id`/`customer_ref` + `license_id` in its signed payload (§11.9.1
leg ④). When a cracked build or a shared token surfaces, feed it here to name the account it traces
to, for revocation (tools/mint_crl.py) and the DMCA/legal workflow (docs/RUNBOOK-anti-piracy.md).

Verifies the signature against the same trust store the box uses, so a forged/edited token is
reported as such rather than mis-attributed.

Usage:
  python tools/attribute_leak.py --token-file leaked.token
  echo '<token json>' | python tools/attribute_leak.py
  python tools/attribute_leak.py --scan /path/to/unpacked/build   # grep artifacts for embedded tokens
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
except Exception:  # pragma: no cover
    Ed25519PublicKey = None  # type: ignore
    InvalidSignature = Exception  # type: ignore

# The pinned public keys (mirror backend/shared/license_verify.py::_TRUST_STORE). Attribution only —
# not an authorisation decision.
TRUST = [
    "jJCebPG7chTyVdNLQ7eCYPqbvjiuWwEahm1ozQyz4pE=",  # 2026 active
    "ZiZR7Qz12/KFTkQfcpvN7m4e9uG9HY7skqCRN3KyrPU=",  # 2027 next
]


def _canon(m: dict) -> bytes:
    p = {k: v for k, v in m.items() if k != "signature"}
    return json.dumps(p, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _verify(claims: dict) -> tuple[bool, str]:
    if Ed25519PublicKey is None:
        return False, "crypto-unavailable"
    sig = claims.get("signature") or {}
    b64 = sig.get("sig", "")
    for pub_b64 in TRUST:
        try:
            pub = base64.b64decode(pub_b64)
            Ed25519PublicKey.from_public_bytes(pub).verify(base64.b64decode(b64), _canon(claims))
            return True, hashlib.sha256(pub).hexdigest()[:16]
        except Exception:  # noqa: BLE001
            continue
    return False, "no-trusted-key"


def _attribute(token: str) -> dict:
    try:
        claims = json.loads(token)
    except Exception:  # noqa: BLE001
        return {"ok": False, "reason": "not-json"}
    ok, why = _verify(claims)
    return {
        "ok": ok,
        "signature_key_id": why if ok else None,
        "reason": None if ok else why,
        "buyer_id": claims.get("buyer_id") or claims.get("customer_ref"),
        "license_id": claims.get("license_id") or claims.get("jti"),
        "tier": claims.get("tier"),
        "issued_at": claims.get("issued_at"),
        "expires_at": claims.get("expires_at"),
    }


def _scan(root: str) -> list[dict]:
    """Grep files under root for embedded signed tokens (a manifest with a signature block)."""
    pat = re.compile(rb'\{[^{}]*"signature"\s*:\s*\{[^{}]*"alg"\s*:\s*"ed25519"[^{}]*\}[^{}]*\}')
    found = []
    for dp, _dn, fns in os.walk(root):
        for fn in fns:
            fp = os.path.join(dp, fn)
            try:
                with open(fp, "rb") as f:
                    blob = f.read(2_000_000)
            except Exception:  # noqa: BLE001
                continue
            for m in pat.finditer(blob):
                try:
                    res = _attribute(m.group(0).decode())
                    res["artifact"] = fp
                    found.append(res)
                except Exception:  # noqa: BLE001
                    continue
    return found


def main() -> None:
    ap = argparse.ArgumentParser(description="Attribute a leaked licence token / build to its buyer.")
    ap.add_argument("--token-file")
    ap.add_argument("--scan", help="directory of an unpacked build to grep for embedded tokens")
    args = ap.parse_args()

    if args.scan:
        hits = _scan(args.scan)
        print(json.dumps(hits, indent=2))
        sys.exit(0 if hits else 2)

    if args.token_file:
        token = open(args.token_file).read().strip()
    else:
        token = sys.stdin.read().strip()
    print(json.dumps(_attribute(token), indent=2))


if __name__ == "__main__":
    main()
