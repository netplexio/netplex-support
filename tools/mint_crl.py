#!/usr/bin/env python3
"""OFFLINE CRL minter - sign a licence revocation list.

⚠️  OFFLINE SIGNING MACHINE ONLY. The signed CRL is shipped to installs over the existing update
channel; each box loads it (default `/netplex/data/license/crl.json`), verifies the signature against
its pinned trust store, and rejects any token whose `license_id` is listed. Downgrade-only + fail-safe:
an absent/invalid CRL revokes nobody, so this can never lock out a legitimate customer.

Usage:
  python tools/mint_crl.py --key netplex-license-2026.key \
      --revoke lic-abc123 --revoke lic-def456 --out crl.json
  # or from a file, one license_id per line:
  python tools/mint_crl.py --key netplex-license-2026.key --revoke-file revoked.txt --out crl.json
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def canonical_bytes(manifest: dict) -> bytes:
    payload = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="Mint a signed licence revocation list (offline).")
    ap.add_argument("--key", required=True, help="base64 32-byte ed25519 private seed file")
    ap.add_argument("--revoke", action="append", default=[], help="a license_id to revoke (repeatable)")
    ap.add_argument("--revoke-file", default=None, help="file with one license_id per line")
    ap.add_argument("--now", type=int, default=None)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    revoked = list(args.revoke)
    if args.revoke_file:
        with open(args.revoke_file) as f:
            revoked += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    revoked = sorted(set(revoked))
    if not revoked:
        raise SystemExit("refusing to mint an empty CRL - pass --revoke / --revoke-file")

    seed = base64.b64decode(open(args.key).read().strip())
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_id = hashlib.sha256(pub).hexdigest()[:16]

    crl = {
        "type": "crl",
        "revoked": revoked,
        "issued_at": int(args.now if args.now is not None else time.time()),
    }
    crl["signature"] = {"alg": "ed25519", "key_id": key_id,
                        "sig": base64.b64encode(sk.sign(canonical_bytes(crl))).decode()}
    with open(args.out, "w") as f:
        f.write(json.dumps(crl, separators=(",", ":"), ensure_ascii=False) + "\n")
    print(f"CRL minted: {len(revoked)} revoked, key_id={key_id} → {args.out}")


if __name__ == "__main__":
    main()
