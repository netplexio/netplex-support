#!/usr/bin/env python3
"""OFFLINE licence minter — signs a netplex licence token with the private licence key.

⚠️  RUN THIS ON THE OFFLINE / AIR-GAPPED SIGNING MACHINE ONLY. The private seed must never touch the
server, CI, or any shared host (docs/SECURITY-BLOCKERS.md gate #3).

Produces the canonical signed **manifest** the box verifies with its pinned trust store
(netplex `backend/shared/license_verify.py`) — byte-for-byte compatible with
`app/crypto/signing.py::canonical_bytes` so either PyNaCl or `cryptography` can sign/verify.

Token shape:
  { "tier", "entitlements"(signed caps, leg ②), "buyer_id"+"customer_ref"(attribution, leg ④),
    "license_id", "fingerprint"("any"|<sha256>), "expires_at"(unix|null),
    "signature": {"alg":"ed25519","key_id","sig"} }

Uses `cryptography` (not PyNaCl) so it runs anywhere the box's own crypto stack runs.

Usage:
  python tools/mint_license.py \
      --key netplex-license-2026.key \
      --tier master --buyer-id netplex-internal-reference-box \
      --entitlements caps.master.json --days 3650 \
      --out refbox.token
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def canonical_bytes(manifest: dict) -> bytes:
    payload = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="Mint a signed netplex licence token (offline).")
    ap.add_argument("--key", required=True, help="base64 32-byte ed25519 private seed file")
    ap.add_argument("--tier", required=True)
    ap.add_argument("--buyer-id", required=True, help="buyer/customer id (attribution — leg ④)")
    ap.add_argument("--customer-ref", default=None, help="defaults to --buyer-id")
    ap.add_argument("--license-id", default=None, help="defaults to lic-<8 hex of buyer_id>")
    ap.add_argument("--machine", default="any",
                    help="'any' or a machine HARDWARE fingerprint (node-lock; §11.10.4). Use the box's "
                         "get_hardware_fingerprint() / the air-gap request bundle's 'fingerprint'.")
    ap.add_argument("--allow-floating", action="store_true",
                    help="signed permission for a node-locked token to run on ANY box (CI/eval). Only "
                         "honoured because it is inside the signature — an env var can't set it.")
    ap.add_argument("--entitlements", default=None, help="path to a JSON caps dict (signed caps — leg ②)")
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument("--days", type=int, default=365, help="validity in days")
    grp.add_argument("--perpetual", action="store_true", help="never expires (expires_at=null)")
    ap.add_argument("--now", type=int, default=None, help="override 'now' unix seconds (reproducible)")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    seed = base64.b64decode(open(args.key).read().strip())
    if len(seed) != 32:
        sys.exit("private key must be a base64 32-byte ed25519 seed")
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_id = hashlib.sha256(pub).hexdigest()[:16]

    now = int(args.now if args.now is not None else time.time())
    expires_at = None if args.perpetual else now + args.days * 86400

    # §11.9 policy guard (Khaled 2026-07-06): hardware-lock ONLY Enterprise / Architect-perpetual.
    # Binding a mid-tier token to a fingerprint would demote honest customers who legitimately migrate
    # VMs (node-lock enforcement compares the bound fp against the box's hardware; a moved VM mismatches
    # → free). Refuse a real bind (a fingerprint that isn't "any", not a floating token) for any tier
    # outside the policy, so staff can't mis-issue. Use --allow-floating or --machine any for the rest.
    _tier = args.tier.lower()
    _real_bind = args.machine and args.machine != "any" and not args.allow_floating
    _LOCKABLE = {"enterprise", "architect", "master"}
    if _real_bind:
        if _tier not in _LOCKABLE:
            sys.exit(f"refusing to hardware-lock a '{_tier}' token: policy binds only "
                     f"{sorted(_LOCKABLE)} (§11.9). Use --machine any or --allow-floating for this tier.")
        if _tier == "architect" and not args.perpetual:
            sys.exit("refusing to hardware-lock a SUBSCRIPTION 'architect' token: only Architect-"
                     "PERPETUAL is node-locked (§11.4). Add --perpetual, or use --machine any.")

    entitlements = {}
    if args.entitlements:
        entitlements = json.load(open(args.entitlements))
        # features may be a set in source; JSON carries a list — the box normalises back to a set.
        if isinstance(entitlements.get("features"), (set, tuple)):
            entitlements["features"] = sorted(entitlements["features"])

    buyer = args.buyer_id
    claims = {
        "tier": args.tier.lower(),
        "entitlements": entitlements,
        "buyer_id": buyer,
        "customer_ref": args.customer_ref or buyer,
        "license_id": args.license_id or f"lic-{hashlib.sha256(buyer.encode()).hexdigest()[:8]}",
        "fingerprint": args.machine,
        "issued_at": now,
        "expires_at": expires_at,
    }
    if args.allow_floating:
        claims["allow_floating"] = True
    claims["signature"] = {
        "alg": "ed25519",
        "key_id": key_id,
        "sig": base64.b64encode(sk.sign(canonical_bytes(claims))).decode(),
    }
    token = json.dumps(claims, separators=(",", ":"), ensure_ascii=False)
    with open(args.out, "w") as f:
        f.write(token + "\n")
    print(f"minted: tier={claims['tier']} buyer_id={buyer} key_id={key_id} "
          f"expires_at={expires_at} → {args.out}")


if __name__ == "__main__":
    main()
