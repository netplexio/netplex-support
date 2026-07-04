#!/usr/bin/env python3
"""OFFLINE signer for the entitlement-kernel integrity manifest (§11.9.1 Layer 3).

Hashes the kernel files (must match backend/shared/integrity.py::_KERNEL_FILES), builds a signed
`{type:integrity, files:{name:sha256}, signature}` manifest, and writes it. Ship it to installs as
`/netplex/data/license/integrity.json`; the box FLAGS (never demotes) on drift.

Usage:
  python tools/sign_integrity.py --key netplex-license-2026.key \
      --shared /path/to/netplex/backend/shared --out integrity.json
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Keep in lock-step with backend/shared/integrity.py::_KERNEL_FILES.
KERNEL_FILES = ("license_verify.py", "entitlements.py", "integrity.py")


def canonical_bytes(m: dict) -> bytes:
    payload = {k: v for k, v in m.items() if k != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="Sign the entitlement-kernel integrity manifest (offline).")
    ap.add_argument("--key", required=True)
    ap.add_argument("--shared", required=True, help="path to backend/shared")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    files = {}
    for name in KERNEL_FILES:
        with open(os.path.join(args.shared, name), "rb") as f:
            files[name] = hashlib.sha256(f.read()).hexdigest()

    seed = base64.b64decode(open(args.key).read().strip())
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_id = hashlib.sha256(pub).hexdigest()[:16]

    manifest = {"type": "integrity", "files": files}
    manifest["signature"] = {"alg": "ed25519", "key_id": key_id,
                             "sig": base64.b64encode(sk.sign(canonical_bytes(manifest))).decode()}
    with open(args.out, "w") as f:
        f.write(json.dumps(manifest, separators=(",", ":"), ensure_ascii=False) + "\n")
    print(f"integrity manifest signed: {list(files)} key_id={key_id} → {args.out}")


if __name__ == "__main__":
    main()
