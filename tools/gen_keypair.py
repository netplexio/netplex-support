#!/usr/bin/env python3
"""OFFLINE keypair generator for release/license signing.

⚠️  RUN THIS ON AN OFFLINE / AIR-GAPPED MACHINE ONLY (docs/SECURITY-BLOCKERS.md gate #3).
The private key it writes must NEVER touch the server, CI, or any shared host. Back it up to
two encrypted offline media in separate locations (escrow).

Outputs:
  <name>.key   — 32-byte ed25519 seed, base64 (PRIVATE — keep offline, chmod 600)
  <name>.pub   — public key, base64 (ship this: bake into the installer trust store)
  prints the key_id and a ready-to-bake trust-store entry.

Usage:  python tools/gen_keypair.py netplex-signing-2026
"""
import base64
import json
import os
import sys

from nacl.signing import SigningKey


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    name = sys.argv[1]
    sk = SigningKey.generate()
    seed = bytes(sk)                       # 32-byte seed = the private key
    pub = bytes(sk.verify_key)
    import hashlib
    key_id = hashlib.sha256(pub).hexdigest()[:16]

    priv_b64 = base64.b64encode(seed).decode()
    pub_b64 = base64.b64encode(pub).decode()

    with open(f"{name}.key", "w") as f:
        f.write(priv_b64 + "\n")
    os.chmod(f"{name}.key", 0o600)
    with open(f"{name}.pub", "w") as f:
        f.write(pub_b64 + "\n")

    print(f"key_id: {key_id}")
    print(f"private: {name}.key  (chmod 600 — OFFLINE ONLY, back up to 2 encrypted media)")
    print(f"public:  {name}.pub")
    print("\nTrust-store entry to bake into the installer (status: active | next):")
    print(json.dumps({"public_key": pub_b64, "status": "active"}, indent=2))


if __name__ == "__main__":
    main()
