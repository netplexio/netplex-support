#!/usr/bin/env python3
"""OFFLINE release-manifest signer.

⚠️  RUN OFFLINE ONLY, on the machine that holds the private key (docs/SECURITY-BLOCKERS.md #3).
Reads an unsigned manifest JSON + the private key, writes the signed manifest. Only the SIGNED
output is ever uploaded to netplex-support / the registry.

Usage:
  python tools/sign_release.py netplex-signing-2026.key manifest.json signed-manifest.json
"""
import json
import sys
import base64

# Allow running from the repo root without install.
sys.path.insert(0, ".")
from app.crypto.signing import sign_manifest, key_id_for  # noqa: E402
from nacl.signing import SigningKey  # noqa: E402


def main() -> None:
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(1)
    key_path, in_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    seed = base64.b64decode(open(key_path).read().strip())
    with open(in_path) as f:
        manifest = json.load(f)
    signed = sign_manifest(manifest, seed)
    with open(out_path, "w") as f:
        json.dump(signed, f, indent=2)
    kid = key_id_for(bytes(SigningKey(seed).verify_key))
    print(f"signed with key_id={kid} → {out_path}")


if __name__ == "__main__":
    main()
