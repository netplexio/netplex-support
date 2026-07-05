#!/usr/bin/env python3
"""Per-download watermark stamper — the §11.10 safety-pairing for the tier package split.

Problem it closes (licensing.md §11.10, point 2): the physical Free/Pro/Architect package split
means a *leaked package* is a clean, anonymous, redistributable build serving every freeloader from
one leak. `attribute_leak.py --scan` can only recover an embedded *activation token* — a freshly
downloaded package has none, so before this tool a leaked pre-activation package was untraceable.

This injects a signed, multi-site **download stamp** into a package tree at fetch time so a leaked
build names the account that downloaded it. It is *attribution*, not authorization — it never gates
a feature, so (unlike the licence root) its signing key may live where downloads are served. A
compromised stamp key only lets an attacker forge *tracers* (misattribute), never mint a licence or
a release. Hence a SEPARATE stamp keypair, distinct from the licence/release root.

⚠️  The live download portal (`app/routers/releases.py`) is GATED on docs/SECURITY-BLOCKERS.md #1–#5
and every route 501s. This tool is the offline/portal-ready PRIMITIVE: usable now for hand-issued
per-customer Enterprise/Architect builds, and the call to wire into `releases.py` once distribution
is un-gated. It does NOT un-gate anything itself.

Usage:
  python tools/stamp_download.py --key stamp-2026.key --artifact /path/to/unpacked/pkg \\
      --customer cust_abc123 --tier pro --package pro --version 1.8.2 \\
      [--download-id <uuid>] [--ledger downloads-ledger.jsonl] [--sites N]

Recover with:  python tools/attribute_leak.py --scan /path/to/leaked/unpacked/build \\
                   --stamp-pubkey <stamp-2026.pub contents> [--ledger downloads-ledger.jsonl]
"""
from __future__ import annotations

import argparse
import base64
import datetime as _dt
import hashlib
import json
import os
import uuid

# Signs with `cryptography` (same lib + canonical bytes as tools/attribute_leak.py, the recovery
# side, and backend/shared/license_verify.py). The signature block {alg,key_id,sig} is byte-identical
# to app/crypto/signing.py's, so a stamp also verifies under verify_manifest() if ever needed. Key
# files are cross-compatible with tools/gen_keypair.py (both use the 32-byte ed25519 seed).
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

STAMP_TYPE = "netplex-download-stamp"
ALG = "ed25519"


def _canonical_bytes(manifest: dict) -> bytes:
    payload = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sign(manifest: dict, seed: bytes) -> dict:
    """Return a copy of manifest with an ed25519 `signature` block (seed = 32-byte private key)."""
    from cryptography.hazmat.primitives import serialization
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    kid = hashlib.sha256(pub).hexdigest()[:16]
    out = {k: v for k, v in manifest.items() if k != "signature"}
    sig = sk.sign(_canonical_bytes(out))
    out["signature"] = {"alg": ALG, "key_id": kid, "sig": base64.b64encode(sig).decode("ascii")}
    return out


def _key_id(seed: bytes) -> str:
    from cryptography.hazmat.primitives import serialization
    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(pub).hexdigest()[:16]

# Redundant, innocuous injection sites (relative to the artifact root). Multi-site so stripping one
# copy does not defeat attribution; the recover side only needs ONE surviving, signature-valid copy.
# Ordered from most-obvious to least; a stripper has to find and remove ALL of them cleanly.
_DEFAULT_SITES = [
    "install-stamp.json",          # 1. primary / honest copy at root
    ".netplex/build.json",         # 2. hidden dir, plausible build metadata
    "share/netplex/.provenance",   # 3. buried under a data path
    "assets/.build-constant.json",  # 4. next to frontend assets
]


def _now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).replace(microsecond=0).isoformat()


def _write_sites(root: str, signed: dict, sites: list[str]) -> list[str]:
    written = []
    blob = json.dumps(signed, indent=2).encode("utf-8")
    for rel in sites:
        dst = os.path.join(root, rel)
        os.makedirs(os.path.dirname(dst) or root, exist_ok=True)
        with open(dst, "wb") as fh:
            fh.write(blob)
        written.append(rel)
    return written


def _append_ledger(ledger_path: str, stamp: dict) -> None:
    """Append download_id → customer mapping (JSONL). Lets a recovered download_id resolve to a
    customer even if the stamp's own customer_ref were somehow stripped from a leaked copy."""
    row = {
        "download_id": stamp["download_id"],
        "customer_ref": stamp["customer_ref"],
        "tier": stamp["tier"],
        "package": stamp["package"],
        "version": stamp["version"],
        "issued_at": stamp["issued_at"],
    }
    os.makedirs(os.path.dirname(ledger_path) or ".", exist_ok=True)
    with open(ledger_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, sort_keys=True) + "\n")


def stamp_artifact(
    *, key_seed: bytes, artifact_root: str, customer: str, tier: str, package: str,
    version: str, download_id: str | None = None, sites: list[str] | None = None,
    ledger_path: str | None = None, embed_customer: bool = True,
) -> dict:
    """Core primitive (import-friendly for tests): sign a stamp and inject it into the tree.

    ``embed_customer=False`` ships a privacy-mode stamp that carries only the ``download_id`` (no
    PII in the artifact); the ``download_id → customer`` mapping lives ONLY in the ledger, so
    attribution still works via ``--ledger`` but the distributed build contains no customer identity.

    Returns {download_id, key_id, sites, stamp}. Raises FileNotFoundError if the tree is missing.
    """
    if not os.path.isdir(artifact_root):
        raise FileNotFoundError(f"artifact root is not a directory: {artifact_root}")
    dl_id = download_id or f"dl_{uuid.uuid4().hex}"
    issued = _now_iso()
    stamp = {"type": STAMP_TYPE, "download_id": dl_id, "tier": tier, "package": package,
             "version": version, "issued_at": issued}
    if embed_customer:
        stamp["customer_ref"] = customer
    signed = _sign(stamp, key_seed)
    kid = _key_id(key_seed)
    written = _write_sites(artifact_root, signed, sites or _DEFAULT_SITES)
    if ledger_path:
        # Ledger ALWAYS records the customer (even in privacy mode) so a download_id resolves later.
        _append_ledger(ledger_path, {"download_id": dl_id, "customer_ref": customer, "tier": tier,
                                     "package": package, "version": version, "issued_at": issued})
    return {"download_id": dl_id, "key_id": kid, "sites": written, "stamp": signed}


def main() -> None:
    ap = argparse.ArgumentParser(description="Inject a signed per-download watermark into a package tree.")
    ap.add_argument("--key", required=True, help="stamp signing key (32-byte ed25519 seed, base64) — a SEPARATE key from the licence/release root")
    ap.add_argument("--artifact", required=True, help="path to the UNPACKED package tree to stamp")
    ap.add_argument("--customer", required=True, help="buyer / account id (customer_ref)")
    ap.add_argument("--tier", required=True)
    ap.add_argument("--package", required=True, help="package edition, e.g. free|pro|architect|enterprise")
    ap.add_argument("--version", required=True)
    ap.add_argument("--download-id", default=None, help="override the generated download id")
    ap.add_argument("--ledger", default=None, help="JSONL ledger to append download_id→customer")
    ap.add_argument("--sites", type=int, default=None, help="number of injection sites (default all built-in sites)")
    ap.add_argument("--no-embed-customer", action="store_true",
                    help="privacy mode: ship only the download_id in the artifact; keep customer_ref in the ledger only")
    args = ap.parse_args()

    seed = base64.b64decode(open(args.key).read().strip())
    sites = _DEFAULT_SITES if not args.sites else _DEFAULT_SITES[: max(1, args.sites)]
    res = stamp_artifact(
        key_seed=seed, artifact_root=args.artifact, customer=args.customer, tier=args.tier,
        package=args.package, version=args.version, download_id=args.download_id,
        sites=sites, ledger_path=args.ledger, embed_customer=not args.no_embed_customer,
    )
    print(f"stamped download_id={res['download_id']} key_id={res['key_id']} "
          f"sites={len(res['sites'])} → {', '.join(res['sites'])}")
    if args.ledger:
        print(f"ledger: appended → {args.ledger}")


if __name__ == "__main__":
    main()
