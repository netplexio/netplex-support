#!/usr/bin/env python3
"""Leak attribution — recover the buyer from a leaked licence token, download stamp, or build.

Two attribution sources, both signature-verified before use:
  * **Licence token** — carries `buyer_id`/`customer_ref` + `license_id` in its signed payload
    (§11.9.1 leg ④). Present once a copy has been ACTIVATED.
  * **Download stamp** (`type: netplex-download-stamp`, §11.10) — injected per download by
    tools/stamp_download.py at multiple sites in the package tree, so a leaked *pre-activation*
    package still names the account that downloaded it. Signed by a SEPARATE stamp key (attribution,
    not authorization) verified against its own trust set (--stamp-pubkey / NETPLEX_STAMP_PUBKEYS).

When a cracked build or a shared token/package surfaces, feed it here to name the account it traces
to, for revocation (tools/mint_crl.py) and the DMCA/legal workflow (docs/RUNBOOK-anti-piracy.md).
Every claim is signature-verified first, so a forged/edited artefact is reported as such rather than
mis-attributed. A recovered download_id can also resolve via the download ledger (--ledger) even if
the stamp's own customer_ref was stripped.

Usage:
  python tools/attribute_leak.py --token-file leaked.token
  echo '<token json>' | python tools/attribute_leak.py
  python tools/attribute_leak.py --scan /path/to/unpacked/build          # licence tokens only
  python tools/attribute_leak.py --scan /path/to/unpacked/build \\
      --stamp-pubkey <b64> [--ledger downloads-ledger.jsonl]             # + download stamps
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

# Pinned LICENCE trust keys (mirror backend/shared/license_verify.py::_TRUST_STORE). Attribution
# only — not an authorisation decision.
TRUST = [
    "jJCebPG7chTyVdNLQ7eCYPqbvjiuWwEahm1ozQyz4pE=",  # 2026 active
    "ZiZR7Qz12/KFTkQfcpvN7m4e9uG9HY7skqCRN3KyrPU=",  # 2027 next
]

# Pinned DOWNLOAD-STAMP trust keys (§11.10) — a SEPARATE set from the licence root, because a stamp
# is a tracer, not a lock. Bake the stamp public key here once tools/gen_keypair.py mints it, and/or
# pass at runtime via --stamp-pubkey / NETPLEX_STAMP_PUBKEYS (comma-separated b64).
STAMP_TRUST: list[str] = [
    # "<stamp-2026.pub b64>",
]

STAMP_TYPE = "netplex-download-stamp"


def _canon(m: dict) -> bytes:
    p = {k: v for k, v in m.items() if k != "signature"}
    return json.dumps(p, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _verify(claims: dict, trust_keys: list[str]) -> tuple[bool, str]:
    if Ed25519PublicKey is None:
        return False, "crypto-unavailable"
    b64 = (claims.get("signature") or {}).get("sig", "")
    for pub_b64 in trust_keys:
        try:
            pub = base64.b64decode(pub_b64)
            Ed25519PublicKey.from_public_bytes(pub).verify(base64.b64decode(b64), _canon(claims))
            return True, hashlib.sha256(pub).hexdigest()[:16]
        except Exception:  # noqa: BLE001
            continue
    return False, "no-trusted-key" if trust_keys else "no-stamp-key-configured"


def _attribute(token: str, *, stamp_trust: list[str] | None = None,
               ledger: dict | None = None) -> dict:
    try:
        claims = json.loads(token)
    except Exception:  # noqa: BLE001
        return {"ok": False, "reason": "not-json"}

    # Download stamp (§11.10) — verify against the SEPARATE stamp trust set.
    if claims.get("type") == STAMP_TYPE:
        keys = list(stamp_trust or []) + STAMP_TRUST
        ok, why = _verify(claims, keys)
        embedded = claims.get("customer_ref") or claims.get("buyer_id")
        dl = claims.get("download_id")
        via_ledger = bool(ok and dl and not embedded and ledger and dl in ledger)
        cust = embedded or ((ledger or {}).get(dl, {}).get("customer_ref") if via_ledger else None)
        return {
            "kind": "download-stamp",
            "ok": ok,
            "signature_key_id": why if ok else None,
            "reason": None if ok else why,
            "customer_ref": cust,
            "download_id": dl,
            "tier": claims.get("tier"),
            "package": claims.get("package"),
            "version": claims.get("version"),
            "issued_at": claims.get("issued_at"),
            "resolved_via_ledger": via_ledger,
        }

    # Licence token (§11.9.1 leg ④).
    ok, why = _verify(claims, TRUST)
    return {
        "kind": "license-token",
        "ok": ok,
        "signature_key_id": why if ok else None,
        "reason": None if ok else why,
        "buyer_id": claims.get("buyer_id") or claims.get("customer_ref"),
        "license_id": claims.get("license_id") or claims.get("jti"),
        "tier": claims.get("tier"),
        "issued_at": claims.get("issued_at"),
        "expires_at": claims.get("expires_at"),
    }


def _load_ledger(path: str | None) -> dict:
    """Load a downloads JSONL ledger into {download_id: row}. Missing/unreadable → empty."""
    out: dict = {}
    if not path or not os.path.isfile(path):
        return out
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except Exception:  # noqa: BLE001
                    continue
                if row.get("download_id"):
                    out[row["download_id"]] = row
    except Exception:  # noqa: BLE001
        pass
    return out


def _scan(root: str, *, stamp_trust: list[str] | None = None, ledger: dict | None = None) -> list[dict]:
    """Grep files under root for embedded signed blobs (licence tokens AND download stamps).

    A download stamp is injected at multiple sites, so the same identity is deduped: one record per
    (kind, id, key), with the surviving copy count + the paths it was found at.
    """
    pat = re.compile(rb'\{[^{}]*"signature"\s*:\s*\{[^{}]*"alg"\s*:\s*"ed25519"[^{}]*\}[^{}]*\}')
    by_id: dict = {}
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
                    res = _attribute(m.group(0).decode(), stamp_trust=stamp_trust, ledger=ledger)
                except Exception:  # noqa: BLE001
                    continue
                ident = res.get("download_id") or res.get("license_id") or "?"
                key = (res.get("kind"), ident, res.get("signature_key_id"), res.get("ok"))
                if key in by_id:
                    by_id[key]["copies"] += 1
                    by_id[key]["artifacts"].append(fp)
                else:
                    res["copies"] = 1
                    res["artifacts"] = [fp]
                    by_id[key] = res
    return list(by_id.values())


def main() -> None:
    ap = argparse.ArgumentParser(description="Attribute a leaked licence token / download stamp / build to its buyer.")
    ap.add_argument("--token-file")
    ap.add_argument("--scan", help="directory of an unpacked build to grep for embedded tokens/stamps")
    ap.add_argument("--stamp-pubkey", action="append", default=[],
                    help="download-stamp public key(s) (b64); repeatable. Also read from NETPLEX_STAMP_PUBKEYS (comma-sep).")
    ap.add_argument("--ledger", help="downloads JSONL ledger to resolve a download_id → customer")
    args = ap.parse_args()

    stamp_trust = list(args.stamp_pubkey)
    env_keys = os.environ.get("NETPLEX_STAMP_PUBKEYS", "")
    stamp_trust += [k.strip() for k in env_keys.split(",") if k.strip()]
    ledger = _load_ledger(args.ledger)

    if args.scan:
        hits = _scan(args.scan, stamp_trust=stamp_trust, ledger=ledger)
        print(json.dumps(hits, indent=2))
        sys.exit(0 if hits else 2)

    if args.token_file:
        token = open(args.token_file).read().strip()
    else:
        token = sys.stdin.read().strip()
    print(json.dumps(_attribute(token, stamp_trust=stamp_trust, ledger=ledger), indent=2))


if __name__ == "__main__":
    main()
