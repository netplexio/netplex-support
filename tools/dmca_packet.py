#!/usr/bin/env python3
"""DMCA packet generator — turn a leaked licence token into a ready-to-review takedown notice.

Runs the same signature-verified attribution as attribute_leak.py, then fills
legal/dmca-takedown-template.md and writes a case folder (notice + the raw attribution JSON) under
cases/. The notice still needs counsel review + your rightsholder details; this removes the manual
transcription and ties the buyer_id/license_id into the § 512 / § 1201 boilerplate.

Usage:
  python tools/dmca_packet.py --token-file leaked.token \
      --infringing-url https://example.com/netplex-cracked.iso \
      --rightsholder "netplex. Pty Ltd" --contact legal@netplex.io \
      --host "GitHub DMCA agent" --case-id CASE-2026-001 [--now-iso 2026-07-05T00:00:00Z]
"""
from __future__ import annotations

import argparse
import json
import os
import sys

# reuse the verified-attribution logic
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from attribute_leak import _attribute  # noqa: E402

_TEMPLATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "legal", "dmca-takedown-template.md")


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate a DMCA/anti-circumvention notice from a leaked token.")
    ap.add_argument("--token-file", required=True)
    ap.add_argument("--infringing-url", required=True)
    ap.add_argument("--rightsholder", required=True)
    ap.add_argument("--contact", required=True)
    ap.add_argument("--host", default="[host/registrar DMCA agent]")
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--now-iso", default=None, help="notice date (ISO); default: prompt to fill")
    ap.add_argument("--cases-dir", default=os.path.join(os.path.dirname(__file__), "..", "cases"))
    args = ap.parse_args()

    attr = _attribute(open(args.token_file).read().strip())
    if not attr.get("buyer_id"):
        sys.exit("no buyer_id in the token — cannot attribute; is this a licence token?")
    if not attr.get("ok"):
        print(f"WARNING: token signature did NOT verify ({attr.get('reason')}) — buyer_id is CLAIMED, "
              f"not proven. State this in the notice.", file=sys.stderr)

    fields = {
        "host_or_registrar": args.host,
        "rightsholder_name": args.rightsholder,
        "rightsholder_contact": args.contact,
        "notice_date": args.now_iso or "[FILL DATE]",
        "infringing_url": args.infringing_url,
        "buyer_id": str(attr.get("buyer_id")),
        "license_id": str(attr.get("license_id")),
        "key_id": str(attr.get("signature_key_id") or "unverified"),
        "signature_verified": "yes" if attr.get("ok") else f"NO ({attr.get('reason')})",
        "tier": str(attr.get("tier")),
        "issued_at": str(attr.get("issued_at")),
        "case_id": args.case_id,
    }
    notice = open(_TEMPLATE).read()
    for k, v in fields.items():
        notice = notice.replace("{{" + k + "}}", v)

    case_dir = os.path.abspath(os.path.join(args.cases_dir, args.case_id))
    os.makedirs(case_dir, exist_ok=True)
    with open(os.path.join(case_dir, "notice.md"), "w") as f:
        f.write(notice)
    with open(os.path.join(case_dir, "attribution.json"), "w") as f:
        json.dump(attr, f, indent=2)
    print(f"case written: {case_dir}")
    print(f"  buyer_id={fields['buyer_id']} license_id={fields['license_id']} "
          f"signature_verified={fields['signature_verified']}")
    print("  NEXT: revoke this license_id (tools/mint_crl.py), review notice.md with counsel, then send.")


if __name__ == "__main__":
    main()
