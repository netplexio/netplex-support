#!/usr/bin/env python3
"""Concurrency VISIBILITY — flag one licence appearing on too many machines (§11.9 Layer 5).

SOFT by design: this NEVER revokes or locks anyone. It turns a check-in ledger into a ranked list of
licences whose distinct-machine count exceeds their purchased seat allowance, for a HUMAN
(sales/support) to look at — typically at renewal. Auto-locking a paying customer on suspicion costs
more than the piracy (their VMs migrate, they reinstall, they run home+work). The calibrated ladder is
notify-first, throttle-candidate-second, human-review-only for the extreme case.

⚠️  This is the ready PRIMITIVE. The live cross-machine check-in feed depends on the release/activation
authority (`app/routers/releases.py`), which is GATED on docs/SECURITY-BLOCKERS.md #1–#5, AND on the
still-open founder decision about phone-home vs air-gap default (licensing.md §11.9 decision points).
Air-gapped / free installs never check in and are never in this report — by design.

Ledger format (JSONL, one check-in per line):
  {"license_id","fingerprint","instance_id","ip_prefix","tier","seats",<ts unix int>:"ts"}

Usage:
  python tools/concurrency_report.py --ledger checkins.jsonl [--window-days 30] [--json]
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict

# Default per-tier seat allowance (distinct machines) when a check-in record carries no explicit
# `seats`. Individual tiers get 2 (home + work) — matches §11.5b Gap 2. 0 = unlimited (Enterprise).
_DEFAULT_SEATS = {
    "free": 1, "associate": 1, "pro": 2, "professional": 2, "architect": 2,
    "team": 0, "classroom": 0, "class": 0, "enterprise": 0, "master": 0,
}


def _seat_allowance(tier: str, explicit) -> int:
    if isinstance(explicit, int) and explicit >= 0:
        return explicit
    return _DEFAULT_SEATS.get((tier or "").lower(), 1)


def _severity(distinct: int, seats: int) -> str:
    """SOFT ladder. seats==0 => unlimited => never flagged."""
    if seats == 0:
        return "ok"
    if distinct <= seats:
        return "ok"
    if distinct <= seats + 2:
        return "notify"          # small overage — email the customer, self-service deactivation
    if distinct <= max(seats * 5, 9):
        return "review"          # likely sharing — sales/support looks at renewal
    return "escalate"            # >=~10x — a key posted somewhere; human review, never auto-revoke


def analyze(records: list[dict], *, window_days: int = 30, now: int | None = None) -> list[dict]:
    """Group check-ins by licence, count distinct machines in the window, apply the SOFT ladder.

    `now` (unix int) is required to window by time; if None, all records are considered (no windowing)
    so the function is deterministic in tests. Returns rows sorted worst-first; ok rows are dropped.
    """
    cutoff = None if now is None else now - window_days * 86400
    by_lic: dict[str, dict] = defaultdict(lambda: {"fps": set(), "instances": set(),
                                                   "ips": set(), "tier": "", "seats": None})
    for r in records:
        lid = r.get("license_id")
        if not lid:
            continue
        ts = r.get("ts")
        if cutoff is not None and isinstance(ts, int) and ts < cutoff:
            continue
        g = by_lic[lid]
        if r.get("fingerprint"):
            g["fps"].add(r["fingerprint"])
        if r.get("instance_id"):
            g["instances"].add(r["instance_id"])
        if r.get("ip_prefix"):
            g["ips"].add(r["ip_prefix"])
        g["tier"] = r.get("tier") or g["tier"]
        if g["seats"] is None and r.get("seats") is not None:
            g["seats"] = r.get("seats")

    out = []
    for lid, g in by_lic.items():
        seats = _seat_allowance(g["tier"], g["seats"])
        distinct = len(g["fps"])
        sev = _severity(distinct, seats)
        if sev == "ok":
            continue
        out.append({
            "license_id": lid, "tier": g["tier"], "seat_allowance": seats,
            "distinct_machines": distinct, "distinct_instances": len(g["instances"]),
            "distinct_ip_prefixes": len(g["ips"]), "severity": sev,
            "action": "soft/human-review only — never auto-revoke",
        })
    order = {"escalate": 0, "review": 1, "notify": 2}
    out.sort(key=lambda x: (order.get(x["severity"], 9), -x["distinct_machines"]))
    return out


def _load(path: str) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:  # noqa: BLE001
                continue
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description="Flag over-seat licences for SOFT human review (never auto-lock).")
    ap.add_argument("--ledger", required=True, help="JSONL check-in ledger")
    ap.add_argument("--window-days", type=int, default=30)
    ap.add_argument("--now", type=int, default=None, help="unix 'now' for windowing (omit = no window)")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    args = ap.parse_args()

    flags = analyze(_load(args.ledger), window_days=args.window_days, now=args.now)
    if args.json:
        print(json.dumps(flags, indent=2))
    else:
        if not flags:
            print("no over-seat licences — nothing to review")
        for f in flags:
            print(f"[{f['severity']:>8}] {f['license_id']}  tier={f['tier'] or '?'}  "
                  f"machines={f['distinct_machines']}/{f['seat_allowance'] or '∞'}  "
                  f"ips={f['distinct_ip_prefixes']}  → {f['action']}")
    sys.exit(0)


if __name__ == "__main__":
    main()
