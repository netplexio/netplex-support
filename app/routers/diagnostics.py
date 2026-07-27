"""Diagnostics destination — receives OPT-IN, already-redacted reports.

Two live intakes:
- POST /forward  — a box forwards an (already-redacted) report → ticket, source="forward".
- POST /web      — PUBLIC website-submitted report → ticket, source="web" (IP rate-limited).

Reports are expected pre-redacted on the box (local-only privacy); size/type are re-validated as
defence in depth. Email intake is a marked stub (no real inbox poller here).
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import client_ip
from app.config import settings
from app.db import get_session
from app.models import create_or_dedupe
from app.ratelimit import rate_ok
from app.routers.licensing import _trust_store, _verify_token

router = APIRouter(prefix="/api/v1/diagnostics", tags=["diagnostics"])


def _require_forward_auth(request: Request) -> None:
    """Machine-to-machine auth for /forward. Fail-CLOSED: if no token is configured,
    the endpoint is disabled entirely (503) rather than accepting anonymous forwards.
    Constant-time compare against any of the configured (comma-separated) tokens."""
    configured = [t.strip() for t in settings.FORWARD_INTAKE_TOKENS.split(",") if t.strip()]
    if not configured:
        raise HTTPException(503, "forward intake is not configured on this server")
    auth = request.headers.get("authorization", "")
    presented = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    if not presented or not any(hmac.compare_digest(presented, t) for t in configured):
        raise HTTPException(401, "invalid or missing intake token")


class ForwardedReport(BaseModel):
    kind: Literal["crash", "bug", "feature", "license"] = "crash"
    fingerprint: Optional[str] = Field(default=None, max_length=128)
    title: str = Field(max_length=200)
    body: str = Field(default="", max_length=10000)
    severity: str = Field(default="s2_broken", max_length=16)
    platform_version: str = Field(default="", max_length=64)
    # tier/identity — present only for identified (paid) tiers
    reporter_tier: str = Field(default="associate", max_length=32)
    install_id: Optional[str] = Field(default=None, max_length=128)
    license_token: Optional[str] = Field(default=None, max_length=4096)
    contact: Optional[str] = Field(default=None, max_length=256)
    attachment_refs: list[str] = Field(default_factory=list, max_length=10)


class WebReport(BaseModel):
    """Website intake — anonymous by default; a contact is optional and self-asserted."""
    kind: Literal["crash", "bug", "feature", "license"] = "bug"
    fingerprint: Optional[str] = Field(default=None, max_length=128)
    title: str = Field(max_length=200)
    body: str = Field(default="", max_length=10000)
    severity: str = Field(default="s3_degraded", max_length=16)
    contact: Optional[str] = Field(default=None, max_length=256)


@router.post("/forward", status_code=202)
async def receive_forwarded(
    report: ForwardedReport, request: Request, session: AsyncSession = Depends(get_session)
):
    """Accept a forwarded, already-redacted report → create/dedupe a ticket (source=forward).

    Authenticated (Bearer token, fail-closed) and rate-limited PER INSTALL so one box
    can't hammer the intake - closes the 2026-07-11 gap where this hop had neither."""
    _require_forward_auth(request)
    # SECURITY (adversarial sweep 2026-07-27, P1): install_id is a free-form,
    # caller-supplied string with no format/ownership check (ForwardedReport.install_id,
    # max_length=128 only) - keying the budget SOLELY on it let any holder of the shared
    # FORWARD_INTAKE_TOKENS value (distributed to every forwarding netplex box by design,
    # so effectively "any registered install", not a privileged secret) send a fresh
    # random install_id on every call and get a brand-new rate-limit bucket every time,
    # making the 30/min budget meaningless - unbounded ticket-row/DB growth from a single
    # source. Enforce BOTH keys: the per-install_id budget (as originally intended, so one
    # legitimate box can't drown out others) AND a per-IP budget the caller cannot
    # cheaply rotate (unlike install_id, an IP address costs real infrastructure to
    # change) - either ceiling being hit rejects the call.
    ip = client_ip(request)
    limit = max(int(getattr(settings, "INTAKE_RATE_PER_MIN", 30)), 1)
    # Check the IP ceiling FIRST (short-circuit): it's the one an attacker can't
    # cheaply rotate, so if it's already exhausted there's no reason to also spend a
    # slot in the (rotatable) per-install_id bucket for a request that's being
    # rejected anyway.
    if not rate_ok(f"fwd:ip:{ip}", limit):
        raise HTTPException(429, "forward rate limit exceeded - back off")
    if not rate_ok(f"fwd:install:{report.install_id or ip}", limit):
        raise HTTPException(429, "forward rate limit exceeded - back off")

    # SECURITY (adversarial sweep 2026-07-27, P2): report.reporter_tier was trusted
    # AS-IS - any caller holding the shared, fleet-wide FORWARD_INTAKE_TOKENS value
    # could set "reporter_tier": "master" on every report with zero proof of
    # entitlement. TIER_WEIGHT (app/models.py) gives master/enterprise a 5x
    # multiplier on priority_score, so this let anyone jump the admin triage queue
    # ahead of genuine paying customers. report.license_token WAS accepted by the
    # schema but never actually verified anywhere - licensing.py's own
    # _verify_token/_trust_store (the SAME primitives /license/verify uses) were
    # simply never wired in here, despite the design doc (support-system.md §3.1)
    # describing license_id_hash as existing specifically "to verify tier without
    # storing the raw license". Fail closed: reporter_tier is now "associate" (the
    # floor) UNLESS a genuine, cryptographically-verified license_token is presented
    # - the self-asserted field is never trusted directly, matching the same
    # verify-don't-trust posture as /license/verify itself. license_id_hash is a
    # hash of the token (not the raw token, matching the design doc's intent) so a
    # ticket can be correlated back to a license without persisting it.
    verified_tier = "associate"
    license_id_hash = None
    if report.license_token:
        result = _verify_token(report.license_token, _trust_store())
        if result.valid:
            verified_tier = result.tier or "associate"
            license_id_hash = hashlib.sha256(report.license_token.encode()).hexdigest()

    ticket = await create_or_dedupe(
        session,
        kind=report.kind,
        fingerprint=report.fingerprint,
        title=report.title,
        body=report.body,
        severity=report.severity,
        source="forward",
        reporter_tier=verified_tier,
        identified=bool(report.contact),
        contact=report.contact,
        install_id=report.install_id,
        license_id_hash=license_id_hash,
    )
    return {
        "accepted": True,
        "ticket_id": ticket.id,
        "occurrences": ticket.occurrences,
        "priority_score": ticket.priority_score,
        "kind": ticket.kind,
    }


@router.post("/web", status_code=202)
async def receive_web(
    report: WebReport, request: Request, session: AsyncSession = Depends(get_session)
):
    """PUBLIC website intake → create/dedupe a ticket (source=web). IP rate-limited
    (trusted-proxy-aware — see app/auth.py:client_ip)."""
    ip = client_ip(request)
    limit = max(int(getattr(settings, "WEB_INTAKE_RATE_PER_MIN", 10)), 1)
    if not rate_ok(f"web:{ip}", limit):
        raise HTTPException(429, "rate limit exceeded — slow down")

    ticket = await create_or_dedupe(
        session,
        kind=report.kind,
        fingerprint=report.fingerprint,
        title=report.title,
        body=report.body,
        severity=report.severity,
        source="web",
        reporter_tier="associate",
        identified=bool(report.contact),
        contact=report.contact,
    )
    return {"accepted": True, "ticket_id": ticket.id, "occurrences": ticket.occurrences}


# ─────────────────────────── email intake (STUB) ───────────────────────────
# STUB ONLY — no real inbox poller. A production deployment would run an out-of-band worker
# (IMAP/SES inbound webhook) that parses support@ mail, redacts, and calls create_or_dedupe with
# source="email". Intentionally not built here (no mailbox credentials in this repo).
async def ingest_email_stub(*args, **kwargs):  # pragma: no cover - intentional stub
    raise NotImplementedError("email intake is a stub; wire an IMAP/SES worker out-of-band")
