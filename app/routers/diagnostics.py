"""Diagnostics destination — receives OPT-IN, already-redacted reports.

Two live intakes:
- POST /forward  — a box forwards an (already-redacted) report → ticket, source="forward".
- POST /web      — PUBLIC website-submitted report → ticket, source="web" (IP rate-limited).

Reports are expected pre-redacted on the box (local-only privacy); size/type are re-validated as
defence in depth. Email intake is a marked stub (no real inbox poller here).
"""
from __future__ import annotations

import hmac
import time
from collections import defaultdict, deque
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db import get_session
from app.models import create_or_dedupe

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


# ── simple in-memory IP rate limiter (per-process; real deploy → Redis) ──
_RATE_WINDOW = 60.0
_hits: dict[str, deque] = defaultdict(deque)


def _rate_ok(client_ip: str, limit: int) -> bool:
    now = time.monotonic()
    q = _hits[client_ip]
    while q and now - q[0] > _RATE_WINDOW:
        q.popleft()
    if len(q) >= limit:
        return False
    q.append(now)
    return True


@router.post("/forward", status_code=202)
async def receive_forwarded(
    report: ForwardedReport, request: Request, session: AsyncSession = Depends(get_session)
):
    """Accept a forwarded, already-redacted report → create/dedupe a ticket (source=forward).

    Authenticated (Bearer token, fail-closed) and rate-limited PER INSTALL so one box
    can't hammer the intake - closes the 2026-07-11 gap where this hop had neither."""
    _require_forward_auth(request)
    # Rate-limit by install_id (falls back to client IP) using the intake budget.
    key = f"fwd:{report.install_id or (request.client.host if request.client else 'unknown')}"
    if not _rate_ok(key, max(int(getattr(settings, "INTAKE_RATE_PER_MIN", 30)), 1)):
        raise HTTPException(429, "forward rate limit exceeded - back off")
    ticket = await create_or_dedupe(
        session,
        kind=report.kind,
        fingerprint=report.fingerprint,
        title=report.title,
        body=report.body,
        severity=report.severity,
        source="forward",
        reporter_tier=report.reporter_tier,
        identified=bool(report.contact),
        contact=report.contact,
        install_id=report.install_id,
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
    """PUBLIC website intake → create/dedupe a ticket (source=web). IP rate-limited."""
    client_ip = request.client.host if request.client else "unknown"
    limit = max(int(getattr(settings, "WEB_INTAKE_RATE_PER_MIN", 10)), 1)
    if not _rate_ok(client_ip, limit):
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
