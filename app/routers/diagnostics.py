"""Diagnostics destination - receives OPT-IN, already-redacted reports.

Three live intakes:
- POST /forward - a box forwards an (already-redacted) report → ticket, source="forward".
- POST /web - PUBLIC website-submitted report → ticket, source="web" (IP rate-limited).
- POST /attachment - upload one blob (screenshot, or any future binary attachment) →
  content-addressed descriptor, referenced by a later /forward's `attachment_refs`.

Reports are expected pre-redacted on the box (local-only privacy); size/type are re-validated as
defence in depth. Email intake is a marked stub (no real inbox poller here).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
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
from app.storage.blobs import put_blob

router = APIRouter(prefix="/api/v1/diagnostics", tags=["diagnostics"])

# §5.3: the route-specific body-size exception the global 64KB cap
# (app/main.py::_BodySizeLimitASGI, settings.MAX_REQUEST_BODY_BYTES) needs for this ONE
# endpoint - a blob (screenshot, up to MAX_BLOB_BYTES=5MB) base64-encoded (~1.37x
# overhead) plus JSON framing simply cannot fit in 64KB. Read by the middleware (see
# app/main.py) by exact path match - every OTHER route keeps the tight 64KB default.
ATTACHMENT_ROUTE_PATH = "/api/v1/diagnostics/attachment"


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
    # tier/identity - present only for identified (paid) tiers
    reporter_tier: str = Field(default="associate", max_length=32)
    install_id: Optional[str] = Field(default=None, max_length=128)
    # T13a (2026-08-30 war-room): the box's OWN local ticket id (its "NPX-..." receipt,
    # minted by netplex/backend/api-gateway/routers/ticket_model.py `_new_id()`) - mirrors
    # netplex-control's `tickets.origin_local_id` field/precedent (backend/app/models.py).
    # Was previously entirely absent here, so a forwarded report landing on this side
    # could only be resolved back to the reporting box via (fingerprint, install_id) -
    # ambiguous once a box had filed more than one report. Optional/max_length=32 to
    # match the column and the box-local id's own format (max seen: "NPX-" + 12 hex).
    origin_local_id: Optional[str] = Field(default=None, max_length=32)
    license_token: Optional[str] = Field(default=None, max_length=4096)
    contact: Optional[str] = Field(default=None, max_length=256)
    attachment_refs: list[str] = Field(default_factory=list, max_length=10)
    # §5.3: an already-redacted health/host/labs/log-tail snapshot, JSON-serialized by
    # the sending box (backend/shared/redact.py's scrub_secrets_deep already ran there
    # before this ever left the box). Size-capped well under the route's raised body
    # limit (see ATTACHMENT_ROUTE_PATH / main.py) so a single oversized bundle can't
    # itself become a DoS vector on a route already sized up for attachments.
    diagnostic_bundle: Optional[str] = Field(default=None, max_length=200_000)


class WebReport(BaseModel):
    """Website intake - anonymous by default; a contact is optional and self-asserted."""
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

    # §5.3: attachment_refs was accepted by the schema then silently discarded here -
    # blobs.put_blob (app/storage/blobs.py) had zero callers anywhere, and this was the
    # one place that should have persisted a ref once uploaded via POST /attachment
    # below. Stored as a JSON list on the ticket row (bounded to 10 refs by the
    # Pydantic field itself); diagnostic_bundle is stored as-is (already redacted +
    # size-capped on the sending side, re-capped here by the Pydantic max_length above).
    attachments_json = json.dumps(report.attachment_refs) if report.attachment_refs else None

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
        origin_local_id=report.origin_local_id,
        license_id_hash=license_id_hash,
        attachments=attachments_json,
        diagnostic_json=report.diagnostic_bundle,
    )
    return {
        "accepted": True,
        "ticket_id": ticket.id,
        "occurrences": ticket.occurrences,
        "priority_score": ticket.priority_score,
        "kind": ticket.kind,
        "origin_local_id": ticket.origin_local_id,
    }


# ─────────────────────────── attachment (blob) upload ───────────────────────────

class AttachmentUpload(BaseModel):
    """One blob, base64-encoded. JSON (not multipart) to match this service's existing
    intake style (every other route here is a plain JSON POST) and to keep the
    content-length accounting in _BodySizeLimitASGI simple (one exact route-path
    exception, see ATTACHMENT_ROUTE_PATH, rather than a second multipart-parsing path)."""

    mime: str = Field(max_length=32)
    data_b64: str = Field(max_length=8_000_000)  # ~5.8MB raw after base64 decode, capped again below


@router.post("/attachment", status_code=201)
async def upload_attachment(upload: AttachmentUpload, request: Request):
    """Upload one attachment blob (screenshot or other binary) → content-addressed
    descriptor. Same machine-to-machine auth as /forward (fail-closed) - an attachment
    is only ever produced by a netplex box that's already forwarding a report, never a
    standalone anonymous upload surface. The returned `sha256` is what a later
    /forward call passes in `attachment_refs`.

    §5.3: this is the caller `blobs.put_blob` (app/storage/blobs.py) never had -
    nothing anywhere in this service invoked it. Real object-store wiring
    (`settings.OBJECT_STORE_URL`) is still a scaffold (see that module's own TODO);
    what changed here is that the upload SURFACE, auth, size/mime validation, and the
    dedupe-by-content-hash guarantee are now real and reachable, not dead code.
    """
    _require_forward_auth(request)
    try:
        data = base64.b64decode(upload.data_b64, validate=True)
    except Exception as exc:
        raise HTTPException(400, f"data_b64 is not valid base64: {exc}") from exc
    try:
        descriptor = put_blob(data, upload.mime, settings.MAX_BLOB_BYTES)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return descriptor


@router.post("/web", status_code=202)
async def receive_web(
    report: WebReport, request: Request, session: AsyncSession = Depends(get_session)
):
    """PUBLIC website intake → create/dedupe a ticket (source=web). IP rate-limited
    (trusted-proxy-aware - see app/auth.py:client_ip)."""
    ip = client_ip(request)
    limit = max(int(getattr(settings, "WEB_INTAKE_RATE_PER_MIN", 10)), 1)
    if not rate_ok(f"web:{ip}", limit):
        raise HTTPException(429, "rate limit exceeded - slow down")

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


# ─────────────────────────── email intake ───────────────────────────────────
# P3 tickets chain (2026-07-28): replaces the previous dead stub (ingest_email_stub
# raised NotImplementedError and, worse, was never even registered as a route - no
# amount of retrying would have reached it). This is a REAL, working, fail-closed
# endpoint - the same shape as /forward and /web above, ingesting via the same
# create_or_dedupe(source="email", ...) the model has always documented as a valid
# source (models.py: "web|email|forward|app") but never had a single caller for.
#
# Deployment note (genuine external blocker, distinct from the code gap this closes):
# this endpoint is ready today, but nothing calls it until support@netplex.io's actual
# mailbox is configured to forward inbound mail here. That is Khaled's mail-provider
# choice (Mailgun inbound routes / SES inbound + Lambda / Postmark inbound webhook) +
# that provider's credentials - neither exists in this repo, and no autonomous agent
# can provision a real mailbox or its DNS/MX records. Once a provider is chosen, its
# own small transform step (or a thin bridge worker, if its native webhook shape needs
# normalizing) calls THIS endpoint with EmailReport below, authenticated by
# EMAIL_INTAKE_SECRETS - deliberately provider-agnostic rather than coupling this
# server to one vendor's native payload shape.


class EmailReport(BaseModel):
    """Normalized inbound-email payload - the mail-forwarding provider/worker's own
    transform step produces this, whatever its native webhook shape is."""
    from_email: str = Field(max_length=256)
    subject: str = Field(default="", max_length=200)
    body: str = Field(default="", max_length=10000)


def _require_email_auth(request: Request) -> None:
    """Fail-CLOSED, same pattern as _require_forward_auth above: if no secret is
    configured, the endpoint is disabled entirely (503) rather than accepting
    anonymous mail. support@netplex.io mail carries no authentication of its own (a
    From: header is trivially spoofable) - the shared secret, held only by the
    mail-forwarding worker, is the ONLY trust boundary here."""
    configured = [t.strip() for t in settings.EMAIL_INTAKE_SECRETS.split(",") if t.strip()]
    if not configured:
        raise HTTPException(503, "email intake is not configured on this server")
    auth = request.headers.get("authorization", "")
    presented = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    if not presented or not any(hmac.compare_digest(presented, t) for t in configured):
        raise HTTPException(401, "invalid or missing intake token")


@router.post("/email", status_code=202)
async def receive_email(
    report: EmailReport, request: Request, session: AsyncSession = Depends(get_session)
):
    """Ingest one inbound support@netplex.io message → create/dedupe a ticket
    (source=email). IP-rate-limited on top of the auth token (same reasoning as
    /web: a misconfigured forwarding worker retrying a bounce shouldn't be able to
    flood ticket creation just because it holds a valid secret)."""
    _require_email_auth(request)
    ip = client_ip(request)
    limit = max(int(getattr(settings, "WEB_INTAKE_RATE_PER_MIN", 10)), 1)
    if not rate_ok(f"email:{ip}", limit):
        raise HTTPException(429, "rate limit exceeded - slow down")

    ticket = await create_or_dedupe(
        session,
        kind="bug",
        title=report.subject or "(no subject)",
        body=report.body,
        severity="s3_degraded",
        source="email",
        reporter_tier="associate",
        identified=True,
        contact=report.from_email,
    )
    return {"accepted": True, "ticket_id": ticket.id, "occurrences": ticket.occurrences}
