"""Ticket model + async store (source-of-truth ticket DB).

Schema mirrors netplex/docs/platform/support-system.md §3.1. Dedupe is by `fingerprint`: a new
forwarded report whose fingerprint already has an OPEN ticket bumps `occurrences` + `last_seen`
instead of creating a row. priority_score = severity_weight × occurrences × tier_weight.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, Integer, String, Text, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base

# severity / tier weights — priority_score = sev × occ × tier (support-system.md §3.3)
SEVERITY_WEIGHT = {"s1_crash": 16, "s2_broken": 8, "s3_degraded": 4, "s4_cosmetic": 2, "s5_idea": 1}
TIER_WEIGHT = {"master": 5, "enterprise": 5, "team": 4, "architect": 4,
               "professional": 3, "class": 3, "associate": 1}

# A ticket is OPEN (eligible for fingerprint dedupe + admin queue) in these states.
OPEN_STATES = ("new", "triaged", "in_progress", "fixed")


def priority_score(severity: str, occurrences: int, tier: str) -> int:
    return SEVERITY_WEIGHT.get(severity, 4) * max(occurrences, 1) * TIER_WEIGHT.get(tier, 1)


def new_ticket_id() -> str:
    """Format 'SUP-XXXXXXXXXXXX' (12 uppercase hex chars = 48 bits).

    Widened from 24 bits (F-S3): 24 bits is both a collision risk (birthday bound ~4k
    tickets) and small enough to enumerate against the unauthenticated GET /tickets/{id}.
    48 bits (still within the String(16) id column: 'SUP-' + 12 = 16) makes both
    infeasible.

    Prefix changed from 'NPX-' to 'SUP-' (2026-08-30, war-room T13b): this repo is a
    LEGACY INTAKE, not the ticket authority (netplex-control is, see ECOSYSTEM.md
    "TICKET IDENTITY" / T13) - it mints ids only for its own local rows, never
    pretending to be the box's receipt. Before this change, `new_ticket_id()` here and
    the box's own local id (netplex/backend/api-gateway/routers/ticket_model.py
    `_new_id()`) minted the EXACT SAME "NPX-" + 12-hex-char format from two entirely
    different databases - a same-looking id could mean two different rows and nothing
    could tell them apart. 'SUP-' makes a netplex-support id and a box-local netplex
    id visually distinguishable at a glance, closing that ambiguity without touching
    the box-local format (which stays 'NPX-') or netplex-control's authority format
    ('T-NNNNNN', backend/app/tickets.py) - neither of those was ever the problem."""
    return "SUP-" + secrets.token_hex(6).upper()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Ticket(Base):
    __tablename__ = "tickets"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), default="crash")
    fingerprint: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="new")
    severity: Mapped[str] = mapped_column(String(16), default="s2_broken")
    title: Mapped[str] = mapped_column(String(200))
    body: Mapped[str] = mapped_column(Text, default="")
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    source: Mapped[str] = mapped_column(String(16), default="web")  # web|email|forward|app
    reporter_tier: Mapped[str] = mapped_column(String(32), default="associate")
    identified: Mapped[bool] = mapped_column(Boolean, default=False)
    contact: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    install_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    # T13a (2026-08-30 war-room): the box's OWN local ticket id (the "NPX-..." id the
    # reporter was actually shown, minted by netplex/backend/api-gateway/routers/
    # ticket_model.py `_new_id()`) - mirrors netplex-control's `tickets.origin_local_id`
    # (backend/app/models.py) so the same box-local id resolves to a row on EITHER
    # upstream, not just the authoritative one. Before this field existed, a forwarded
    # report could only be resolved back to the reporting box via
    # (fingerprint, install_id) - ambiguous once a box had filed more than one report.
    # Indexed: this is exactly the lookup key get_ticket_by_origin_local_id uses.
    origin_local_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    license_id_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    scope_path: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    priority_score: Mapped[int] = mapped_column(Integer, default=0)
    github_issue: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    fixed_in_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    # §5.3 (2026-07-28): bundle transport. `attachments` is a JSON-encoded list of blob
    # descriptors ({sha256,url,mime,bytes,redacted} - see app/storage/blobs.py) - was
    # ALWAYS discarded before (ForwardedReport.attachment_refs was accepted, never
    # persisted). `diagnostic_json` is a JSON-encoded, ALREADY-REDACTED health/host/
    # labs/log-tail snapshot (mirrors docs/platform/support-system.md §3.1's
    # documented-but-never-implemented `diagnostic_json JSONB` column) - the box
    # redacts before sending; this server re-validates size/shape as defence in depth,
    # it does not itself scrub (it has no redaction rules of its own to apply).
    attachments: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    diagnostic_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


# ───────────────────────────── async store ─────────────────────────────

async def create_or_dedupe(session: AsyncSession, **fields) -> Ticket:
    """Create a ticket, or — if `fingerprint` matches an OPEN ticket **from the same
    source** — bump its occurrences.

    Recomputes priority_score on every (severity, occurrences, tier). Returns the live Ticket.

    SECURITY (§5.3, 2026-07-28): dedupe is now scoped to `(fingerprint, source)`, not
    `fingerprint` alone. `POST /diagnostics/web` is PUBLIC and unauthenticated, and its
    `fingerprint` is entirely caller-chosen (WebReport.fingerprint, no server-side
    computation, no ownership check) - with the OLD fingerprint-only query, anyone
    could pre-POST a `source=web` ticket at a fingerprint value they expect a REAL
    crash to use later (crash fingerprints are a deterministic
    sha1(normalized_message + top_3_frames) over a known, guessable bug signature),
    and every subsequent authenticated `source=forward` occurrence of that real crash
    would silently merge into the attacker's pre-seeded ticket - inheriting whatever
    title/body/contact the attacker planted, and inflating occurrences/priority_score
    with fabricated history. Scoping the match to the SAME source closes this: an
    anonymous `web` submission can only ever dedupe against other anonymous `web`
    submissions (still real work, still rate-limited per-IP, but can never poison an
    authenticated `forward` ticket's identity), and a `forward` submission (from an
    authenticated, token-holding box) can only dedupe against other `forward`
    submissions - exactly the "repeated identical report" case dedupe exists for.
    """
    fingerprint = fields.get("fingerprint")
    severity = fields.get("severity", "s2_broken")
    tier = fields.get("reporter_tier", "associate")
    source = fields.get("source", "web")

    if fingerprint:
        stmt = (
            select(Ticket)
            .where(
                Ticket.fingerprint == fingerprint,
                Ticket.source == source,
                Ticket.status.in_(OPEN_STATES),
            )
            .order_by(Ticket.first_seen.asc())
            .limit(1)
        )
        existing = (await session.execute(stmt)).scalar_one_or_none()
        if existing is not None:
            existing.occurrences += 1
            existing.last_seen = _utcnow()
            existing.priority_score = priority_score(
                existing.severity, existing.occurrences, existing.reporter_tier
            )
            await session.commit()
            await session.refresh(existing)
            return existing

    now = _utcnow()
    ticket = Ticket(
        id=new_ticket_id(),
        kind=fields.get("kind", "crash"),
        fingerprint=fingerprint,
        status=fields.get("status", "new"),
        severity=severity,
        title=fields.get("title", ""),
        body=fields.get("body", ""),
        occurrences=fields.get("occurrences", 1),
        first_seen=now,
        last_seen=now,
        source=fields.get("source", "web"),
        reporter_tier=tier,
        identified=fields.get("identified", False),
        contact=fields.get("contact"),
        install_id=fields.get("install_id"),
        origin_local_id=fields.get("origin_local_id"),
        license_id_hash=fields.get("license_id_hash"),
        scope_path=fields.get("scope_path"),
        priority_score=priority_score(severity, fields.get("occurrences", 1), tier),
        github_issue=fields.get("github_issue"),
        fixed_in_version=fields.get("fixed_in_version"),
        attachments=fields.get("attachments"),
        diagnostic_json=fields.get("diagnostic_json"),
    )
    session.add(ticket)
    await session.commit()
    await session.refresh(ticket)
    return ticket


async def get_ticket(session: AsyncSession, ticket_id: str) -> Optional[Ticket]:
    return (
        await session.execute(select(Ticket).where(Ticket.id == ticket_id))
    ).scalar_one_or_none()


async def get_ticket_by_origin_local_id(
    session: AsyncSession, origin_local_id: str
) -> Optional[Ticket]:
    """T13a: resolve a forwarded report back to the reporting box's own row, keyed on
    the box-local id it was actually shown — unambiguous even when a box has filed more
    than one report (unlike the old fingerprint+install_id-only resolution). Most
    recent first, matching create_or_dedupe's own dedupe-then-create ordering."""
    stmt = (
        select(Ticket)
        .where(Ticket.origin_local_id == origin_local_id)
        .order_by(Ticket.first_seen.desc())
        .limit(1)
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def admin_queue(session: AsyncSession, limit: int = 100) -> list[Ticket]:
    """Open tickets only, highest priority_score first."""
    stmt = (
        select(Ticket)
        .where(Ticket.status.in_(OPEN_STATES))
        .order_by(Ticket.priority_score.desc(), Ticket.last_seen.desc())
        .limit(limit)
    )
    return list((await session.execute(stmt)).scalars().all())


# ─────────────────────── release manifests (signed, offline) ───────────────────────
# Rows here are ALREADY-VERIFIED manifests: app/routers/releases.py's /upload only ever
# inserts a row after app.crypto.signing.verify_manifest passed against the PUBLIC
# signing trust store. No private key material is ever stored — manifest_json is the
# full signed manifest exactly as uploaded (including its signature block), so a box
# fetching it can independently re-verify against its own baked-in trust store too.
# Append-only (never overwritten in place): every accepted upload is a new row, so
# GET /releases/manifest/{channel} serving "the latest" is a query, not a destructive
# write, and history/rollback stay possible.

class ReleaseManifest(Base):
    __tablename__ = "release_manifests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    channel: Mapped[str] = mapped_column(String(32), index=True)
    version: Mapped[str] = mapped_column(String(64), default="")
    key_id: Mapped[str] = mapped_column(String(32), default="")
    manifest_json: Mapped[str] = mapped_column(Text)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


async def store_release_manifest(
    session: AsyncSession, *, channel: str, version: str, key_id: str, manifest_json: str
) -> ReleaseManifest:
    row = ReleaseManifest(
        channel=channel, version=version, key_id=key_id, manifest_json=manifest_json
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return row


async def latest_release_manifest(session: AsyncSession, channel: str) -> Optional[ReleaseManifest]:
    stmt = (
        select(ReleaseManifest)
        .where(ReleaseManifest.channel == channel)
        .order_by(ReleaseManifest.id.desc())
        .limit(1)
    )
    return (await session.execute(stmt)).scalar_one_or_none()


# ─────────────────────── license tokens (signed, offline) ───────────────────────
# Same shape/boundary as release manifests above: a row only ever exists after
# app.routers.licensing's /register verified the token against the PUBLIC license
# trust store. Append-only per customer_ref so re-registering (renewal, tier change)
# never loses the prior record.

class LicenseToken(Base):
    __tablename__ = "license_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    customer_ref: Mapped[str] = mapped_column(String(256), index=True, default="")
    key_id: Mapped[str] = mapped_column(String(32), default="")
    tier: Mapped[str] = mapped_column(String(32), default="")
    expires_at: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    token_json: Mapped[str] = mapped_column(Text)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


async def store_license_token(
    session: AsyncSession,
    *,
    customer_ref: str,
    key_id: str,
    tier: str,
    expires_at: Optional[int],
    token_json: str,
) -> LicenseToken:
    row = LicenseToken(
        customer_ref=customer_ref,
        key_id=key_id,
        tier=tier,
        expires_at=expires_at,
        token_json=token_json,
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return row


async def latest_license_token_for(session: AsyncSession, customer_ref: str) -> Optional[LicenseToken]:
    stmt = (
        select(LicenseToken)
        .where(LicenseToken.customer_ref == customer_ref)
        .order_by(LicenseToken.id.desc())
        .limit(1)
    )
    return (await session.execute(stmt)).scalar_one_or_none()
