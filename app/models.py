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
    """Format 'NPX-XXXXXX' (6 uppercase hex chars)."""
    return "NPX-" + secrets.token_hex(3).upper()


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
    license_id_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    scope_path: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    priority_score: Mapped[int] = mapped_column(Integer, default=0)
    github_issue: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    fixed_in_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


# ───────────────────────────── async store ─────────────────────────────

async def create_or_dedupe(session: AsyncSession, **fields) -> Ticket:
    """Create a ticket, or — if `fingerprint` matches an OPEN ticket — bump its occurrences.

    Recomputes priority_score on every (severity, occurrences, tier). Returns the live Ticket.
    """
    fingerprint = fields.get("fingerprint")
    severity = fields.get("severity", "s2_broken")
    tier = fields.get("reporter_tier", "associate")

    if fingerprint:
        stmt = (
            select(Ticket)
            .where(Ticket.fingerprint == fingerprint, Ticket.status.in_(OPEN_STATES))
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
        license_id_hash=fields.get("license_id_hash"),
        scope_path=fields.get("scope_path"),
        priority_score=priority_score(severity, fields.get("occurrences", 1), tier),
        github_issue=fields.get("github_issue"),
        fixed_in_version=fields.get("fixed_in_version"),
    )
    session.add(ticket)
    await session.commit()
    await session.refresh(ticket)
    return ticket


async def get_ticket(session: AsyncSession, ticket_id: str) -> Optional[Ticket]:
    return (
        await session.execute(select(Ticket).where(Ticket.id == ticket_id))
    ).scalar_one_or_none()


async def admin_queue(session: AsyncSession, limit: int = 100) -> list[Ticket]:
    """Open tickets only, highest priority_score first."""
    stmt = (
        select(Ticket)
        .where(Ticket.status.in_(OPEN_STATES))
        .order_by(Ticket.priority_score.desc(), Ticket.last_seen.desc())
        .limit(limit)
    )
    return list((await session.execute(stmt)).scalars().all())
