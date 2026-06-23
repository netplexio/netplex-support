"""Ticket / triage subsystem — the authoritative ticket store (source of truth).

Schema mirrors netplex/docs/platform/support-system.md §3.1. priority_score = sev × occ × tier.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.models import (  # re-exported for callers/tests
    SEVERITY_WEIGHT,
    TIER_WEIGHT,
    Ticket,
    admin_queue,
    get_ticket,
    priority_score,
)

router = APIRouter(prefix="/api/v1/tickets", tags=["tickets"])

__all__ = ["router", "SEVERITY_WEIGHT", "TIER_WEIGHT", "priority_score"]


class TicketView(BaseModel):
    id: str
    kind: str
    status: str
    severity: str
    title: str
    occurrences: int = 1
    reporter_tier: str = "associate"
    priority_score: Optional[int] = None
    fixed_in_version: Optional[str] = None
    source: str = "web"

    @classmethod
    def of(cls, t: Ticket) -> "TicketView":
        return cls(
            id=t.id, kind=t.kind, status=t.status, severity=t.severity, title=t.title,
            occurrences=t.occurrences, reporter_tier=t.reporter_tier,
            priority_score=t.priority_score, fixed_in_version=t.fixed_in_version, source=t.source,
        )


@router.get("/admin/queue")
async def triage_queue(limit: int = 100, session: AsyncSession = Depends(get_session)):
    """Admin triage queue — open tickets ordered by priority_score desc. TODO: admin auth."""
    rows = await admin_queue(session, limit=limit)
    return {"count": len(rows), "tickets": [TicketView.of(t).model_dump() for t in rows]}


@router.get("/claim/{claim_code}", response_model=TicketView)
async def claim_lookup(claim_code: str, session: AsyncSession = Depends(get_session)):
    """Anonymous reporter looks up their ticket by claim code.

    Anonymous claim-code tickets are not implemented yet; lookups 404 cleanly rather than 501.
    """
    raise HTTPException(404, "no ticket for that claim code")


@router.get("/{ticket_id}", response_model=TicketView)
async def get_ticket_route(ticket_id: str, session: AsyncSession = Depends(get_session)):
    """Look up a ticket by ID."""
    t = await get_ticket(session, ticket_id)
    if t is None:
        raise HTTPException(404, "ticket not found")
    return TicketView.of(t)
