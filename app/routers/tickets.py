"""Ticket / triage subsystem — the authoritative ticket store (source of truth).

Schema mirrors netplex/docs/platform/support-system.md §3.1. priority_score = sev × occ × tier.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_admin
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
    # §5.3 (2026-07-28): previously MISSING here entirely - a bundle/attachment could
    # be persisted on the row (models.py) but was invisible through every admin-facing
    # endpoint, since this view never surfaced either column. has_diagnostic_bundle /
    # attachment_refs make the transport actually USEFUL to an admin, not just present
    # in the database. The full diagnostic_json text is intentionally NOT inlined here
    # (it can be tens of KB - triage_queue lists every open ticket at once) - a
    # follow-up per-ticket detail endpoint is the natural place for the full bundle;
    # this flag is enough to tell an admin scanning the queue that one exists.
    has_diagnostic_bundle: bool = False
    attachment_refs: list[str] = []

    @classmethod
    def of(cls, t: Ticket) -> "TicketView":
        import json as _json
        refs: list[str] = []
        if t.attachments:
            try:
                refs = _json.loads(t.attachments)
            except (ValueError, TypeError):
                refs = []
        return cls(
            id=t.id, kind=t.kind, status=t.status, severity=t.severity, title=t.title,
            occurrences=t.occurrences, reporter_tier=t.reporter_tier,
            priority_score=t.priority_score, fixed_in_version=t.fixed_in_version, source=t.source,
            has_diagnostic_bundle=bool(t.diagnostic_json),
            attachment_refs=refs,
        )


@router.get("/admin/queue", dependencies=[Depends(require_admin)])
async def triage_queue(limit: int = 100, session: AsyncSession = Depends(get_session)):
    """Admin triage queue — open tickets ordered by priority_score desc.

    Operator-only: gated on ADMIN_API_TOKENS (fail-closed). Previously this had only a
    `TODO: admin auth` and handed the full triage queue to any anonymous caller (W15.4)."""
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


@router.get("/{ticket_id}/diagnostic", dependencies=[Depends(require_admin)])
async def get_ticket_diagnostic(ticket_id: str, session: AsyncSession = Depends(get_session)):
    """Admin-only: the FULL diagnostic bundle attached to a ticket (§5.3).

    Deliberately separate from the plain ticket view (TicketView.of only exposes a
    `has_diagnostic_bundle` flag + attachment refs, kept small since the triage queue
    lists every open ticket at once) - this is the "click through to see it" detail
    endpoint an admin needs once has_diagnostic_bundle says one exists. Never public:
    even though the bundle is already redacted before it reaches this server, it is
    real operational detail about a customer's host (CPU/RAM/log lines), not a public
    payload.
    """
    t = await get_ticket(session, ticket_id)
    if t is None:
        raise HTTPException(404, "ticket not found")
    import json as _json
    diagnostic_bundle = None
    if t.diagnostic_json:
        try:
            diagnostic_bundle = _json.loads(t.diagnostic_json)
        except (ValueError, TypeError):
            diagnostic_bundle = t.diagnostic_json  # not JSON-shaped; return raw text as-is
    attachment_refs: list[str] = []
    if t.attachments:
        try:
            attachment_refs = _json.loads(t.attachments)
        except (ValueError, TypeError):
            attachment_refs = []
    return {"id": t.id, "diagnostic_bundle": diagnostic_bundle, "attachment_refs": attachment_refs}
