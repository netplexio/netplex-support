"""Ticket / triage subsystem — the authoritative ticket store (source of truth).

SCAFFOLD: defines the API surface. Schema mirrors netplex/docs/platform/support-system.md §3.1.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/tickets", tags=["tickets"])

# severity / tier weights — see support-system.md §3.3 (priority_score = sev × occ × tier)
SEVERITY_WEIGHT = {"s1_crash": 16, "s2_broken": 8, "s3_degraded": 4, "s4_cosmetic": 2, "s5_idea": 1}
TIER_WEIGHT = {"master": 5, "enterprise": 5, "team": 4, "architect": 4,
               "professional": 3, "class": 3, "associate": 1}


def priority_score(severity: str, occurrences: int, tier: str) -> int:
    return SEVERITY_WEIGHT.get(severity, 4) * max(occurrences, 1) * TIER_WEIGHT.get(tier, 1)


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


@router.get("/{ticket_id}", response_model=TicketView)
async def get_ticket(ticket_id: str):
    """Look up a ticket by ID. TODO: read from DB."""
    raise HTTPException(501, "scaffold — ticket store not yet implemented")


@router.get("/claim/{claim_code}", response_model=TicketView)
async def claim_lookup(claim_code: str):
    """Anonymous reporter looks up their ticket by claim code. TODO: read from DB."""
    raise HTTPException(501, "scaffold — claim lookup not yet implemented")


@router.get("/admin/queue")
async def triage_queue(limit: int = 100):
    """Admin triage queue ordered by priority_score. TODO: query + auth (admin only)."""
    raise HTTPException(501, "scaffold — triage queue not yet implemented")
