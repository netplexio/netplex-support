"""Diagnostics destination — receives OPT-IN, already-redacted reports forwarded from a box.

SCAFFOLD: shapes the contract; persistence + dedupe + blob storage are TODO. Reports are expected
pre-redacted on the box (local-only privacy); this endpoint never accepts raw user data it must
scrub itself, but it re-validates size/type as defence in depth.
"""
from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/diagnostics", tags=["diagnostics"])


class ForwardedReport(BaseModel):
    kind: Literal["crash", "bug", "feature", "license"] = "crash"
    fingerprint: Optional[str] = Field(default=None, max_length=128)
    title: str = Field(max_length=200)
    body: str = Field(max_length=10000)
    severity: str = Field(default="s2_broken", max_length=16)
    platform_version: str = Field(default="", max_length=64)
    # tier/identity — present only for identified (paid) tiers
    reporter_tier: str = Field(default="associate", max_length=32)
    install_id: Optional[str] = Field(default=None, max_length=128)
    license_token: Optional[str] = Field(default=None, max_length=4096)  # verified for tier
    contact: Optional[str] = Field(default=None, max_length=256)         # paid only
    # attachments are uploaded separately to the blob store; refs only here
    attachment_refs: list[str] = Field(default_factory=list, max_length=10)


@router.post("/forward", status_code=202)
async def receive_forwarded(report: ForwardedReport):
    """Accept a forwarded report → create/dedupe a ticket. TODO: persist, verify license_token
    for tier, fingerprint-dedupe, compute priority_score + sla_due, mirror to GitHub on triage."""
    # TODO(scaffold): wire to app.routers.tickets store; this is the contract only.
    return {
        "accepted": True,
        "ticket_id": "NPX-PENDING",
        "note": "scaffold — persistence not yet implemented",
        "kind": report.kind,
    }
