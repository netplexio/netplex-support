"""Licensing authority — the source of tier truth.

VERIFY is open to build (stateless, public key). ISSUE is 🔴 GATED — it mints signed tokens with
the PRIVATE license key, gated on docs/SECURITY-BLOCKERS.md (key custody).
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/license", tags=["licensing"])

VALID_TIERS = {"associate", "professional", "architect", "team", "enterprise", "class", "master"}


class VerifyRequest(BaseModel):
    token: str  # signed license token presented by a box


class VerifyResult(BaseModel):
    valid: bool
    tier: str
    expires_at: int | None = None
    entitlements: dict = {}


@router.post("/verify", response_model=VerifyResult)
async def verify_license(req: VerifyRequest):
    """Verify a presented license token with the PUBLIC key → tier + entitlements.
    TODO: ed25519 verify against settings.LICENSE_PUBLIC_KEY; parse claims; offline-grace aware."""
    raise HTTPException(501, "scaffold — verify not yet implemented (public-key path, buildable)")


class IssueRequest(BaseModel):
    tier: str
    customer_ref: str
    days_valid: int = 365


@router.post("/issue")
async def issue_license(req: IssueRequest):
    """🔴 GATED: mint a signed license token. Requires the PRIVATE license key.
    Blocked until docs/SECURITY-BLOCKERS.md #3 (key custody) is cleared."""
    raise HTTPException(501, "GATED — license issuance blocked on key-custody security blocker")
