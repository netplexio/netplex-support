"""Licensing authority — the source of tier truth.

VERIFY is live (stateless, PUBLIC key). A license "token" is a JSON string holding a signed dict:
{tier, expires_at(unix), customer_ref, ..., signature:{alg,key_id,sig}}. We verify the ed25519
signature against a TrustStore built from settings.LICENSE_PUBLIC_KEY, then check expiry.

ISSUE is 🔴 GATED — it mints tokens with the PRIVATE license key (offline custody).
"""
from __future__ import annotations

import json
import time

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app.auth import client_ip
from app.config import settings
from app.crypto.signing import TrustStore, verify_manifest
from app.ratelimit import rate_ok

router = APIRouter(prefix="/api/v1/license", tags=["licensing"])

VALID_TIERS = {"associate", "professional", "architect", "team", "enterprise", "class", "master"}


class VerifyRequest(BaseModel):
    # signed license token (JSON) presented by a box. max_length matches
    # ForwardedReport.license_token's cap (app/routers/diagnostics.py) for the same
    # kind of signed-JSON-token payload - this field had NO cap at all before
    # (adversarial sweep 2026-07-27, P1), unlike every other field in this codebase,
    # letting an unauthenticated, unbounded-size, unrate-limited caller push arbitrary
    # amounts of data through json.loads() on every call.
    token: str = Field(max_length=4096)


class VerifyResult(BaseModel):
    valid: bool
    tier: str = ""
    expires_at: int | None = None
    entitlements: dict = {}
    reason: str = ""


def _trust_store() -> TrustStore:
    """Build a TrustStore from the configured base64 public key. Empty config → empty store."""
    if not settings.LICENSE_PUBLIC_KEY:
        return TrustStore.from_keys([])
    return TrustStore.from_keys([{"public_key": settings.LICENSE_PUBLIC_KEY, "status": "active"}])


def _verify_token(token: str, trust: TrustStore) -> VerifyResult:
    """Parse + verify a signed license token. Pure (no settings) so tests can inject a trust store."""
    try:
        claims = json.loads(token)
    except (ValueError, TypeError):
        return VerifyResult(valid=False, reason="malformed-token")
    if not isinstance(claims, dict):
        return VerifyResult(valid=False, reason="malformed-token")

    ok, why = verify_manifest(claims, trust)
    if not ok:
        return VerifyResult(valid=False, reason=why)

    tier = str(claims.get("tier", ""))
    expires_at = claims.get("expires_at")
    if expires_at is not None and int(expires_at) < int(time.time()):
        return VerifyResult(valid=False, tier=tier, expires_at=int(expires_at), reason="expired")

    return VerifyResult(
        valid=True,
        tier=tier,
        expires_at=int(expires_at) if expires_at is not None else None,
        entitlements={},
    )


@router.post("/verify", response_model=VerifyResult)
async def verify_license(req: VerifyRequest, request: Request):
    """Verify a presented license token with the PUBLIC key → {valid, tier, expires_at, entitlements}.

    IP rate-limited (adversarial sweep 2026-07-27, P1): this endpoint has no auth by
    design (it verifies with the PUBLIC key only, matching "VERIFY is live... stateless,
    PUBLIC key" above) and previously had no rate limit at all - an anonymous caller
    could hammer it as fast as the network allowed. Same anti-abuse primitive as the
    diagnostics intake (app/ratelimit.py), trusted-proxy-aware client IP
    (app/auth.py:client_ip)."""
    ip = client_ip(request)
    limit = max(int(getattr(settings, "LICENSE_VERIFY_RATE_PER_MIN", 30)), 1)
    if not rate_ok(f"license-verify:{ip}", limit):
        raise HTTPException(429, "rate limit exceeded - slow down")
    return _verify_token(req.token, _trust_store())


class IssueRequest(BaseModel):
    tier: str
    customer_ref: str
    days_valid: int = 365


@router.post("/issue")
async def issue_license(req: IssueRequest):
    """🔴 GATED: mint a signed license token. Requires the OFFLINE private license key.
    Blocked until docs/SECURITY-BLOCKERS.md key-custody item is cleared."""
    raise HTTPException(501, "GATED — license issuance blocked on key-custody security blocker")
