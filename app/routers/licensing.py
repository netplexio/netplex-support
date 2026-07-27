"""Licensing authority — the source of tier truth.

VERIFY is live (stateless, PUBLIC key). A license "token" is a JSON string holding a signed dict:
{tier, expires_at(unix), customer_ref, ..., signature:{alg,key_id,sig}}. We verify the ed25519
signature against a TrustStore built from settings.LICENSE_PUBLIC_KEY / LICENSE_TRUST_STORE_JSON,
then check expiry.

REGISTER is live too, admin-only: it accepts a token ALREADY signed OFFLINE (by whoever holds the
private license key, via tools/mint_license.py on an air-gapped machine — see
docs/KEY-GENERATION-RUNBOOK.md) and, if it verifies, stores it. This is the only way a license
token ever reaches this server's store.

ISSUE stays 🔴 GATED — it would mean minting tokens with the PRIVATE license key, which this
server must never hold (docs/SECURITY-BLOCKERS.md #3, key custody). That is a permanent
architectural boundary, not a temporary block — REGISTER does not relax it.
"""
from __future__ import annotations

import json
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import client_ip, require_admin
from app.config import settings
from app.crypto.signing import TrustStore, trust_store_from_settings, verify_manifest
from app.db import get_session
from app.models import latest_license_token_for, store_license_token
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
    """Build a TrustStore from the configured PUBLIC license key(s). Prefers the full
    LICENSE_TRUST_STORE_JSON (rotation/revocation) over the single LICENSE_PUBLIC_KEY when
    set; both unset → empty store (verification fails closed)."""
    return trust_store_from_settings(settings.LICENSE_TRUST_STORE_JSON, settings.LICENSE_PUBLIC_KEY)


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
    """🔴 PERMANENTLY GATED: mint a signed license token. Requires the OFFLINE private
    license key, which this server must never hold (docs/SECURITY-BLOCKERS.md #3). Mint
    a token OFFLINE with tools/mint_license.py, then POST it to /api/v1/license/register."""
    raise HTTPException(
        501,
        "GATED — server-side license issuance is permanently disabled by design (key-custody "
        "rule). Mint a token offline via tools/mint_license.py, then POST it to "
        "/api/v1/license/register",
    )


class RegisterRequest(BaseModel):
    token: str = Field(max_length=4096)  # an ALREADY-SIGNED token, minted offline


class RegisterResult(BaseModel):
    accepted: bool
    customer_ref: str = ""
    tier: str = ""
    key_id: str = ""
    expires_at: int | None = None


@router.post(
    "/register", response_model=RegisterResult, dependencies=[Depends(require_admin)]
)
async def register_license(
    req: RegisterRequest, session: AsyncSession = Depends(get_session)
):
    """Admin-only: register an ALREADY-SIGNED license token into the store.

    This endpoint NEVER signs anything — it only verifies the presented signature against
    the PUBLIC license trust store (the same primitive /verify uses) and, if and only if
    that verification passes, persists the token. The token itself must have been produced
    OFFLINE, on the machine that holds the private license key, using tools/mint_license.py
    (docs/KEY-GENERATION-RUNBOOK.md). Mirrors app/routers/releases.py's /upload — same
    custody boundary, same shape."""
    trust = _trust_store()
    try:
        claims = json.loads(req.token)
    except (ValueError, TypeError):
        raise HTTPException(400, "malformed token: not valid JSON")
    if not isinstance(claims, dict):
        raise HTTPException(400, "malformed token: not a JSON object")

    ok, key_id_or_reason = verify_manifest(claims, trust)
    if not ok:
        raise HTTPException(400, f"signature rejected: {key_id_or_reason}")

    result = _verify_token(req.token, trust)
    if not result.valid:
        raise HTTPException(400, f"token rejected: {result.reason}")

    customer_ref = str(claims.get("customer_ref", ""))
    await store_license_token(
        session,
        customer_ref=customer_ref,
        key_id=key_id_or_reason,
        tier=result.tier,
        expires_at=result.expires_at,
        token_json=req.token,
    )
    return RegisterResult(
        accepted=True,
        customer_ref=customer_ref,
        tier=result.tier,
        key_id=key_id_or_reason,
        expires_at=result.expires_at,
    )


class RegisteredView(BaseModel):
    customer_ref: str
    tier: str
    key_id: str
    expires_at: Optional[int] = None
    token: str


@router.get(
    "/registered/{customer_ref}",
    response_model=RegisteredView,
    dependencies=[Depends(require_admin)],
)
async def get_registered_license(
    customer_ref: str, session: AsyncSession = Depends(get_session)
):
    """Admin-only: look up the most recently registered license token for a customer_ref
    (support-ops lookup — "did we register this customer's license, and with what terms").
    """
    row = await latest_license_token_for(session, customer_ref)
    if row is None:
        raise HTTPException(404, "no registered license for that customer_ref")
    return RegisteredView(
        customer_ref=row.customer_ref,
        tier=row.tier,
        key_id=row.key_id,
        expires_at=row.expires_at,
        token=row.token_json,
    )
