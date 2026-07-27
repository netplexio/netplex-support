"""Release / update authority — the manifest distribution hop.

Server-side SIGNING is PERMANENTLY impossible here — this server must never hold the private
signing key (docs/SECURITY-BLOCKERS.md #3, key custody). /publish always 501s; that is an
architectural constant, not a temporary gate.

What IS live: verifying, storing, and serving an ALREADY-SIGNED manifest. Whoever holds the
offline signing key signs a manifest OFFLINE with tools/sign_release.py (never on this server —
see docs/KEY-GENERATION-RUNBOOK.md), then uploads the signed result via POST /upload. This route
verifies the signature against the PUBLIC signing trust store (settings.SIGNING_PUBLIC_KEY /
SIGNING_TRUST_STORE_JSON) and, only if it verifies, stores it. GET /manifest/{channel} serves the
latest stored manifest for that channel. A box still independently re-verifies against its own
baked-in trust store before applying anything — this service is the distribution hop, not the
trust boundary (the box's own verification is).
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_admin
from app.config import settings
from app.crypto.signing import TrustStore, trust_store_from_settings, verify_manifest
from app.db import get_session
from app.models import latest_release_manifest, store_release_manifest

router = APIRouter(prefix="/api/v1/releases", tags=["releases"])

# Matches docs/SECURITY-BLOCKERS.md / KEY-GENERATION-RUNBOOK.md's channel vocabulary.
CHANNELS = {"canary", "beta", "stable", "lts"}

_PUBLISH_GATED = (
    "publish (server-side signing) is permanently disabled by design — this server never "
    "holds the private signing key (docs/SECURITY-BLOCKERS.md #3). Sign a manifest OFFLINE "
    "via tools/sign_release.py on the air-gapped signing machine, then POST the signed "
    "result to /api/v1/releases/upload"
)


def _trust_store() -> TrustStore:
    """Build a TrustStore from the configured PUBLIC signing key(s). Prefers the full
    SIGNING_TRUST_STORE_JSON (rotation/revocation) over the single SIGNING_PUBLIC_KEY when
    set; both unset → empty store, so /upload fails closed (every manifest is "unknown-key")
    until Khaled hands over a real public key (README.md / docker-compose.yml already
    document this as the expected pre-key state, not a deploy defect)."""
    return trust_store_from_settings(settings.SIGNING_TRUST_STORE_JSON, settings.SIGNING_PUBLIC_KEY)


class UploadRequest(BaseModel):
    manifest: dict  # the full signed manifest, including its `signature` block


class UploadResult(BaseModel):
    accepted: bool
    channel: str = ""
    version: str = ""
    key_id: str = ""


@router.get("/manifest/{channel}")
async def get_manifest(channel: str, session: AsyncSession = Depends(get_session)):
    """Serve the latest UPLOADED (and, at upload time, verified) signed manifest for a
    channel. Public — a box needs to reach this before it has decided to trust anything;
    the box's own verification against its baked-in trust store is what actually gates
    whether it applies the manifest."""
    if channel not in CHANNELS:
        raise HTTPException(404, f"unknown channel: {channel!r} (expected one of {sorted(CHANNELS)})")
    row = await latest_release_manifest(session, channel)
    if row is None:
        raise HTTPException(404, f"no manifest has been published for channel {channel!r} yet")
    return json.loads(row.manifest_json)


@router.post("/upload", response_model=UploadResult, dependencies=[Depends(require_admin)])
async def upload_manifest(req: UploadRequest, session: AsyncSession = Depends(get_session)):
    """Admin-only: accept an ALREADY-SIGNED manifest and, if its signature verifies against
    the PUBLIC signing trust store, store it as the latest manifest for its channel.

    This is the ONLY path a manifest can ever reach this server through — there is no
    server-side signing path (see POST /publish, always 501). Rejects (400) on: missing/
    invalid `channel`, an unparseable manifest, a forged/tampered signature, or a signature
    from an unknown or revoked key_id — the same verify_manifest() primitive
    app/crypto/signing.py already ships and tests/test_signing.py already covers."""
    manifest = req.manifest
    if not isinstance(manifest, dict):
        raise HTTPException(400, "manifest must be a JSON object")
    channel = manifest.get("channel")
    if channel not in CHANNELS:
        raise HTTPException(400, f"manifest.channel must be one of {sorted(CHANNELS)}, got {channel!r}")

    ok, reason = verify_manifest(manifest, _trust_store())
    if not ok:
        raise HTTPException(400, f"signature rejected: {reason}")
    key_id = reason  # verify_manifest returns the verifying key_id in `reason` on success

    version = str(manifest.get("version", ""))
    await store_release_manifest(
        session,
        channel=channel,
        version=version,
        key_id=key_id,
        manifest_json=json.dumps(manifest, sort_keys=True, separators=(",", ":")),
    )
    return UploadResult(accepted=True, channel=channel, version=version, key_id=key_id)


@router.post("/publish")
async def publish_release():
    """Server-side build+sign+publish. PERMANENTLY disabled — see module docstring and
    docs/SECURITY-BLOCKERS.md #3. Use tools/sign_release.py offline, then POST /upload."""
    raise HTTPException(501, _PUBLISH_GATED)
