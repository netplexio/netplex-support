"""Release / update authority — 🔴 GATED in full.

Builds release manifests, ed25519-SIGNS them, pins image digests, serves the registry, emits
offline bundles. Holds the PRIVATE signing key. Every route here returns 501 until
docs/SECURITY-BLOCKERS.md #1–#5 are cleared (trust-bootstrap, rotation, custody, self-update,
contract-versioning). This stub exists only to reserve the surface and make the gate explicit.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api/v1/releases", tags=["releases"])

_GATED = "GATED — release/signing/distribution blocked on docs/SECURITY-BLOCKERS.md #1-#5"


@router.get("/manifest/{channel}")
async def get_manifest(channel: str):
    """Return the signed release manifest for a channel (canary/beta/stable/lts)."""
    raise HTTPException(501, _GATED)


@router.post("/publish")
async def publish_release():
    """Build + sign + publish a release. Requires the private signing key."""
    raise HTTPException(501, _GATED)
