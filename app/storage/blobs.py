"""Object-store interface for screenshot / diagnostic blobs.

Rule: blobs are content-addressed (sha256) and live in object storage ONLY — NEVER git, NEVER the
relational DB. The ticket row stores only {sha256, url, mime, bytes, redacted}. Screenshots arrive
already redacted from the box; size/type are re-validated here as defence in depth.
"""
from __future__ import annotations

import hashlib

ALLOWED_MIME = {"image/png", "image/jpeg", "image/webp"}


def content_address(data: bytes) -> str:
    """Return the sha256 hex key a blob is stored under (enables dedupe)."""
    return hashlib.sha256(data).hexdigest()


def put_blob(data: bytes, mime: str, max_bytes: int) -> dict:
    """Store a blob and return its descriptor. TODO: wire to S3-compatible store."""
    if mime not in ALLOWED_MIME:
        raise ValueError(f"unsupported mime: {mime}")
    if len(data) > max_bytes:
        raise ValueError("blob too large")
    key = content_address(data)
    # TODO(scaffold): upload to settings.OBJECT_STORE_URL under `key`; return real URL.
    return {"sha256": key, "url": f"objstore://{key}", "mime": mime, "bytes": len(data), "redacted": True}
