"""Bearer-token auth for netplex-support's privileged surfaces.

Fail-CLOSED: when the relevant token set is unconfigured the endpoint is DISABLED (503)
rather than served open. Constant-time compare against any of the (comma-separated)
configured tokens, so a rotation window can keep old+new valid. This mirrors the intake
auth on /diagnostics/forward (app/routers/diagnostics.py)."""
from __future__ import annotations

import hmac

from fastapi import HTTPException, Request

from app.config import settings


def _require_bearer(request: Request, tokens_csv: str, what: str) -> None:
    configured = [t.strip() for t in (tokens_csv or "").split(",") if t.strip()]
    if not configured:
        raise HTTPException(503, f"{what} is not configured on this server")
    auth = request.headers.get("authorization", "")
    presented = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    if not presented or not any(hmac.compare_digest(presented, t) for t in configured):
        raise HTTPException(401, f"invalid or missing {what} token")


def require_admin(request: Request) -> None:
    """Gate the operator triage surface on ADMIN_API_TOKENS (fail-closed)."""
    _require_bearer(request, settings.ADMIN_API_TOKENS, "admin API")
