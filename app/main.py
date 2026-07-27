"""netplex-support API entrypoint.

Mounts the receiving-end subsystems. Diagnostics + tickets + license-verify/register +
release manifest-upload/serve are all live. Server-side SIGNING (releases.py's /publish,
licensing.py's /issue) stays PERMANENTLY 501 — this server must never hold a private
signing/license key (docs/SECURITY-BLOCKERS.md #3, key custody) — that boundary does not
move regardless of what else is built around it. init_db() runs on startup via the lifespan.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException

from app import __version__
from app.config import settings
from app.db import init_db
from app.routers import diagnostics, tickets, licensing, releases


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(title="netplex-support", version=__version__, lifespan=lifespan)


class _BodySizeLimitASGI:
    """Enforce settings.MAX_REQUEST_BODY_BYTES on the ACTUAL byte stream of every
    request, application-wide.

    SECURITY (adversarial sweep 2026-07-27, P1): this service had NO request-size
    limit anywhere - not in the app, not in the Dockerfile, not in docker-compose (a
    fronting Caddy may add one in prod, but its config isn't in this repo, so nothing
    HERE enforced a cap). FastAPI reads and fully buffers a declared-Pydantic-body
    route's payload before ANY dependency (auth, rate limit) runs, so an
    UNAUTHENTICATED caller could POST an arbitrarily large body to
    /api/v1/diagnostics/forward (bypassing its Bearer-token requirement for this
    attack class entirely) or /api/v1/license/verify (no auth dependency, no rate
    limit at all, and VerifyRequest.token had no max_length, unlike every other field
    in this codebase) - live-verified: both accepted a several-MB body and fully
    processed it with zero credentials. A straightforward unauthenticated memory/CPU-
    exhaustion DoS of the whole service (single host-networked container).

    A raw ASGI middleware (not BaseHTTPMiddleware, which has its own known
    body-buffering/backpressure pitfalls for exactly this kind of guard) wraps
    receive() and counts bytes AS they stream in, aborting (413) the instant the
    running total crosses the cap - the oversized remainder is never read into
    memory, chunked-Transfer-Encoding or not. A declared oversized Content-Length is
    still fast-rejected up front (no bytes read at all). Raises a genuine
    fastapi.HTTPException(413) from inside receive(): FastAPI's own routing.py
    explicitly re-raises an HTTPException raised during body-parsing unchanged
    (documented in its own source as a supported pattern for exactly this), rather
    than swallowing it into a generic 400. Same proven fix as netplex-rendezvous's
    2026-07-27 P1 (identical vulnerability class, same root cause: a client-declared
    Content-Length is the only thing FastAPI/Starlette will ever check on their own).
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        cl = headers.get(b"content-length")
        if cl is not None:
            try:
                if int(cl) > settings.MAX_REQUEST_BODY_BYTES:
                    await _send_json(send, 413, {"detail": "request body too large"})
                    return
            except ValueError:
                await _send_json(send, 400, {"detail": "invalid Content-Length"})
                return

        total = 0

        async def limited_receive():
            nonlocal total
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body") or b"")
                if total > settings.MAX_REQUEST_BODY_BYTES:
                    raise HTTPException(status_code=413, detail="request body too large")
            return message

        await self.app(scope, limited_receive, send)


async def _send_json(send, status: int, payload: dict) -> None:
    import json as _json
    body = _json.dumps(payload).encode()
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
    })
    await send({"type": "http.response.body", "body": body})


app.add_middleware(_BodySizeLimitASGI)

app.include_router(diagnostics.router)
app.include_router(tickets.router)
app.include_router(licensing.router)
app.include_router(releases.router)


@app.get("/health")
async def health():
    return {"service": "netplex-support", "version": __version__, "status": "ok"}
