"""netplex-support API entrypoint.

Scaffold: mounts the receiving-end subsystems. Release/signing routes are GATED (return 501)
until docs/SECURITY-BLOCKERS.md is cleared.
"""
from __future__ import annotations

from fastapi import FastAPI

from app import __version__
from app.routers import diagnostics, tickets, licensing, releases

app = FastAPI(title="netplex-support", version=__version__)

app.include_router(diagnostics.router)
app.include_router(tickets.router)
app.include_router(licensing.router)
app.include_router(releases.router)


@app.get("/health")
async def health():
    return {"service": "netplex-support", "version": __version__, "status": "ok"}
