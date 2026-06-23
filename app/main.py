"""netplex-support API entrypoint.

Mounts the receiving-end subsystems. Diagnostics + tickets + license-verify are live; the
release/signing routes stay GATED (501) until docs/SECURITY-BLOCKERS.md distribution items land.
init_db() runs on startup via the lifespan.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app import __version__
from app.db import init_db
from app.routers import diagnostics, tickets, licensing, releases


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(title="netplex-support", version=__version__, lifespan=lifespan)

app.include_router(diagnostics.router)
app.include_router(tickets.router)
app.include_router(licensing.router)
app.include_router(releases.router)


@app.get("/health")
async def health():
    return {"service": "netplex-support", "version": __version__, "status": "ok"}
