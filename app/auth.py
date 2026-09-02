"""Bearer-token auth + trusted-proxy IP resolution for netplex-support's privileged
and rate-limited surfaces.

Fail-CLOSED: when the relevant token set is unconfigured the endpoint is DISABLED (503)
rather than served open. Constant-time compare against any of the (comma-separated)
configured tokens, so a rotation window can keep old+new valid. This mirrors the intake
auth on /diagnostics/forward (app/routers/diagnostics.py)."""
from __future__ import annotations

import hmac
import ipaddress

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


# ── trusted-proxy client-IP resolution (mirrors netplex-rendezvous's app/security.py
# client_ip() fix, F-R5) ──
#
# A production deploy always sits behind our Caddy TLS terminator, so the socket peer
# FastAPI sees on every request is Caddy (typically 127.0.0.1), never the real visitor.
# Any IP-keyed decision (the /diagnostics/web anti-abuse rate limit) that trusted
# X-Forwarded-For unconditionally would let a caller forge it to dodge the limit; one
# that ignored it entirely would bucket every visitor behind the proxy into a single IP
# and make the limiter useless. So: honour X-Forwarded-For ONLY when the immediate
# socket peer is a configured trusted proxy; otherwise the socket peer is authoritative.
def _trusted_proxies() -> list:
    """Peers whose X-Forwarded-For we honour: IPs, CIDRs, or the literal "*" (trust all
    forwarders - never use on a public listener). Default empty = trust NONE."""
    out: list = []
    for tok in settings.TRUSTED_PROXIES.split(","):
        tok = tok.strip()
        if not tok:
            continue
        if tok == "*":
            out.append("*")
            continue
        try:
            out.append(ipaddress.ip_network(tok, strict=False))
        except ValueError:
            continue  # ignore garbage rather than crash the request path
    return out


def _peer_is_trusted(peer: str) -> bool:
    nets = _trusted_proxies()
    if not nets:
        return False
    if any(n == "*" for n in nets):
        return True
    try:
        ip = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return any(
        isinstance(n, (ipaddress.IPv4Network, ipaddress.IPv6Network)) and ip in n
        for n in nets
    )


def client_ip(request: Request) -> str:
    """Resolve the real client IP for IP-keyed decisions (rate limiting). Honours
    X-Forwarded-For ONLY when the socket peer is a configured trusted proxy
    (settings.TRUSTED_PROXIES); otherwise the socket peer is authoritative.

    Walks X-Forwarded-For from the RIGHT and returns the first entry that is NOT
    itself a trusted proxy. Each hop APPENDS the address it observed (Caddy's default
    reverse_proxy behaviour, matching the general X-Forwarded-For convention), so the
    rightmost entries are the ones OUR infrastructure actually added - the leftmost
    entry is whatever the original caller sent us unauthenticated and can freely forge
    before ever reaching Caddy. Taking the first (leftmost) entry - as an earlier
    version of this function, and netplex-rendezvous's client_ip(), both did - trusts
    exactly that forgeable value; live-verified against this deploy's real Caddy (2026-
    07-27): a request carrying a forged X-Forwarded-For arrives with Caddy's own
    observed peer appended AFTER it, so only the rightmost-non-trusted-hop walk is
    actually safe. (uvicorn's own ProxyHeadersMiddleware - default-enabled, trusting
    127.0.0.1 - already applies this same correct algorithm ahead of this function when
    Caddy is the immediate TCP peer; this makes the same guarantee hold even if that
    upstream default is ever disabled or the deploy topology changes.)"""
    peer = request.client.host if request.client else ""
    if not _peer_is_trusted(peer):
        return peer or "unknown"
    xff = request.headers.get("x-forwarded-for", "")
    hops = [h.strip() for h in xff.split(",") if h.strip()]
    for hop in reversed(hops):
        if not _peer_is_trusted(hop):
            return hop
    # every hop (including the caller) is itself a trusted proxy - nothing untrusted
    # to report; fall back to the socket peer.
    return peer or "unknown"
