"""Trusted-proxy client-IP resolution (app/auth.py:client_ip), used by the
/diagnostics/web anti-abuse rate limiter.

A production deploy sits behind Caddy, so the socket peer FastAPI sees is always the
proxy (127.0.0.1), never the real visitor. These tests lock in: (1) by default (no
trusted proxy configured) X-Forwarded-For is ignored entirely - a caller can't forge it
to dodge the rate limit; (2) once the socket peer is a configured trusted proxy,
X-Forwarded-For IS honoured, but ONLY the RIGHTMOST entry that isn't itself a trusted
proxy - never the leftmost. Caddy's reverse_proxy APPENDS the address it observed to
any existing X-Forwarded-For rather than replacing it, so a caller can freely prepend
whatever value it likes; only the trailing, proxy-added entry is trustworthy. (An
earlier version of this function - and netplex-rendezvous's client_ip(), which this was
ported from - took the leftmost entry instead; live-verified wrong against this
deploy's real Caddy on 2026-07-27 before being fixed here.)

httpx's ASGITransport reports the socket peer as ("127.0.0.1", 123) for every test
request (see httpx._transports.asgi.ASGITransport), which doubles as our "the proxy is
on localhost" fixture without needing a real TCP socket.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio


async def test_xff_ignored_when_no_trusted_proxy_configured(client, reset_rate_limit):
    """Default (TRUSTED_PROXIES unset): a forged X-Forwarded-For does NOT let two
    "different" visitors dodge the shared rate limit - the socket peer is authoritative."""
    from app.config import settings

    prev = settings.TRUSTED_PROXIES
    settings.TRUSTED_PROXIES = ""
    try:
        c, _ = client
        codes = []
        for i in range(12):
            r = await c.post(
                "/api/v1/diagnostics/web",
                json={"title": f"spam {i}"},
                headers={"X-Forwarded-For": f"10.0.0.{i}"},  # forged, must be ignored
            )
            codes.append(r.status_code)
        assert codes.count(202) == 10  # limit is 10/min, shared bucket despite forged XFF
        assert 429 in codes
    finally:
        settings.TRUSTED_PROXIES = prev


async def test_xff_honoured_when_peer_is_a_trusted_proxy(client, reset_rate_limit):
    """TRUSTED_PROXIES=127.0.0.1 (the test client's socket peer): a single, proxy-added
    X-Forwarded-For entry IS honoured, so two distinct forwarded IPs get two independent
    rate-limit budgets."""
    from app.config import settings

    prev = settings.TRUSTED_PROXIES
    settings.TRUSTED_PROXIES = "127.0.0.1"
    try:
        c, _ = client
        codes_a = []
        for i in range(12):
            r = await c.post(
                "/api/v1/diagnostics/web",
                json={"title": f"visitor-a {i}"},
                headers={"X-Forwarded-For": "203.0.113.10"},
            )
            codes_a.append(r.status_code)
        assert codes_a.count(202) == 10
        assert 429 in codes_a

        # a genuinely different forwarded visitor is NOT throttled by visitor-a's budget
        r = await c.post(
            "/api/v1/diagnostics/web",
            json={"title": "visitor-b first"},
            headers={"X-Forwarded-For": "203.0.113.20"},
        )
        assert r.status_code == 202, r.text
    finally:
        settings.TRUSTED_PROXIES = prev


async def test_xff_forged_leading_hop_cannot_dodge_the_rate_limit(client, reset_rate_limit):
    """The realistic shape: a caller sends its OWN forged X-Forwarded-For, then Caddy
    (a trusted proxy) appends the address it actually observed. Varying the forged
    leading entry must NOT create new rate-limit buckets - only the trailing,
    Caddy-added entry may."""
    from app.config import settings

    prev = settings.TRUSTED_PROXIES
    settings.TRUSTED_PROXIES = "127.0.0.1"
    try:
        c, _ = client
        codes = []
        for i in range(12):
            r = await c.post(
                "/api/v1/diagnostics/web",
                json={"title": f"spam {i}"},
                # left = attacker-forged and different every request; right = what
                # Caddy actually saw, constant. Only the right one should matter.
                headers={"X-Forwarded-For": f"9.9.9.{i}, 203.0.113.77"},
            )
            codes.append(r.status_code)
        assert codes.count(202) == 10, codes  # shared bucket despite the varying forged prefix
        assert 429 in codes
    finally:
        settings.TRUSTED_PROXIES = prev


async def test_xff_rightmost_untrusted_hop_used_when_chained(client, reset_rate_limit):
    """A multi-hop X-Forwarded-For chain: the RIGHT-most entry that isn't itself a
    trusted proxy wins - never the left-most (client-forgeable) one."""
    from app.auth import client_ip
    from app.config import settings
    from starlette.requests import Request

    prev = settings.TRUSTED_PROXIES
    settings.TRUSTED_PROXIES = "127.0.0.1"
    try:
        scope = {
            "type": "http",
            "client": ("127.0.0.1", 123),
            # "198.51.100.5" is whatever the caller claimed (forgeable); "203.0.113.77"
            # is what Caddy itself actually observed and appended - only that trailing
            # entry is trustworthy.
            "headers": [(b"x-forwarded-for", b"198.51.100.5, 203.0.113.77")],
        }
        req = Request(scope)
        assert client_ip(req) == "203.0.113.77"
    finally:
        settings.TRUSTED_PROXIES = prev


async def test_untrusted_peer_falls_back_to_socket_ip(client):
    """A peer NOT in TRUSTED_PROXIES: X-Forwarded-For is ignored, socket IP used."""
    from app.auth import client_ip
    from app.config import settings
    from starlette.requests import Request

    prev = settings.TRUSTED_PROXIES
    settings.TRUSTED_PROXIES = "10.10.10.10"  # some other proxy, not this peer
    try:
        scope = {
            "type": "http",
            "client": ("127.0.0.1", 123),
            "headers": [(b"x-forwarded-for", b"198.51.100.5")],
        }
        req = Request(scope)
        assert client_ip(req) == "127.0.0.1"
    finally:
        settings.TRUSTED_PROXIES = prev
