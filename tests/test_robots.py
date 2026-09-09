"""This host is a pure API - GET /robots.txt must disallow the whole crawl so
search engines stop probing API paths and landing 4xx/405s (Search Console
flagged /api/v1/diagnostics/web as "Blocked due to other 4xx issue" for
exactly this reason, since GETting a POST-only route 405s)."""
from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_robots_disallows_everything(client):
    c, _ = client
    resp = await c.get("/robots.txt")
    assert resp.status_code == 200
    assert "Disallow: /" in resp.text


@pytest.mark.asyncio
async def test_diagnostics_web_get_is_405_not_indexable_content(client):
    # The route itself is legitimately POST-only (405 on GET is correct API
    # behaviour) - robots.txt is what stops a crawler from bothering it, not
    # a change to the route's method handling.
    c, _ = client
    resp = await c.get("/api/v1/diagnostics/web")
    assert resp.status_code == 405
