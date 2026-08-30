"""Cross-repo contract test: the PRODUCT's forward payload is accepted by THIS receiver.

Imports the product's `routers.ticket_model.forward_payload` (api-gateway) and POSTs its output to
netplex-support's `/api/v1/diagnostics/forward` (via the shared isolated `client` fixture),
asserting a ticket is created and identity is not leaked. Proves the product→central forwarding
contract end-to-end. Skips cleanly if the product repo isn't checked out alongside.
"""
import sys

import pytest
from tests.conftest import FORWARD_HEADERS

# Locate the product's payload builder; skip if the product repo isn't present.
#
# Two paths, not one (fixed 2026-08-30, Wave 18.6 T2): `routers.ticket_model` does
# `from shared...`, and `shared` lives one level up at backend/shared. With only the
# api-gateway path on sys.path the import raised ModuleNotFoundError: No module named
# 'shared', importorskip swallowed it, and this whole cross-repo contract test had been
# silently skipping — reporting "1 skipped" rather than "the product→support forwarding
# contract is unverified".
_BACKEND = "/root/netplex/backend"
for _p in (f"{_BACKEND}/api-gateway", _BACKEND):
    if _p not in sys.path:
        sys.path.insert(0, _p)
forward_payload = pytest.importorskip("routers.ticket_model").forward_payload


@pytest.mark.asyncio
async def test_product_payload_is_accepted_and_creates_ticket(client):
    c, _session = client  # conftest yields (AsyncClient, sessionmaker)
    # a representative product ticket (with fields that MUST be redacted out of the forward)
    # "id" is the box's own local ticket id (T13a: origin_local_id) - forward_payload's
    # own docstring says this is exactly what it carries upstream.
    product_ticket = {
        "id": "NPX-A1B2C3D4E5F6",
        "kind": "crash", "fingerprint": "fp-contract", "title": "Studio crash on labs",
        "body": "TypeError: data?.some is not a function", "severity": "s1_crash",
        "platform_version": "1.4.2", "reporter_tier": "architect",
        "url": "http://secret/lab/123", "contact": "user@example.com", "user_id": "u-secret",
    }
    payload = forward_payload(product_ticket)

    res = await c.post("/api/v1/diagnostics/forward", json=payload, headers=FORWARD_HEADERS)
    assert res.status_code == 202, res.text
    tid = res.json()["ticket_id"]
    assert tid.startswith("SUP-"), (  # T13b: this repo's own id format, never the box-local one
        f"expected netplex-support's own 'SUP-' id format, got {tid!r}"
    )

    got = await c.get(f"/api/v1/tickets/{tid}")
    assert got.status_code == 200
    body = got.json()
    assert body["title"] == "Studio crash on labs" and body["severity"] == "s1_crash"
    assert "user@example.com" not in str(body) and "u-secret" not in str(body)
    # T13a: the box's own local id rode along and is resolvable back to this row.
    assert body["origin_local_id"] == "NPX-A1B2C3D4E5F6"

    # same fingerprint again → dedupe (occurrences grows, same id)
    res2 = await c.post("/api/v1/diagnostics/forward", json=payload, headers=FORWARD_HEADERS)
    assert res2.json()["ticket_id"] == tid
    assert res2.json()["occurrences"] == 2
