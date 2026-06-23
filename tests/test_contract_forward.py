"""Cross-repo contract test: the PRODUCT's forward payload is accepted by THIS receiver.

Imports the product's `routers.ticket_model.forward_payload` (api-gateway) and POSTs its output to
netplex-support's `/api/v1/diagnostics/forward` (via the shared isolated `client` fixture),
asserting a ticket is created and identity is not leaked. Proves the product→central forwarding
contract end-to-end. Skips cleanly if the product repo isn't checked out alongside.
"""
import sys

import pytest

# Locate the product's payload builder; skip if the product repo isn't present.
_GW = "/root/netplex/backend/api-gateway"
if _GW not in sys.path:
    sys.path.insert(0, _GW)
forward_payload = pytest.importorskip("routers.ticket_model").forward_payload


@pytest.mark.asyncio
async def test_product_payload_is_accepted_and_creates_ticket(client):
    c, _session = client  # conftest yields (AsyncClient, sessionmaker)
    # a representative product ticket (with fields that MUST be redacted out of the forward)
    product_ticket = {
        "kind": "crash", "fingerprint": "fp-contract", "title": "Studio crash on labs",
        "body": "TypeError: data?.some is not a function", "severity": "s1_crash",
        "platform_version": "1.4.2", "reporter_tier": "architect",
        "url": "http://secret/lab/123", "contact": "user@example.com", "user_id": "u-secret",
    }
    payload = forward_payload(product_ticket)

    res = await c.post("/api/v1/diagnostics/forward", json=payload)
    assert res.status_code == 202, res.text
    tid = res.json()["ticket_id"]
    assert tid.startswith("NPX-")

    got = await c.get(f"/api/v1/tickets/{tid}")
    assert got.status_code == 200
    body = got.json()
    assert body["title"] == "Studio crash on labs" and body["severity"] == "s1_crash"
    assert "user@example.com" not in str(body) and "u-secret" not in str(body)

    # same fingerprint again → dedupe (occurrences grows, same id)
    res2 = await c.post("/api/v1/diagnostics/forward", json=payload)
    assert res2.json()["ticket_id"] == tid
    assert res2.json()["occurrences"] == 2
