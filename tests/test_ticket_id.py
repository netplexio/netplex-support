"""W15.4 / F-S3 — ticket IDs were 24-bit (`token_hex(3)`): a collision risk (birthday
bound ~4k tickets) and small enough to enumerate against the unauthenticated
GET /tickets/{id}. They are now 48-bit and still fit the String(16) id column.

T13b (2026-08-30 war-room) — the prefix changed from "NPX-" to "SUP-": this repo's own
ids used to mint byte-for-byte the same "NPX-" + 12-hex format as the box's own local
receipt (netplex/backend/api-gateway/routers/ticket_model.py `_new_id()`), from a
completely different database. "SUP-" makes a netplex-support id visually
distinguishable from a box-local id at a glance — this is a regression test for that:
it would fail if new_ticket_id() ever reverted to "NPX-".
"""
from app.models import new_ticket_id


def test_ticket_id_is_48_bit_and_fits_column():
    seen = set()
    for _ in range(2000):
        tid = new_ticket_id()
        assert tid.startswith("SUP-")
        hexpart = tid[4:]
        assert len(hexpart) == 12                 # 48 bits (was 6 hex = 24 bits)
        int(hexpart, 16)                          # valid hex
        assert hexpart == hexpart.upper()         # uppercase
        assert len(tid) <= 16                     # fits Ticket.id String(16)
        seen.add(tid)
    assert len(seen) == 2000                       # no collisions in a large batch


def test_ticket_id_does_not_collide_in_format_with_box_local_id():
    """T13b regression test: a netplex-support id must never be visually confusable
    with the box-local "NPX-..." id minted by netplex/backend/api-gateway/routers/
    ticket_model.py `_new_id()` — same width, same alphabet, only the prefix differs.
    This fails without the T13b fix (both minted "NPX-" before)."""
    tid = new_ticket_id()
    assert not tid.startswith("NPX-"), (
        "REGRESSION: netplex-support minted an id in the box-local 'NPX-' format — "
        "this is the exact ambiguity T13b closed (two different databases, "
        "same-looking id, nothing to tell them apart)"
    )
    assert tid.startswith("SUP-")
