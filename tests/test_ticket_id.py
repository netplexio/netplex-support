"""W15.4 / F-S3 — ticket IDs were 24-bit (`token_hex(3)`): a collision risk (birthday
bound ~4k tickets) and small enough to enumerate against the unauthenticated
GET /tickets/{id}. They are now 48-bit and still fit the String(16) id column.
"""
from app.models import new_ticket_id


def test_ticket_id_is_48_bit_and_fits_column():
    seen = set()
    for _ in range(2000):
        tid = new_ticket_id()
        assert tid.startswith("NPX-")
        hexpart = tid[4:]
        assert len(hexpart) == 12                 # 48 bits (was 6 hex = 24 bits)
        int(hexpart, 16)                          # valid hex
        assert hexpart == hexpart.upper()         # uppercase
        assert len(tid) <= 16                     # fits Ticket.id String(16)
        seen.add(tid)
    assert len(seen) == 2000                       # no collisions in a large batch
