# 🔑 Offline key-generation runbook

> **Who:** Khaled (or whoever holds release authority). **Where:** an **air-gapped / offline**
> machine — never a server, never the shared media host, never CI. **Why:** the private signing &
> license keys are the crown jewels; if they leak, an attacker can forge updates/licenses. See
> [SECURITY-BLOCKERS.md](SECURITY-BLOCKERS.md) gates #1–#3.
>
> Do this ONCE to bootstrap, then keep the keys offline forever. Signing releases also happens
> offline (Step 6). The server only ever sees **public** keys and **already-signed** artifacts.

---

## 0. Prepare the offline machine

1. Use a clean machine with **no network** (pull the cable / disable Wi-Fi). A spare laptop or a
   live-USB Linux session is ideal.
2. Copy the repo's tools onto it via USB: you only need `app/crypto/` + `tools/` + a Python 3.12
   with **PyNaCl** installed (`pip install pynacl` — do this on the offline box from a vendored
   wheel, or install before going offline).
3. Verify the tools are present: `tools/gen_keypair.py`, `tools/sign_release.py`,
   `app/crypto/signing.py`.

## 1. Generate the SIGNING keypair (for release manifests)

```
python tools/gen_keypair.py netplex-signing-2026
```
Outputs:
- `netplex-signing-2026.key` — **PRIVATE** (32-byte ed25519 seed, base64, `chmod 600`). **Never leaves the offline machine + escrow.**
- `netplex-signing-2026.pub` — **PUBLIC** (base64). Safe to ship.
- prints the **`key_id`** (e.g. `98f5018062f93851`) and a ready-to-bake trust-store entry.

Write down the `key_id` — it identifies this signer in every manifest.

## 2. Generate the LICENSE keypair (separate key for licenses)

```
python tools/gen_keypair.py netplex-license-2026
```
Same outputs. Keep release-signing and license-issuing keys **separate** so one can be rotated or
revoked without the other.

## 3. Escrow (do NOT skip)

- Copy **both `.key` files** onto **two encrypted USB drives** (e.g. LUKS or VeraCrypt).
- Store the two drives in **two physically separate locations** (e.g. home safe + offsite).
- Record each `key_id` and which drive holds which key, somewhere durable (password manager note).
- **Test restore once:** plug a drive in on the offline box, decrypt, confirm the `.key` reads.
- If both escrow copies are ever lost, you can never sign a trusted update again → treat escrow as
  mandatory, not optional.

## 4. Bake the PUBLIC keys into the product trust store

The product ships a trust store of public keys. Add an entry per key:

```json
{
  "keys": [
    { "key_id": "<signing key_id>", "public_key": "<netplex-signing-2026.pub contents>", "status": "active",  "use": "release" },
    { "key_id": "<license key_id>", "public_key": "<netplex-license-2026.pub contents>", "status": "active",  "use": "license" }
  ]
}
```
- This file is **baked into the install image** (trust-on-first-install) — it is public, commit it
  to the product repo when that wiring is built (tracker item "bake public key into product").
- `status`: `active` (current), `next` (incoming during rotation), `revoked` (compromised).

## 5. Configure the receiving end (server)

On `netplex-support`, set the **public** keys via env (never the private keys):
```
SIGNING_PUBLIC_KEY=<netplex-signing-2026.pub contents>
LICENSE_PUBLIC_KEY=<netplex-license-2026.pub contents>
```
The server verifies signatures/licenses with these; it holds **no** private key.

## 6. Sign a release (every release, OFFLINE)

1. Build the unsigned `manifest.json` (versions, per-service digests, changelog) on the online box.
2. Move it to the offline box via USB.
3. Sign:
   ```
   python tools/sign_release.py netplex-signing-2026.key manifest.json signed-manifest.json
   ```
4. Move **only `signed-manifest.json`** back; publish it (+ artifacts) from `netplex-support`.
5. Boxes verify it against the baked-in public key before applying.

## 7. Rotation (planned, seamless — no downtime)

1. Offline: generate the new keypair (`gen_keypair.py netplex-signing-2027`).
2. Publish a **trust-update**: a manifest signed by the **current (active)** key that adds the new
   public key with `status: "next"`. Boxes adopt it → they now trust both.
3. After boxes have had time to adopt (an overlap window), switch signing to the new key and flip
   statuses: new → `active`, old → `revoked` (or drop).
4. Old key retired with zero box breakage.

## 8. Compromise response (emergency)

1. If a private key leaks: offline, publish a **revocation** — a trust-update signed by a
   *still-trusted* key that sets the bad `key_id` to `status: "revoked"`. Boxes reject anything
   signed by it immediately.
2. Roll forward to a fresh key per Step 7.
3. If **all** keys are compromised (escrow + active): ship an **out-of-band emergency installer**
   with a new baked-in trust store (rare, documented worst case).

## 9. Hard rules

- ❌ Never copy a `.key` to a server, CI, cloud, email, or chat.
- ❌ Never run `gen_keypair.py` / `sign_release.py` on the shared host or a networked server.
- ✅ Only `.pub` files and `signed-*.json` ever leave the offline machine.
- ✅ Keep escrow current after every rotation.
