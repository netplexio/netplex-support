# netplex-support — the receiving end

> **Crown-jewel repo.** This is the **central, server-side** half of netplex's support &
> update system. It is **separate from the `netplex` product repo on purpose**: it holds the
> private signing key and the license-issuing key, which must never live near a repo that
> self-hosting customers can read. Deploy to **our** cloud only (alongside the rendezvous relay).

**Plain English:** the `netplex` product (on the user's box) is the *transmitting* end. This repo
is the *receiving* end — where forwarded diagnostics land, where licenses are issued and verified,
where tickets are triaged, and where signed releases/updates are built and published.

## What lives here

| Subsystem | Purpose | Status |
|---|---|---|
| **Diagnostics destination** | receives opt-in forwarded crash/bug reports over TLS; stores tickets + redacted screenshot blobs | scaffold |
| **Ticket / triage** | the authoritative ticket DB + triage console; mirrors selected tickets to GitHub Issues | scaffold |
| **Licensing authority** | issues + verifies signed license tokens (tier, expiry); the source of tier truth | scaffold (🔴 key custody gated) |
| **Release / update authority** | builds release manifests, **ed25519-signs** them, runs the container registry, emits offline bundles | 🔴 GATED — do not implement until blockers cleared |

## Boundary rules (non-negotiable)

1. The **private signing key** and **license-issuing key** live ONLY here, never in `netplex`.
2. The product talks to this service **outbound-only / pull-based** over TLS 1.3. This service
   **never** connects into a user's box.
3. **Source of truth** = this repo's DB + object store. GitHub Issues is a *work mirror*, never
   the database or a binary store. **No binaries are ever committed to git** (screenshots → object store).
4. Identity is stored only for **identified (paid) tiers**; free tier stays anonymous (claim code).

## Status

DESIGN + SCAFFOLD (2026-06-23). The 🔴 release/signing/distribution subsystems are **gated** on the
security blockers in [docs/SECURITY-BLOCKERS.md](docs/SECURITY-BLOCKERS.md). The diagnostics +
ticket + licensing-verify paths can be built first.

Design source of truth lives in the product repo:
`netplex/docs/platform/support-system.md` and `netplex/docs/platform/living-system.md`.

## Layout

```
app/
  main.py            FastAPI entrypoint (health + router mounts)
  config.py          settings
  db.py              DB session (Postgres / SQLite dev)
  models.py          ticket / license / blob tables
  routers/
    diagnostics.py   receive forwarded reports  (scaffold)
    tickets.py       ticket CRUD + triage + claim (scaffold)
    licensing.py     issue/verify license tokens (scaffold; issue = gated)
    releases.py      manifest build + sign + publish (🔴 GATED stub)
  storage/
    blobs.py         object-store interface for screenshots (scaffold)
docs/
  SECURITY-BLOCKERS.md   the 🔴 gates that must clear before signing/distribution code
tests/
```
