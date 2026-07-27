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
| **Licensing authority** | verifies signed license tokens (tier, expiry); registers tokens minted offline; the source of tier truth | **live** — verify + register; `/issue` permanently 🔴 gated (key custody) |
| **Release / update authority** | receives + verifies + serves signed release manifests; offline signing pipeline for whoever holds the signing key | **live** — upload + serve; `/publish` (server-side signing) permanently 🔴 gated (key custody) |

## Boundary rules (non-negotiable)

1. The **private signing key** and **license-issuing key** live ONLY here, never in `netplex`.
2. The product talks to this service **outbound-only / pull-based** over TLS 1.3. This service
   **never** connects into a user's box.
3. **Source of truth** = this repo's DB + object store. GitHub Issues is a *work mirror*, never
   the database or a binary store. **No binaries are ever committed to git** (screenshots → object store).
4. Identity is stored only for **identified (paid) tiers**; free tier stays anonymous (claim code).

## Status

DESIGN + SCAFFOLD (2026-06-23), **deployed** (2026-07-27) as `support.netplex.io`. Khaled
generated the real production **license** keypair offline 2026-07-27
(`key_id f98ca2703f3ed827`) and `LICENSE_PUBLIC_KEY` is live — `/license/verify` genuinely
verifies now. As of the same day, the **offline-sign-then-upload receiving pipeline** is built
+ tested for both subsystems:

- `POST /api/v1/releases/upload` (admin-only) + `GET /api/v1/releases/manifest/{channel}` —
  accepts an already-signed manifest, verifies it against `SIGNING_PUBLIC_KEY`/
  `SIGNING_TRUST_STORE_JSON`, stores it, serves the latest per channel.
- `POST /api/v1/license/register` (admin-only) + `GET /api/v1/license/registered/{customer_ref}`
  — same shape, for license tokens minted offline with `tools/mint_license.py`.

`POST /api/v1/releases/publish` and `POST /api/v1/license/issue` stay **permanently** `501` —
server-side signing/issuing is an architectural boundary (docs/SECURITY-BLOCKERS.md #3), not a
temporary gate the upload/register endpoints relax. `SIGNING_PUBLIC_KEY` is not yet set (only the
license key has been generated so far), so `/releases/upload` correctly fails closed as
`unknown-key` until Khaled generates the release-signing keypair too (see
[docs/KEY-GENERATION-RUNBOOK.md](docs/KEY-GENERATION-RUNBOOK.md)) and hands over its `.pub`.
Everything else — `/health`, diagnostics intake (`/forward`, `/web`), ticket triage — is live,
scoped and bounded, no private key involved anywhere in this repo.

Design source of truth lives in the product repo:
`netplex/docs/platform/support-system.md` and `netplex/docs/platform/living-system.md`.

## Run

```bash
pip install -r requirements.txt
# Fail-closed without these — generate with: openssl rand -base64 32
export FORWARD_INTAKE_TOKENS="..."
export ADMIN_API_TOKENS="..."
uvicorn app.main:app --host 0.0.0.0 --port 8080
# or: docker compose up   (FORWARD_INTAKE_TOKENS / ADMIN_API_TOKENS must be set)
pytest -q
```

## Deploy

`./deploy.sh` clones/pulls this repo on the remote and runs it via `docker compose`
(host networking, `uvicorn` bound to `127.0.0.1` only, fronted by the shared Caddy —
see `docker-compose.yml`). Host networking (like `netplex-rendezvous`, though for a
different reason: bridge NAT would make the peer IP Caddy's `X-Forwarded-For` trust
depends on float across network recreation, silently breaking `TRUSTED_PROXIES` —
see the compose file's comment) keeps Caddy's real loopback address the stable,
actual peer, which `app/auth.py:client_ip` needs for the `/diagnostics/web` rate
limiter. SQLite (the dev fallback) is bind-mounted at `./data` for persistence across
container recreation; swap `DATABASE_URL` for Postgres when ticket volume warrants it.

## Layout

```
app/
  main.py            FastAPI entrypoint (health + router mounts)
  config.py          settings
  db.py              DB session (Postgres / SQLite dev)
  models.py          ticket / license-token / release-manifest tables
  routers/
    diagnostics.py   receive forwarded reports  (scaffold)
    tickets.py       ticket CRUD + triage + claim (scaffold)
    licensing.py     verify / register (live); issue permanently gated
    releases.py      upload / serve manifests (live); publish permanently gated
  storage/
    blobs.py         object-store interface for screenshots (scaffold)
docs/
  SECURITY-BLOCKERS.md   the 🔴 gates that must clear before signing/distribution code
tests/
```
