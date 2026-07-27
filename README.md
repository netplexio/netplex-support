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

DESIGN + SCAFFOLD (2026-06-23), now **deployed** (2026-07-27) as `support.netplex.io`. The 🔴
release/signing/distribution subsystems stay **gated** on the security blockers in
[docs/SECURITY-BLOCKERS.md](docs/SECURITY-BLOCKERS.md) — `/api/v1/releases/*` returns `501` and
`/api/v1/license/issue` returns `501` until Khaled generates the offline signing + license
keypair (see [docs/KEY-GENERATION-RUNBOOK.md](docs/KEY-GENERATION-RUNBOOK.md)) and hands over the
two `.pub` files. Everything else — `/health`, diagnostics intake (`/forward`, `/web`), ticket
triage, and license **verify** — is live now, scoped and bounded, no private key involved.

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
(bridge networking, published to `127.0.0.1` only, fronted by the shared Caddy — see
`docker-compose.yml`). Unlike `netplex-rendezvous`, this service does **not** need host
networking: it's a plain HTTP API, always reached through the proxy, so
`TRUSTED_PROXIES` (honoured only from the proxy's own address) resolves the real client
IP for the `/diagnostics/web` rate limiter instead (`app/auth.py:client_ip`). SQLite
(the dev fallback) is bind-mounted at `./data` for persistence across container
recreation; swap `DATABASE_URL` for Postgres when ticket volume warrants it.

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
