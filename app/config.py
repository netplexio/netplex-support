"""Settings for netplex-support. Keys are loaded from the environment / secret store ONLY —
never hard-coded, never committed (see .gitignore)."""
from __future__ import annotations
import os


class Settings:
    # Storage
    DATABASE_URL: str = os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///./netplex_support.db")
    OBJECT_STORE_URL: str = os.environ.get("OBJECT_STORE_URL", "")  # S3-compatible; blobs only

    # GitHub mirror (work surface, not source of truth)
    GITHUB_REPO: str = os.environ.get("GITHUB_REPO", "netplexio/netplex")
    GITHUB_TOKEN: str = os.environ.get("GITHUB_TOKEN", "")  # scoped issues:write

    # Crypto — PUBLIC keys only; PRIVATE keys are never read here (see the "Private keys
    # intentionally NOT read here" line below — that invariant has NOT changed by adding
    # the two _TRUST_STORE_JSON settings: they still only ever carry public keys + status).
    LICENSE_PUBLIC_KEY: str = os.environ.get("LICENSE_PUBLIC_KEY", "")
    SIGNING_PUBLIC_KEY: str = os.environ.get("SIGNING_PUBLIC_KEY", "")
    # Optional multi-key trust stores (rotation/revocation — docs/KEY-GENERATION-RUNBOOK.md
    # §7-8): a JSON list of {"public_key": <b64>, "status": "active"|"next"|"revoked"}.
    # Takes precedence over the single *_PUBLIC_KEY above when set, so a key can be rotated
    # or revoked by redeploying this one value instead of losing history. Unset (the
    # default) → falls back to the single active key above, unchanged behaviour.
    LICENSE_TRUST_STORE_JSON: str = os.environ.get("LICENSE_TRUST_STORE_JSON", "")
    SIGNING_TRUST_STORE_JSON: str = os.environ.get("SIGNING_TRUST_STORE_JSON", "")
    # Private keys intentionally NOT read here — signing/issuing always happens OFFLINE
    # (tools/sign_release.py, tools/mint_license.py); this server only ever verifies.

    # Trusted reverse-proxy peers (IPs/CIDRs, or "*") whose X-Forwarded-For we honour for
    # IP-keyed decisions (the /diagnostics/web rate limit). Default empty = trust NONE, so
    # the raw socket peer is authoritative. Set to our Caddy terminator's address (it always
    # connects from localhost — "127.0.0.1") when deployed behind it. See app/auth.py.
    TRUSTED_PROXIES: str = os.environ.get("TRUSTED_PROXIES", "")

    # Intake limits (anti-abuse)
    INTAKE_RATE_PER_MIN: int = int(os.environ.get("INTAKE_RATE_PER_MIN", "30"))
    WEB_INTAKE_RATE_PER_MIN: int = int(os.environ.get("WEB_INTAKE_RATE_PER_MIN", "10"))
    # Anti-abuse ceiling for /license/verify specifically - it has no per-install budget
    # (a box calling it has no "install_id" concept the way diagnostics does), so it gets
    # its own, slightly more generous, IP-keyed limit (app/routers/licensing.py).
    LICENSE_VERIFY_RATE_PER_MIN: int = int(os.environ.get("LICENSE_VERIFY_RATE_PER_MIN", "30"))
    MAX_BLOB_BYTES: int = int(os.environ.get("MAX_BLOB_BYTES", str(5 * 1024 * 1024)))
    # Hard cap on ANY JSON API request body (app/main.py's _BodySizeLimitASGI), enforced
    # on the actual byte stream, not just a client-declared Content-Length. Generous
    # against the largest legitimate payload (ForwardedReport: 200+10000+16+64+32+128+
    # 4096+256 chars of declared fields + up to 10 attachment_refs, well under 32KB even
    # with JSON overhead) while still bounding an attacker's worst case.
    MAX_REQUEST_BODY_BYTES: int = int(os.environ.get("MAX_REQUEST_BODY_BYTES", str(64 * 1024)))

    # Machine-to-machine intake auth for /diagnostics/forward. A netplex box must
    # present `Authorization: Bearer <token>` matching this. UNSET ⇒ /forward is
    # DISABLED (fail-closed) so an open, unauthenticated ingest can never accept junk
    # (the box-forward hop was previously unauthenticated). Comma-separated allows
    # rotating tokens (old+new valid during a rollover).
    FORWARD_INTAKE_TOKENS: str = os.environ.get("FORWARD_INTAKE_TOKENS", "")

    # Admin/operator auth for the privileged triage surface (/tickets/admin/*). Same
    # fail-closed, comma-separated, Bearer-token scheme as the intake token. UNSET ⇒ the
    # admin queue is DISABLED (503), never served open (it was previously a `TODO: admin
    # auth` that handed the full triage queue to anyone).
    ADMIN_API_TOKENS: str = os.environ.get("ADMIN_API_TOKENS", "")


settings = Settings()
