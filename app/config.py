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

    # Crypto — 🔴 GATED subsystems. Public keys may be present; PRIVATE keys must come from the
    # secret store at runtime and are gated on docs/SECURITY-BLOCKERS.md.
    LICENSE_PUBLIC_KEY: str = os.environ.get("LICENSE_PUBLIC_KEY", "")
    SIGNING_PUBLIC_KEY: str = os.environ.get("SIGNING_PUBLIC_KEY", "")
    # Private keys intentionally NOT read here — release/issue code is gated.

    # Intake limits (anti-abuse)
    INTAKE_RATE_PER_MIN: int = int(os.environ.get("INTAKE_RATE_PER_MIN", "30"))
    WEB_INTAKE_RATE_PER_MIN: int = int(os.environ.get("WEB_INTAKE_RATE_PER_MIN", "10"))
    MAX_BLOB_BYTES: int = int(os.environ.get("MAX_BLOB_BYTES", str(5 * 1024 * 1024)))

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
