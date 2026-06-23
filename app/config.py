"""Settings for netplex-support. Keys are loaded from the environment / secret store ONLY —
never hard-coded, never committed (see .gitignore)."""
from __future__ import annotations
import os


class Settings:
    # Storage
    DATABASE_URL: str = os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///./netplex_support.db")
    OBJECT_STORE_URL: str = os.environ.get("OBJECT_STORE_URL", "")  # S3-compatible; blobs only

    # GitHub mirror (work surface, not source of truth)
    GITHUB_REPO: str = os.environ.get("GITHUB_REPO", "ikhal3d/netplex")
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


settings = Settings()
