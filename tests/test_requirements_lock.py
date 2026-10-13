"""NPX-2906 - the image must build from exact pins that include greenlet.

WHAT WENT WRONG: unpinned `sqlalchemy>=2.0` re-resolved to SQLAlchemy 2.1, which no
longer pulls in `greenlet`, so on the aarch64 Oracle box `sqlalchemy.ext.asyncio`
raised ImportError and the container crash-looped. API-only by design: no UI surface.
The real arm64 build+import proof is tests/arm64_build_check.sh.
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _names(path):
    out = {}
    for line in (ROOT / path).read_text().splitlines():
        line = line.split("#")[0].strip()
        if line:
            m = re.match(r"([A-Za-z0-9_.-]+)(\[[^\]]*\])?(.*)", line)
            out[m.group(1).lower().replace("_", "-")] = m.group(3).strip()
    return out


def test_every_requirement_is_pinned_exactly():
    lock = _names("requirements.lock")
    for name in _names("requirements.txt"):
        assert name in lock, f"{name} missing from requirements.lock"
    assert all(v.startswith("==") for v in lock.values())


def test_greenlet_is_pinned():
    assert "greenlet" in _names("requirements.lock")


def test_sqlalchemy_asks_for_asyncio_extra():
    assert "sqlalchemy[asyncio]" in (ROOT / "requirements.txt").read_text().lower()


def test_dockerfile_installs_the_lock():
    d = (ROOT / "Dockerfile").read_text()
    assert "requirements.lock" in d and "requirements.txt" not in d
