#!/bin/sh
# NPX-2906: install deps for linux/arm64 and import the app. Run on a test VM (needs the
# container engine + qemu binfmt for arm64). Usage: arm64_build_check.sh [requirements-file]
# Default = requirements.lock (must pass). Pass requirements.txt (loose ranges) to see the
# old failure when sqlalchemy resolves to a release without greenlet.
cd "$(dirname "$0")/.." || exit 1
REQ="${1:-requirements.lock}"
exec docker run --rm --platform linux/arm64 --memory 1g --cpus 2 \
  -v "$PWD:/src:ro" python:3.12-slim sh -c \
  "pip install -q -r /src/$REQ && cd /src && python -c 'import greenlet, sqlalchemy.ext.asyncio, app.main; print(\"ARM64 IMPORT OK\")'"
