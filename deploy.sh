#!/usr/bin/env bash
# Remote deploy for support.netplex.io (the netplex-support receiving-end service).
# Usage: ./deploy.sh [user@host] [port]
#   defaults: user@host = ${DEPLOY_TARGET:-ubuntu@168.138.30.115}, port = ${PORT:-18099}
# Clones (or pulls) this repo on the remote and runs it via docker compose.
# Mirrors netplex-rendezvous/deploy.sh's shape. Also host-networked like rendezvous
# (see docker-compose.yml for why - bridge NAT floats the peer IP Caddy's
# X-Forwarded-For trust needs to be stable), but binds 127.0.0.1 only, never 0.0.0.0.
#
# REQUIRED on the remote before first run - the container is fail-closed without them:
#   FORWARD_INTAKE_TOKENS, ADMIN_API_TOKENS   (openssl rand -base64 32 each)
# Put them in the remote checkout's .env. This script does NOT generate, transmit, or
# store any secret itself - nor the license/signing keys (those are never generated
# here at all; see docs/KEY-GENERATION-RUNBOOK.md).
set -euo pipefail
TARGET="${1:-${DEPLOY_TARGET:-ubuntu@168.138.30.115}}"
PORT="${2:-${PORT:-18099}}"
REPO="https://github.com/netplexio/netplex-support.git"
DIR="netplex-support"

echo "[deploy] target=$TARGET port=$PORT"
ssh -o StrictHostKeyChecking=accept-new "$TARGET" bash -s -- "$REPO" "$DIR" "$PORT" <<'REMOTE'
set -euo pipefail
REPO="$1"; DIR="$2"; PORT="$3"
if [ -d "$DIR/.git" ]; then git -C "$DIR" pull --ff-only; else git clone "$REPO" "$DIR"; fi
cd "$DIR"
mkdir -p data
# Prefer docker compose; fall back to a venv + uvicorn if docker is absent.
if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
  PORT_HOST="$PORT" docker compose up -d --build
else
  python3 -m venv .venv && . .venv/bin/activate && pip install -q -r requirements.txt
  pkill -f "uvicorn app.main:app" 2>/dev/null || true
  nohup .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port "$PORT" >/tmp/netplex-support.log 2>&1 &
  sleep 2
fi
curl -sf "http://127.0.0.1:${PORT}/health" && echo "  <- health OK on :$PORT" || { echo "health FAILED"; exit 1; }
REMOTE
echo "[deploy] done - service should answer on 127.0.0.1:$PORT/health on the target"
