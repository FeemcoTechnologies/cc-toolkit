#!/usr/bin/env bash
# ── CC Toolkit — stop + remove the stack ──────────────────────────────────
# Reads .env for the network name. Relies on compose's own env loading.
# Usage:
#   ./down.sh
# ──────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")"

if [ -f .env ]; then
  set -a
  . ./.env
  set +a
fi

if command -v podman-compose >/dev/null 2>&1; then
  podman-compose down
else
  docker compose down
fi