#!/usr/bin/env bash
# ── CC Toolkit — stop + remove the stack ──────────────────────────────────
# Uses podman-compose when available, else docker compose. Down does not need
# any value from .env; completions rely on compose's own env loading.
# Usage:
#   ./down.sh
# ──────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")"

if command -v podman-compose >/dev/null 2>&1; then
  podman-compose down
else
  docker compose down
fi