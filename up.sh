#!/usr/bin/env bash
# ── CC Toolkit — build + start the whole stack ─────────────────────────────
# Read .env (flags + secrets), assemble the service list, ensure the shared
# edge network exists, then up. Uses podman-compose when available, else
# docker compose.
#
# Usage:
#   ./up.sh [--no-build] [,service ...]
#
# Flags from .env (default 1):
#   CC_ENABLE_JUPYTER=1  CC_ENABLE_CAIDO=1  CC_ENABLE_EDR=1
# ──────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")"

# Load .env if present (quietly — don't override the shell's own values).
if [ -f .env ]; then
  set -a
  . ./.env
  set +a
fi

BUILD=1
if [ "${1:-}" = "--no-build" ]; then
  BUILD=0
  shift
fi

CC_ENABLE_JUPYTER="${CC_ENABLE_JUPYTER:-1}"
CC_ENABLE_CAIDO="${CC_ENABLE_CAIDO:-1}"
CC_ENABLE_EDR="${CC_ENABLE_EDR:-1}"

# cc-toolkit is always on. Append others per flags.
SERVICES=(cc-toolkit)
[ "$CC_ENABLE_JUPYTER" = "1" ] && SERVICES+=(jupyter)
[ "$CC_ENABLE_CAIDO" = "1" ]   && SERVICES+=(caido)
[ "$CC_ENABLE_EDR" = "1" ]     && SERVICES+=(edr)
SERVICES+=("$@")

# Engine pick: podman-compose first (server), docker compose otherwise.
if command -v podman-compose >/dev/null 2>&1; then
  ENGINE=podman
  CMD=(podman-compose up -d)
else
  ENGINE=docker
  CMD=(docker compose up -d)
fi

# Ensure the shared edge network exists (nginx-proxy-manager/wg-easy join it
# via edges/. Services on it talk by container name, so no public ports are
# needed on the stack).
NET="${CC_NETNAME:-cc-net}"
if [ "$ENGINE" = "podman" ]; then
  podman network exists "$NET" >/dev/null 2>&1 || { echo "[up] creating network $NET"; podman network create "$NET"; }
else
  docker network inspect "$NET" >/dev/null 2>&1 || { echo "[up] creating network $NET"; docker network create "$NET"; }
fi

echo "[up] engine: $ENGINE  services: ${SERVICES[*]}"
if [ "$BUILD" = "1" ]; then
  if [ "$ENGINE" = "podman" ]; then
    podman-compose build "${SERVICES[@]}"
  else
    docker compose build "${SERVICES[@]}"
  fi
fi

"${CMD[@]}" "${SERVICES[@]}"