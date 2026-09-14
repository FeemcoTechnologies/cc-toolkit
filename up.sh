#!/usr/bin/env bash
# ── CC Toolkit — build + start the whole stack ─────────────────────────────
# Safely reads the few flags it needs from .env (never sources it), assembles
# the service list, ensures the shared edge network exists, then up. Compose
# itself loads .env for the real environment (its parser, not the shell), so
# secret values may contain arbitrary characters without breaking this script.
#
# Usage:
#   ./up.sh [--no-build] [,service ...]
#
# Flags from .env (default 1):
#   CC_ENABLE_JUPYTER=1  CC_ENABLE_CAIDO=1  CC_ENABLE_EDR=1
# ──────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")"

# ── Safe .env read ─────────────────────────────────────────────────────────
# dotenv_get KEY [FILE] — print the value of KEY without ever evaluating the
# file with the shell, so weird characters in secrets can't break parsing.
# Strips surrounding single/double quotes and a trailing CR (CRLF-safe).
dotenv_get() {
  local key="$1" file="${2:-.env}" line val=""
  [ -f "$file" ] || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      \#*|"") continue ;;
      "$key"=*) val="${line#*=}"; break ;;
    esac
  done <"$file"
  [ -n "$val" ] || return 1
  val="${val%\"}"; val="${val#\"}"
  val="${val%\'}"; val="${val#\'}"
  val="${val%$'\r'}"
  printf '%s' "$val"
}

BUILD=1
if [ "${1:-}" = "--no-build" ]; then
  BUILD=0
  shift
fi

# Flags from .env (default 1). Read safely — never source the file.
CC_ENABLE_JUPYTER="$(dotenv_get CC_ENABLE_JUPYTER || true)"; CC_ENABLE_JUPYTER="${CC_ENABLE_JUPYTER:-1}"
CC_ENABLE_CAIDO="$(dotenv_get CC_ENABLE_CAIDO || true)"; CC_ENABLE_CAIDO="${CC_ENABLE_CAIDO:-1}"
CC_ENABLE_EDR="$(dotenv_get CC_ENABLE_EDR || true)"; CC_ENABLE_EDR="${CC_ENABLE_EDR:-1}"

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
NET="$(dotenv_get CC_NETNAME || true)"
NET="${NET:-cc-net}"
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