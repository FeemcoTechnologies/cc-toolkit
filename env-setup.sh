#!/bin/bash
# env-setup.sh — source this from .bashrc or run at VM startup:
#   source /share/git-repo/Scripts/ai-combined-tools/env-setup.sh
#
# Sets up aliases, env vars, and optionally launches services based on profile.

CC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CC_SCRIPT="$CC_DIR/kali-command-center.py"
PROFILE="${1:-default}"

# Primary alias
alias cc="python3 $CC_SCRIPT"

# Quick-access aliases for common operations
alias ccdash="python3 $CC_SCRIPT dashboard"
alias cctools="python3 $CC_SCRIPT tools"
alias ccwifi="python3 $CC_SCRIPT wifi"
alias ccscan="python3 $CC_SCRIPT scan"
alias ccvm="python3 $CC_SCRIPT vm"
alias cchex="python3 $CC_SCRIPT hexstrike"
alias ccarsenal="python3 $CC_SCRIPT arsenal"

# Caido remote proxy shortcut
alias caido-proxy="export HTTP_PROXY=http://192.168.56.1:8080 HTTPS_PROXY=http://192.168.56.1:8080 && echo 'Proxy set to 192.168.56.1:8080'"

# Source profile configuration
if command -v python3 &>/dev/null && [ -f "$CC_DIR/env-profiles.json" ]; then
    while IFS='=' read -r key value; do
        export "$key=$value"
    done < <(python3 -c "
import json
prof = json.load(open('$CC_DIR/env-profiles.json'))
p = prof['profiles'].get('$PROFILE', prof['profiles']['default'])
for k, v in p.get('env_vars', {}).items():
    print(f'{k}={v}')
for alias_name, alias_cmd in p.get('aliases', {}).items():
    print(f'ALIAS:{alias_name}={alias_cmd}')
")
fi

# Check if we should auto-start services (skip if already running or if SSH)
if [ -z "$SSH_CONNECTION" ] && [ -z "$CC_NO_START" ]; then
    python3 "$CC_SCRIPT" start 2>/dev/null
fi

echo "Kali Command Center loaded (profile: $PROFILE)"
echo "  Run: cc --help"
