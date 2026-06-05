#!/bin/bash
# vm-startup-hook.sh — intended to be called from VM startup scripts
# (e.g. rc.local, systemd, .bashrc of auto-login user)
#
# This replaces the old vm-startup-new.sh with a more flexible approach.
# It sources the environment setup and optionally launches the dashboard.
#
# Usage:
#   ./vm-startup-hook.sh                    # default profile
#   ./vm-startup-hook.sh forensics          # forensics profile
#   ./vm-startup-hook.sh lightweight        # lightweight profile
#
# Environment:
#   CC_NO_DASHBOARD=1   skip dashboard launch
#   CC_PROFILE=full     set profile (also accepted as $1)

CC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE="${1:-${CC_PROFILE:-default}}"

# Source environment (this also starts JupyterLab)
source "$CC_DIR/env-setup.sh" "$PROFILE"

# Print quick reference
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║            Kali Command Center - Quick Ref              ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  cc dashboard           Live resource dashboard         ║"
echo "║  cc tools list          Browse all available tools      ║"
echo "║  cc tools search <term> Search for a tool               ║"
echo "║  cc wifi scan           Scan for access points          ║"
echo "║  cc hexstrike           Launch HexStrike                ║"
echo "║  cc scan quick <target> Quick nmap + whatweb            ║"
echo "║  cc vm list             List VMs (VBox + libvirt)       ║"
echo "║  cc arsenal case <type> Set runtime arsenal filter      ║"
echo "║  cc profile list        Show environment profiles       ║"
echo "║  cc start               Start JupyterLab                ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo "Caido proxy: http://192.168.56.1:8080"
echo ""

# Optionally launch dashboard in a tmux session
if [ -z "$CC_NO_DASHBOARD" ]; then
    tmux new-session -s "cc-dashboard" -d "python3 $CC_DIR/kali-command-center.py dashboard"
fi
