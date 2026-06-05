#!/usr/bin/env bash
# ── CC Toolkit — First-Run Setup ──────────────────────────────────────────
# Run this once after cloning the repository.
# It creates the workspace structure, generates config, and validates
# that the core dependencies are available.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/.../scripts/setup.sh | bash
#   # or
#   ./scripts/setup.sh
# ──────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CC="${PROJECT_DIR}/run.py"

echo "╔════════════════════════════════════════════════╗"
echo "║        CC Toolkit — First-Run Setup            ║"
echo "╚════════════════════════════════════════════════╝"

# ── 1. Workspace ──────────────────────────────────────────────────────────
CC_WORKSPACE="${CC_WORKSPACE:-/workspace}"
echo ""
echo "[1/5] Creating workspace: $CC_WORKSPACE"
mkdir -p "$CC_WORKSPACE"/{cases,tools,wordlists,logs,sessions,config,notebooks}
echo "  ✓ Done"

# ── 2. Python Environment ─────────────────────────────────────────────────
echo ""
echo "[2/5] Checking Python environment"
PYTHON=$(command -v python3 || command -v python || echo "")
if [ -z "$PYTHON" ]; then
    echo "  ✗ Python 3 not found! Install Python 3.10+ and try again."
    exit 1
fi
echo "  ✓ Found: $($PYTHON --version)"

# ── 3. Dependencies ───────────────────────────────────────────────────────
echo ""
echo "[3/5] Installing Python dependencies"
cd "$PROJECT_DIR"
$PYTHON -m pip install --quiet --upgrade pip
$PYTHON -m pip install --quiet -r requirements.txt
echo "  ✓ Done"

# ── 4. Optional Tools ─────────────────────────────────────────────────────
echo ""
echo "[4/5] Checking optional tools"
TOOLS_MISSING=()

for tool in nmap curl jq; do
    if command -v "$tool" &>/dev/null; then
        echo "  ✓ $tool found"
    else
        echo "  · $tool not found (optional)"
    fi
done

# ── 5. First-Run Validation ───────────────────────────────────────────────
echo ""
echo "[5/5] Validating setup"
cd "$PROJECT_DIR"
$PYTHON -c "
from modules.config import ensure_dirs, WORKSPACE
ensure_dirs()
print(f'  ✓ Workspace root: {WORKSPACE}')
print('  ✓ Configuration module loaded')
print('  ✓ Data directories created')
"
echo ""
echo "╔════════════════════════════════════════════════╗"
echo "║        Setup Complete!                         ║"
echo "║                                                ║"
echo "║  Run the web dashboard:                        ║"
echo "║    python run.py web                           ║"
echo "║                                                ║"
echo "║  Run the CLI/TUI:                              ║"
echo "║    python run.py cli                           ║"
echo "║                                                ║"
echo "║  Run the MCP server:                           ║"
echo "║    python run.py mcp                           ║"
echo "║                                                ║"
echo "║  Or with Docker:                               ║"
echo "║    docker compose up -d                        ║"
echo "╚════════════════════════════════════════════════╝"
