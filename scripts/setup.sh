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
echo "[1/7] Creating workspace: $CC_WORKSPACE"
mkdir -p "$CC_WORKSPACE"/{cases,tools,wordlists,logs,sessions,config,notebooks}
echo "  ✓ Done"

# ── 2. Python Environment ─────────────────────────────────────────────────
echo ""
echo "[2/7] Checking Python environment"
PYTHON=$(command -v python3 || command -v python || echo "")
if [ -z "$PYTHON" ]; then
    echo "  ✗ Python 3 not found! Install Python 3.10+ and try again."
    exit 1
fi
echo "  ✓ Found: $($PYTHON --version)"

# ── 3. Dependencies ───────────────────────────────────────────────────────
echo ""
echo "[3/7] Installing Python dependencies"
cd "$PROJECT_DIR"
$PYTHON -m pip install --quiet --upgrade pip
$PYTHON -m pip install --quiet -r requirements.txt
echo "  ✓ Done"

# ── 4. Optional Tools ─────────────────────────────────────────────────────
echo ""
echo "[4/7] Checking optional tools"
TOOLS_MISSING=()

for tool in nmap curl jq; do
    if command -v "$tool" &>/dev/null; then
        echo "  ✓ $tool found"
    else
        echo "  · $tool not found (optional)"
    fi
done

# ── 6. OpenCode MCP Configuration ──────────────────────────────────────────
echo ""
echo "[6/6] Configuring opencode MCP servers"
cfg_dir="${CC_OPENCODE_CONFIG_DIR:-$HOME/.config/opencode}"
cfg_file="${cfg_dir}/opencode.json"
mkdir -p "$cfg_dir"

$PYTHON - <<PYEOF
import json, os, shutil
from pathlib import Path

proj = Path("$PROJECT_DIR")
cfg_dir = Path("$cfg_dir")
cfg_file = cfg_dir / "opencode.json"

data = {}
if cfg_file.exists():
    try:
        data = json.loads(cfg_file.read_text(encoding="utf-8"))
    except Exception:
        data = {}
mcp = data.setdefault("mcp", {})

# Always register cc-toolkit (python3 run.py mcp — portable relative path)
mcp["cc-toolkit"] = {
    "type": "local",
    "command": ["python3", str((proj / "run.py"))],
    "args": ["mcp"],
    "enabled": True,
}

# FFUF/fuzz-guide MCP — registered if the modules are present
if (proj / "fuzz_guide_mcp.py").exists():
    mcp["fuzz-guide"] = {
        "type": "local",
        "command": ["python3", str((proj / "fuzz_guide_mcp.py"))],
        "environment": {
            "FUZZ_GUIDE_WORKDIR": os.environ.get("FUZZ_GUIDE_WORKDIR", "/tmp/fuzz_guide_workdir"),
        },
        "enabled": True,
    }
    print("  ✓ fuzz-guide MCP registered")
else:
    mcp.pop("fuzz-guide", None)

# Ghidra MCP — registered only when GHIDRA_SERVICE_DIR is set
ghidra_svc = os.environ.get("GHIDRA_SERVICE_DIR", "")
if ghidra_svc and (proj / "ghidra_mcp.py").exists():
    mcp["ghidra"] = {
        "type": "local",
        "command": ["python3", str((proj / "ghidra_mcp.py"))],
        "environment": {"GHIDRA_SERVICE_DIR": ghidra_svc},
        "enabled": True,
    }
    print("  ✓ ghidra MCP registered")
else:
    mcp.pop("ghidra", None)

# Preserve any existing provider/other keys; only add our servers.
cfg_file.write_text(json.dumps(data, indent=2))
print(f"  ✓ wrote {cfg_file}")
PYEOF

# ── 7. First-Run Validation ───────────────────────────────────────────────
echo ""
echo "[7/7] Validating setup"
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
