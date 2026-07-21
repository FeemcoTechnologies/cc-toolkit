"""Configuration system for cc-toolkit.

All settings have sensible defaults and can be overridden via:
1. Environment variables (CC_* prefix)
2. A JSON config file (CC_CONFIG_FILE or /workspace/config/settings.json)
"""

import os
import json
from pathlib import Path


def _env_or_default(key, default):
    """Return env var CC_<key> if set, else default."""
    return os.environ.get(f"CC_{key}", default)


# ── Workspace ──────────────────────────────────────────────────────────────
# Root data directory. In Docker: /workspace. On host: any writable path.
WORKSPACE = Path(_env_or_default("WORKSPACE", "/workspace"))

PENTEST_DIR  = Path(_env_or_default("PENTEST_DIR",  str(WORKSPACE / "cases")))
TOOLS_DIR    = Path(_env_or_default("TOOLS_DIR",    str(WORKSPACE / "tools")))
WORDLISTS_DIR = Path(_env_or_default("WORDLISTS_DIR", str(WORKSPACE / "wordlists")))
LOGS_DIR     = Path(_env_or_default("LOGS_DIR",     str(WORKSPACE / "logs")))
SESSIONS_DIR = Path(_env_or_default("SESSIONS_DIR", str(WORKSPACE / "sessions")))
CONFIG_DIR   = Path(_env_or_default("CONFIG_DIR",   str(WORKSPACE / "config")))
NOTEBOOK_DIR = Path(_env_or_default("NOTEBOOK_DIR", str(WORKSPACE / "notebooks")))
GIT_REPO     = Path(_env_or_default("GIT_REPO",     str(WORKSPACE / "git-repo")))

# ── Web Dashboard ──────────────────────────────────────────────────────────
DASHBOARD_HOST     = _env_or_default("HOST",     "0.0.0.0")
DASHBOARD_PORT     = int(_env_or_default("PORT",      "5000"))
DASHBOARD_API_KEY  = _env_or_default("API_KEY",  "")
WS_PORT            = int(_env_or_default("WS_PORT",   "5001"))
DEBUG              = _env_or_default("DEBUG",    "").lower() in ("1", "true", "yes")
SECRET_KEY         = _env_or_default("SECRET",   "change-me-in-production")

# ── External Services ──────────────────────────────────────────────────────
# Jupyter notebook server
JUPYTER_URL = _env_or_default("JUPYTER_URL", "http://localhost:8888")
# Caido intercepting proxy
CAIDO_URL   = _env_or_default("CAIDO_URL",   "http://localhost:8080")
# Ollama LLM inference server
OLLAMA_HOST = _env_or_default("OLLAMA_HOST", "http://localhost:11434")
# SSH tunnel target for AI infrastructure (host where ollama runs)
AI_TUNNEL_HOST  = _env_or_default("AI_TUNNEL_HOST",  "tunnel-host")
AI_JUMP_HOST    = _env_or_default("AI_JUMP_HOST",    "jump-host")
AI_JUMP_USER    = _env_or_default("AI_JUMP_USER",    "jump-user")
AI_TARGET_HOST  = _env_or_default("AI_TARGET_HOST",  "target-host")
AI_TARGET_USER  = _env_or_default("AI_TARGET_USER",  "target-user")
AI_MODEL        = _env_or_default("AI_MODEL",        "qwen2.5:3b")
AI_GPU_LAYERS   = int(_env_or_default("AI_GPU_LAYERS",  "10"))
AI_LOCAL_PORT   = int(_env_or_default("AI_LOCAL_PORT",  "11434"))
AI_OLLAMA_PORT  = int(_env_or_default("AI_OLLAMA_PORT", "11434"))
# Kali SSH target ("user@host" – empty = disabled)
KALI_SSH    = _env_or_default("KALI_SSH",    "")

# ── Obsidian Report Output ─────────────────────────────────────────────────
# Set CC_OBSIDIAN_DIR to a path inside an Obsidian vault for auto-export.
# When None/empty, reports are saved locally only under the case directory.
OBSIDIAN_DIR          = _env_or_default("OBSIDIAN_DIR", "")
OBSIDIAN_OUTPUT_SUBDIR = _env_or_default("OBSIDIAN_OUTPUT_SUBDIR", "Command Center")

# ── Misc ───────────────────────────────────────────────────────────────────
# AES secret for credential vault (auto-generated on first run if empty)
VAULT_SECRET = _env_or_default("VAULT_SECRET", "")

# ── Report Branding ─────────────────────────────────────────────────────────
COMPANY      = _env_or_default("COMPANY",      "Your Company Name")  # Change this or set CC_COMPANY env var
TESTER       = _env_or_default("TESTER",       "Your Name")          # Change this or set CC_TESTER env var
LOGO_RELPATH = _env_or_default("LOGO_RELPATH", "")                   # Optional: path to logo image for reports
LOGOS_DIR    = Path(_env_or_default("LOGOS_DIR", str(WORKSPACE / "logos")))

# Derived from OBSIDIAN_DIR — default output for Obsidian vault reports
if OBSIDIAN_DIR:
    PENTEST_NOTES_DIR = Path(OBSIDIAN_DIR) / "Pentests" / "c-reports"
else:
    PENTEST_NOTES_DIR = Path("")

# ── Sync Compatibility Aliases ──────────────────────────────────────────────
# Code synced from the working repo imports these symbols from modules.config.
# They are aliases for the primary env-var-driven values above.
CASES_DIR = PENTEST_DIR
CC_DIR = WORKSPACE
PLAYBOOKS_DIR = WORKSPACE / "playbooks"
TEMPLATES_DIR = WORKSPACE / "templates"
MODULES_DIR = WORKSPACE / "modules"
SCRIPTS_DIR = WORKSPACE
NUCLEI_TEMPLATES_DIR = WORKSPACE / "nuclei-templates"
YARA_RULES_DIR = WORKSPACE / "rules" / "yara"
SIGMA_RULES_DIR = WORKSPACE / "rules" / "sigma"
SEMGREP_RULES_DIR = WORKSPACE / "rules" / "semgrep"


def load_config_file(path=None):
    """Merge settings from a JSON config file (overrides env vars)."""
    if path is None:
        path = os.environ.get("CC_CONFIG_FILE", str(CONFIG_DIR / "settings.json"))
    p = Path(path)
    if not p.exists():
        return {}
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def ensure_dirs():
    """Create all data directories if they don't exist."""
    for d in [PENTEST_DIR, TOOLS_DIR, WORDLISTS_DIR, LOGS_DIR,
              SESSIONS_DIR, CONFIG_DIR, NOTEBOOK_DIR]:
        d.mkdir(parents=True, exist_ok=True)
