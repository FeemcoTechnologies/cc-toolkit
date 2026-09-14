"""Configuration system for cc-toolkit.

All settings have sensible defaults and can be overridden via:
1. Environment variables (CC_* prefix)
2. A JSON config file (CC_CONFIG_FILE or /workspace/config/settings.json)
"""

import copy
import json
import os
import secrets
import threading
from pathlib import Path

from modules.feature_groups import DEFAULT_FEATURES


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
ARSENAL_DIR  = Path(_env_or_default("ARSENAL_DIR",  str(WORKSPACE / "arsenal")))
ARSENAL_RULES_FILE = Path(_env_or_default("ARSENAL_RULES_FILE",
                                          str(WORKSPACE / "arsenal-rules.json")))
ENV_PROFILES_FILE  = Path(_env_or_default("ENV_PROFILES_FILE",
                                          str(WORKSPACE / "env-profiles.json")))

# ── Web Dashboard ──────────────────────────────────────────────────────────
DASHBOARD_HOST     = _env_or_default("HOST",     "0.0.0.0")
DASHBOARD_PORT     = int(_env_or_default("PORT",      "5000"))
DASHBOARD_API_KEY  = _env_or_default("API_KEY",  "")
WS_PORT            = int(_env_or_default("WS_PORT",   "5001"))
DEBUG              = _env_or_default("DEBUG",    "").lower() in ("1", "true", "yes")
# If CC_SECRET is not set a per-process random key is generated so sessions
# are always signed and the weak placeholder can never be relied upon.
# Set CC_SECRET (or CC_DASHBOARD_KEY for API access) in production.
SECRET_KEY         = _env_or_default("SECRET", "") or secrets.token_hex(16)

# ── External Services ──────────────────────────────────────────────────────
# Jupyter notebook server
JUPYTER_URL = _env_or_default("JUPYTER_URL", "http://localhost:8888")
# Caido intercepting proxy
CAIDO_URL   = _env_or_default("CAIDO_URL",   "http://localhost:8080")
CAIDO_HOST  = _env_or_default("CAIDO_HOST",  "localhost")
CAIDO_PORT  = int(_env_or_default("CAIDO_PORT", "8080"))
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

# Directory names excluded from recursive scans (appsec, bin_surface, yara,
# semgrep, etc.). These hold engagement artifacts / tooling output that must
# never be fed back into the scanner.
DEFAULT_EXCLUDE_DIRS = (
    ".git", "__pycache__", ".venv", "venv", "node_modules", "dist", "build",
    "site-packages", "target", ".mypy_cache", ".pytest_cache", "cases",
    "data", "nmap_scans",
)


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


# ── Burp Suite / ZAP / Misc constants expected by web_dashboard/app.py ─────
BURP_API_URL   = _env_or_default("BURP_API_URL",  "http://192.168.56.1:1337")
BURP_API_KEY   = os.environ.get("BURP_API_KEY", "")
BURP_PROXY_URL = _env_or_default("BURP_PROXY_URL", "http://192.168.56.1:8081")

# ── Config file with mtime-cached reads ─────────────────────────────────────
CONFIG_FILE = CONFIG_DIR / "settings.json"

DEFAULT_CONFIG = {
    "dashboard_host": DASHBOARD_HOST,
    "dashboard_port": DASHBOARD_PORT,
    "dashboard_debug": DEBUG,
    "dashboard_api_key": DASHBOARD_API_KEY,
    "workspace": str(WORKSPACE),
    "pentest_dir": str(PENTEST_DIR),
    "cases_dir": str(CASES_DIR),
    "tools_dir": str(TOOLS_DIR),
    "wordlists_dir": str(WORDLISTS_DIR),
    "logs_dir": str(LOGS_DIR),
    "sessions_dir": str(SESSIONS_DIR),
    "jupyter_url": str(JUPYTER_URL),
    "caido_url": str(CAIDO_URL),
    "obsidian_dir": str(OBSIDIAN_DIR),
    "burp_api_url": BURP_API_URL,
    "burp_api_key": BURP_API_KEY,
    "burp_proxy_url": BURP_PROXY_URL,
    "zap": {"url": "http://127.0.0.1:8080", "api_key": "changeme", "bin": "zaproxy"},
    "features": DEFAULT_FEATURES,
}

_CONFIG_CACHE = None
_CONFIG_MTIME = None
_config_lock = threading.RLock()


def load_config() -> dict:
    """Return config dict, re-reading CONFIG_FILE when it changes on disk."""
    global _CONFIG_CACHE, _CONFIG_MTIME
    with _config_lock:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        if CONFIG_FILE.exists():
            try:
                mtime = CONFIG_FILE.stat().st_mtime
            except OSError:
                mtime = _CONFIG_MTIME
            if _CONFIG_CACHE is None or _CONFIG_MTIME != mtime:
                _CONFIG_CACHE = {**copy.deepcopy(DEFAULT_CONFIG),
                                 **json.loads(CONFIG_FILE.read_text())}
                _CONFIG_MTIME = mtime
        else:
            _CONFIG_CACHE = copy.deepcopy(DEFAULT_CONFIG)
            _CONFIG_MTIME = None
            save_config(_CONFIG_CACHE)
        return _CONFIG_CACHE


def save_config(cfg: dict) -> None:
    global _CONFIG_CACHE, _CONFIG_MTIME
    with _config_lock:
        _CONFIG_CACHE = cfg
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
        try:
            _CONFIG_MTIME = CONFIG_FILE.stat().st_mtime
        except OSError:
            _CONFIG_MTIME = None


def update_config(mutator) -> dict:
    """Atomically load → mutate → save the config under a lock."""
    with _config_lock:
        cfg = load_config()
        mutator(cfg)
        save_config(cfg)
        return cfg
