# Shared constants used across all modules

import json
from pathlib import Path

CC_DIR = Path(__file__).resolve().parent.parent
CASES_DIR = CC_DIR / "cases"
PLAYBOOKS_DIR = CC_DIR / "playbooks"
TEMPLATES_DIR = CC_DIR / "templates"
MODULES_DIR = CC_DIR / "modules"

CONFIG_DIR = Path.home() / ".config" / "kali-command-center"
CONFIG_FILE = CONFIG_DIR / "config.json"
WORKSPACE = Path("/share")
PENTEST_DIR = WORKSPACE / "pentests"
VMS_DIR = WORKSPACE / "vms"
DISKS_DIR = VMS_DIR / "disks"
ISOS_DIR = VMS_DIR / "isos"
LOGS_DIR = VMS_DIR / "logs"
TOOLS_DIR = WORKSPACE / "tools"
GIT_REPO = Path("/share/git-repo")
# SCRIPTS_DIR is the parent of CC_DIR (ai-combined-tools), which contains
# all the sibling rule directories (Semgrep-Crypto-Backdoors, aislop, nuclei, etc.)
# On Kali: /share/git-repo/Scripts. On Windows: C:\Users\...\git-repo\Scripts
SCRIPTS_DIR = CC_DIR.parent
ARSENAL_DIR = Path.home() / "arsenal"
ARSENAL_RULES_FILE = CC_DIR / "arsenal-rules.json"
ENV_PROFILES_FILE = CC_DIR / "env-profiles.json"
NOTEBOOK_DIR = GIT_REPO / "Notebooks" / "Mine"

WORDLISTS_DIR = Path("/wordlists")
YARA_RULES_DIR = SCRIPTS_DIR / "SpecialYaraRules"
SIGMA_RULES_DIR = SCRIPTS_DIR / "sigma rules"
SEMGREP_RULES_DIR = SCRIPTS_DIR / "Semgrep-Crypto-Backdoors"
NUCLEI_TEMPLATES_DIR = Path.home() / "nuclei-templates"

OBSIDIAN_DIR = GIT_REPO / "Notes" / "Obsidian" / "RandomDocs" / "RandomDocs"
OBSIDIAN_OUTPUT_SUBDIR = "Command Center"  # subfolder in vault for auto-generated notes
PENTEST_NOTES_DIR = OBSIDIAN_DIR / "Pentests" / "c-reports"  # Obsidian vault reports

JUPYTER_PORT = 8888
CAIDO_HOST = "192.168.56.1"
CAIDO_PORT = 8080

# Report branding
COMPANY = "Feemco Technologies"
TESTER = "Jeff Feemster"
LOGO_RELPATH = "./Data/Logo Try 2.png"

DEFAULT_CONFIG = {
    "jupyter_port": JUPYTER_PORT,
    "jupyter_dir": "/",
    "caido_url": f"http://{CAIDO_HOST}:{CAIDO_PORT}",
    "caido_host": CAIDO_HOST,
    "caido_port": CAIDO_PORT,
    "workspace": str(WORKSPACE),
    "vms_dir": str(VMS_DIR),
    "disks_dir": str(DISKS_DIR),
    "isos_dir": str(ISOS_DIR),
    "logs_dir": str(LOGS_DIR),
    "tools_dir": str(TOOLS_DIR),
    "arsenal_dir": str(ARSENAL_DIR),
    "pentest_dir": str(PENTEST_DIR),
    "cases_dir": str(CASES_DIR),
    "wordlists_dir": str(WORDLISTS_DIR),
    "wordlist_dns": "/wordlists/dns-top-10000.txt",
    "wordlist_web": "/wordlists/webcontent-top-10000.txt",
    "yara_rules_dir": str(YARA_RULES_DIR),
    "sigma_rules_dir": str(SIGMA_RULES_DIR),
    "semgrep_rules_dir": str(SEMGREP_RULES_DIR),
    "nuclei_templates_dir": str(NUCLEI_TEMPLATES_DIR),
    # Web dashboard
    "dashboard_host": "0.0.0.0",
    "dashboard_port": 5000,
    "dashboard_debug": False,
    "dashboard_api_key": "",
}


_CONFIG_CACHE = None


def load_config() -> dict:
    global _CONFIG_CACHE
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if CONFIG_FILE.exists():
        _CONFIG_CACHE = {**DEFAULT_CONFIG, **json.loads(CONFIG_FILE.read_text())}
    else:
        _CONFIG_CACHE = dict(DEFAULT_CONFIG)
        save_config(_CONFIG_CACHE)
    return _CONFIG_CACHE


def save_config(cfg: dict) -> None:
    global _CONFIG_CACHE
    _CONFIG_CACHE = cfg
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
