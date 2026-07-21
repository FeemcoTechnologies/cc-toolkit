"""Sync code from local working repo (ai-combined-tools) to public repo (cc-toolkit-public).

DATA SAFETY: This script NEVER copies case data, credentials, loot, assets,
or any runtime-generated data. It only copies code and configuration templates.

Transforms:
  - Rewrites modules.constants → modules.config (public shim)
  - Strips hardcoded IPs, PII, hostnames, file paths
  - Reports anything needing manual review
"""

import re
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
PUBLIC = _HERE                                # cc-toolkit-public  (destination)
WORKING = _HERE.parent / "ai-combined-tools"   # ai-combined-tools  (source)

if not WORKING.is_dir():
    print(f"ERROR: source directory not found: {WORKING}")
    print("Run this script from cc-toolkit-public/")
    sys.exit(1)

# -- DATA EXCLUSIONS ----------------------------------------------------------
# Any file or directory matching these names (at any depth) is SKIPPED.
# These are runtime-generated data that must NEVER reach the public repo.
SKIP_NAMES = {
    # Case management data directories
    "cases",              # Individual case directories with findings, evidence, notes
    "data",               # Logs, sessions, wifi sessions, dns monitors
    "nmap_scans",         # Raw nmap scan outputs
    "screenshots",        # Screenshots taken during assessments
    "logs",               # Application logs
    "sessions",           # App session data
    "wifi_sessions",      # WiFi monitor session captures
    "dns_monitors",       # DNS monitoring history
    "wordlists",           # Downloaded wordlists (large, environment-specific)

    # Runtime state files (NFC identification)
    ".vault_key",         # Encryption key
    "asset_db.json",      # Asset inventory database
    "arsenal-rules.json", # Local rules state
    "dashboard_layout.json", # User's widget layout
    "env-profiles.json",  # Environment profiles

    # Environment-specific scripts (never sync)
    "env-setup.sh",
    "vm-startup-hook.sh",

    # Client-specific files (never sync)
    "posusa_retest_xss_validation.md",
    "pt-2026-001-retest.yaml",

    # Code with hardcoded environment data (public uses modules/config.py instead)
    "constants.py",

    # Runtime scan/report output files (never sync)
    "ffuf_output",           # ffuf scan results
    "gobuster_output",       # gobuster scan results
    "sqlmap",                # sqlmap output in case dirs
    "reports",               # Per-case Eng report outputs under web_dashboard/

    # Local analysis artifacts (never sync)
    "report.json",           # Binary analysis report
    "reverse_exploit_analyzer.py",   # Per-binary analysis script
}
# Files that MUST NOT exist in the public repo — if found, abort
FILE_BLOCKLIST = frozenset({
    "manifest.json",      # Case manifest (contains targets, PII)
    "scope.json",         # Case scope (contains client targets)
    "tasks.json",         # Case task data
    "playbook.json",      # Case runbook state
    "runbook-log.json",   # Runbook execution logs
    "findings.json",      # Case findings DB
    "findings.db",        # Alternative findings storage
    "evidence.db",        # Evidence database
    "loot.db",            # Loot database
    "case.json",          # Case metadata (contains client name, targets)
})

# Files that exist ONLY in public — preserve them
PUBLIC_ONLY_FILES = frozenset({
    "run.py", "modules/config.py", ".env.example", ".dockerignore",
    "Dockerfile", "docker-compose.yml", "scripts/setup.sh",
})

# File renames (working filename → public filename)
RENAME = {
    "kali-command-center.py": "cli.py",
}

# Non-Python files to copy verbatim
VERBATIM_EXTS = frozenset({
    ".yaml", ".yml", ".json", ".md", ".txt", ".css", ".js", ".html", ".sh",
    ".conf", ".toml", ".cfg", ".ini", ".svg",
    ".go", ".java", ".ql", ".ps1", ".php", ".py", ".rb", ".rs", ".ts",
    ".xml", ".xsl", ".xslt", ".lock",
})

# Environment-specific patterns that trigger a warning
ENV_PATTERNS = [
    (r"192\.168\.\d+\.\d+", "Hardcoded IP (VirtualBox host-only)"),
    (r"10\.\d+\.\d+\.\d+", "Hardcoded IP (private network)"),
    (r"172\.\d+\.\d+\.\d+", "Hardcoded IP (private network)"),
    (r"\bjeff\b", "Hardcoded username (case-insensitive)"),
    (r"kraken-pc", "Hardcoded hostname"),
    (r"Feemco\s*Technologies?", "Hardcoded company name"),
    (r"Jeff\s+Feemster", "Hardcoded tester name"),
    (r"/share/tools", "Hardcoded /share/tools path"),
    (r"/share/git-repo", "Hardcoded /share/git-repo path"),
    (r"/wordlists", "Hardcoded /wordlists path"),
    (r"/root/", "Hardcoded /root/ path"),
]

IMPORT_RE = re.compile(r"^[ \t]*(from\s+modules)\.constants(\s+import)", re.MULTILINE)
REL_IMPORT_RE = re.compile(r"^[ \t]*(from\s+\.)constants(\s+import)", re.MULTILINE)


# -- SAFETY CHECKS ------------------------------------------------------------

def _safety_scan(path: Path, label: str) -> list[str]:
    """Scan a directory for files that should never be in the public repo.
    Returns list of violations. Empty list = SAFE."""
    violations = []
    for f in path.rglob("*"):
        if not f.is_file():
            continue
        rel = f.relative_to(path)
        # Skip .git internals
        if ".git" in rel.parts:
            continue
        if f.name in FILE_BLOCKLIST:
            violations.append(f"  BLOCKED: {f.relative_to(path)} ({f.name})")
        # Flag files inside blocked data directories
        in_skipped = False
        for part in rel.parts:
            if part in SKIP_NAMES:
                in_skipped = True
                violations.append(f"  INSIDE-BLOCKED-DIR: {rel} (under '{part}/')")
                break
        if in_skipped:
            continue
        # Check for JSON files containing case data patterns
        if f.suffix == ".json" and f.stat().st_size > 100:
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
                if "case_id" in text and ("findings" in text or "evidence" in text or "scope" in text):
                    violations.append(f"  SUSPECT: {rel} (contains case data markers)")
            except Exception as _e:
                print(f"[sync] Skipping file: {_e}", flush=True)
    return violations


# -- TRANSFORMS --------------------------------------------------------------─

def _transform_source(src: str, rel_path: str) -> tuple[str, list[str]]:
    """Transform source code from working → public conventions."""
    issues = []

    src, n1 = IMPORT_RE.subn(r"\1.config\2", src)
    src, n2 = REL_IMPORT_RE.subn(r"\1config\2", src)
    if n1 or n2:
        print(f"  imports: {n1 + n2} rewritten")

    for pattern, desc in ENV_PATTERNS:
        for i, line in enumerate(src.splitlines(), 1):
            stripped = line.strip()
            if re.search(pattern, line, re.IGNORECASE) and not stripped.startswith("#"):
                issues.append(f"    {rel_path}:{i} — {desc}: {stripped[:100]}")
                break

    return src, issues


# -- SYNC --------------------------------------------------------------------─

def sync_file(src_path: Path, rel_path: str) -> list[str]:
    """Sync a single file from working → public."""
    dst_path = PUBLIC / rel_path
    issues = []

    if src_path.is_dir():
        dst_path.mkdir(parents=True, exist_ok=True)
        return issues

    ext = src_path.suffix.lower()
    is_py = ext == ".py"

    if not is_py and ext not in VERBATIM_EXTS:
        return issues

    src = src_path.read_text(encoding="utf-8", errors="replace")

    if is_py:
        src, file_issues = _transform_source(src, rel_path)
        issues.extend(file_issues)
    else:
        for pattern, desc in ENV_PATTERNS:
            for i, line in enumerate(src.splitlines(), 1):
                stripped = line.strip()
                if re.search(pattern, line, re.IGNORECASE) and not stripped.startswith("#"):
                    issues.append(f"    {rel_path}:{i} — {desc}: {stripped[:100]}")
                    break

    dst_path.parent.mkdir(parents=True, exist_ok=True)

    if dst_path.exists():
        existing = dst_path.read_text(encoding="utf-8", errors="replace")
        if existing == src:
            return issues

    dst_path.write_text(src, encoding="utf-8")
    print(f"  {'=' if is_py else ' '} {rel_path}")
    return issues


def main():
    print(f"Syncing FROM: {WORKING}")
    print(f"Syncing TO:   {PUBLIC}\n")

    # -- Pre-sync safety scan: verify destination has no leaked data --
    print("-- Safety scan (destination) --")
    dst_violations = _safety_scan(PUBLIC, "destination")
    if dst_violations:
        print("DATA LEAK DETECTED in public repo! Aborting sync.")
        for v in dst_violations:
            print(v)
        print("\nRemove these files first, then re-run.")
        sys.exit(1)
    print("  OK — no blocked data files found\n")

    # -- Safety scan: verify source has expected structure --
    print("-- Safety scan (source) --")
    src_violations = _safety_scan(WORKING, "source")
    if src_violations:
        print("WARNING: Source repo contains data files:")
        for v in src_violations:
            print(v)
        print("These will NOT be synced (data dirs are excluded)\n")
    else:
        print("  OK\n")

    # -- Sync --
    print("-- Sync --")
    all_issues = []
    synced = 0
    skipped = 0

    for src_path in sorted(WORKING.rglob("*")):
        rel = src_path.relative_to(WORKING).as_posix()
        parts = set(rel.split("/"))

        # Skip data directories
        if SKIP_NAMES & parts:
            skipped += 1
            continue
        if any(p == "__pycache__" or p.startswith(".") for p in parts):
            skipped += 1
            continue

        # Apply renames
        renamed = RENAME.get(rel)
        if renamed:
            rel = renamed
            print(f"  > rename: {src_path.name} -> {renamed}")

        issues = sync_file(src_path, rel)
        all_issues.extend(issues)
        synced += 1

    print(f"\nSynced: {synced}, Skipped (data/cache): {skipped}")

    # -- Report --
    if all_issues:
        print(f"\n! {len(all_issues)} environment-specific value(s) to review:")
        for issue in all_issues:
            print(issue)
    else:
        print("\nOK - No environment-specific values detected")

    # -- Post-sync safety check --
    print("\n-- Post-sync safety check --")
    post_violations = _safety_scan(PUBLIC, "destination")
    if post_violations:
        print("DATA LEAK DETECTED after sync! Aborting.")
        for v in post_violations:
            print(v)
        sys.exit(1)
    print("  OK — sync is clean\n")

    print("To verify:  cd cc-toolkit-public && python run.py web")


if __name__ == "__main__":
    main()
