"""
Pre-commit safety checker for cc-toolkit-public.

Scans staged files and the working directory for:
  - Case data (manifest.json, scope.json, findings.json, etc.)
  - Hardcoded IPs, hostnames, usernames
  - Runtime database files
  - Any file inside a data directory

Exit code: 0 = safe, 1 = BLOCKED
"""

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent

# Files that are ALWAYS blocked — case data, credentials, runtime state
BLOCKED_FILENAMES = frozenset({
    "manifest.json",      # Case summary with targets, client names
    "scope.json",         # In-scope / out-of-scope targets
    "tasks.json",         # Case task checklist
    "playbook.json",      # Case runbook state (may contain targets)
    "runbook-log.json",   # Runbook execution results
    "findings.json",      # All case findings
    "findings.db",        # Findings database
    "asset_db.json",      # Asset inventory
    "arsenal-rules.json",
    "dashboard_layout.json",
    "env-profiles.json",
    ".vault_key",
})

BLOCKED_DIRS = frozenset({
    "cases", "data", "nmap_scans", "screenshots",
    "logs", "sessions", "wifi_sessions", "dns_monitors", "wordlists",
})

# Suspicious patterns in file contents
SUSPICIOUS_PATTERNS = [
    (r"\bPT-\d{4}-\d{3}\b", "Case ID pattern (PT-YYYY-NNN)"),
    (r"192\.168\.\d+\.\d+", "Private IP"),
    (r"10\.\d+\.\d+\.\d+", "Private IP"),
    (r"172\.\d+\.\d+\.\d+", "Private IP"),
    (r"(?i)\bjeff\b", "Hardcoded username"),
    (r"(?i)kraken-pc", "Hardcoded hostname"),
    (r"(?i)feemco", "Hardcoded company name"),
]


def check_file(filepath: Path, is_staged: bool = False) -> list[str]:
    """Check a single file for data leakage. Returns list of violations."""
    violations = []
    rel = filepath.relative_to(REPO).as_posix()

    # Check filename blocklist
    if filepath.name in BLOCKED_FILENAMES:
        violations.append(f"BLOCKED: {rel} — blocked filename ({filepath.name})")

    # Check parent directory blocklist
    for part in rel.split("/"):
        if part in BLOCKED_DIRS:
            violations.append(f"BLOCKED: {rel} — inside blocked directory ({part})")
            break

    if not filepath.is_file():
        return violations

    # NOTE: Path(".env").suffix == "" (dotfiles have no extension), so the
    # literal filename must be matched explicitly — otherwise .env is never
    # content-scanned even though it's in the extension tuple.
    if filepath.suffix in (".py", ".yaml", ".yml", ".json", ".html", ".js", ".md", ".txt", ".sh", ".conf", ".env", ".toml", ".cfg", ".ini") or filepath.name in (".env", ".env.example"):
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return violations

        for pattern, desc in SUSPICIOUS_PATTERNS:
            for i, line in enumerate(content.splitlines(), 1):
                stripped = line.strip()
                if re.search(pattern, line) and not stripped.startswith("#") and not stripped.startswith("//"):
                    violations.append(f"SUSPICIOUS: {rel}:{i} — {desc}: {stripped[:100]}")
                    break

    return violations


def check_staged() -> list[str]:
    """Check files staged for commit."""
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True, text=True, cwd=REPO
    )
    files = [f.strip() for f in result.stdout.splitlines() if f.strip()]
    all_violations = []
    for f in files:
        filepath = REPO / f
        violations = check_file(filepath, is_staged=True)
        all_violations.extend(violations)
    return all_violations


def check_working_dir() -> list[str]:
    """Check entire working directory (not just staged)."""
    all_violations = []
    for filepath in sorted(REPO.rglob("*")):
        if not filepath.is_file():
            continue
        # Skip .git directory
        if ".git" in filepath.parts:
            continue
        # Skip __pycache__
        if "__pycache__" in filepath.parts:
            continue
        violations = check_file(filepath)
        all_violations.extend(violations)
    return all_violations


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "staged"

    if mode == "staged":
        violations = check_staged()
    elif mode == "full":
        violations = check_working_dir()
    else:
        print(f"Usage: {sys.argv[0]} [staged|full]")
        sys.exit(1)

    if violations:
        print(f"DATA SAFETY CHECK FAILED ({len(violations)} violation(s)):\n")
        for v in violations:
            print(f"  {v}")
        print("\nRemove or .gitignore these files before committing.")
        sys.exit(1)

    print("OK — no data safety violations detected")
    sys.exit(0)


if __name__ == "__main__":
    main()
