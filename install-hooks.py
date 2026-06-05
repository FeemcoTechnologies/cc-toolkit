#!/usr/bin/env python3
"""Install the data-safety pre-commit hook into the public repo's .git/hooks/."""

from pathlib import Path

REPO = Path(__file__).resolve().parent
HOOK_SRC = REPO / ".git" / "hooks" / "pre-commit"
HOOK_SRC.parent.mkdir(parents=True, exist_ok=True)

hook_script = r"""#!/bin/sh
# Pre-commit hook: block commits containing case data or PII
echo "── Data Safety Check ──"
python3 "$(git rev-parse --show-toplevel)/check-data-safety.py" staged
rc=$?
if [ $rc -ne 0 ]; then
    echo "COMMIT BLOCKED — remove data files or add to .gitignore"
    exit 1
fi
echo "  OK"
"""

HOOK_SRC.write_text(hook_script)
HOOK_SRC.chmod(0o755)
print(f"Pre-commit hook installed: {HOOK_SRC}")
