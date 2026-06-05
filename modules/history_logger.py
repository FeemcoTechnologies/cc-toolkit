import logging
"""Command audit logger — records every CLI invocation."""

import datetime
import json
import os
import sys
from pathlib import Path
from typing import Optional

from .config import CONFIG_DIR
logger = logging.getLogger(__name__)


class HistoryLogger:
    """Append-only audit log of all command center invocations."""

    def __init__(self, log_dir: Optional[Path] = None):
        self.log_dir = Path(log_dir or CONFIG_DIR)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._path = self.log_dir / "history.jsonl"

    def log(self, command: str, args: Optional[dict] = None,
            case_id: str = "", target: str = "",
            rc: int = 0):
        """Append a single invocation record."""
        entry = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "command": command,
            "args": args or {},
            "case_id": case_id,
            "target": target,
            "rc": rc,
            "pid": os.getpid(),
        }
        with self._path.open("a") as f:
            f.write(json.dumps(entry) + "\n")

    def recent(self, limit: int = 25) -> list:
        """Return the most recent N entries."""
        if not self._path.exists():
            return []
        lines = self._path.read_text().strip().splitlines()
        results = []
        for line in lines[-limit:]:
            try:
                results.append(json.loads(line))
            except Exception:

                logger.debug("Exception in history_logger.py", exc_info=True)
        return results

    def search(self, query: str, limit: int = 50) -> list:
        """Search history for entries containing query."""
        if not self._path.exists():
            return []
        results = []
        with self._path.open() as f:
            for line in f:
                if query.lower() in line.lower():
                    try:
                        results.append(json.loads(line))
                    except Exception:

                        logger.debug("Exception in history_logger.py", exc_info=True)
                    if len(results) >= limit:
                        break
        return results

    def summary(self) -> dict:
        if not self._path.exists():
            return {"total": 0, "unique_commands": 0}
        commands = set()
        total = 0
        with self._path.open() as f:
            for line in f:
                total += 1
                try:
                    entry = json.loads(line)
                    commands.add(entry.get("command", "?"))
                except Exception:

                    logger.debug("Exception in history_logger.py", exc_info=True)
        return {"total": total, "unique_commands": len(commands)}