"""Osquery wrapper for running queries via subprocess."""

import json
import logging
import subprocess

logger = logging.getLogger(__name__)

QUERY_TIMEOUT = 30
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class OsqueryRunner:
    """Runs osquery queries and parses JSON output."""

    def __init__(self, osquery_path: str = "osqueryi"):
        self._path = osquery_path
        self._available = self._check_available()

    def _check_available(self) -> bool:
        try:
            result = subprocess.run(
                [self._path, "--version"],
                capture_output=True, text=True, timeout=5,
                creationflags=CREATE_NO_WINDOW,
            )
            if result.returncode == 0:
                logger.info("osquery available: %s", result.stdout.strip())
                return True
            logger.warning("osquery --version returned %d", result.returncode)
        except FileNotFoundError:
            logger.warning("osquery not found at '%s'", self._path)
        except subprocess.TimeoutExpired:
            logger.warning("osquery --version timed out")
        except OSError as exc:
            logger.warning("Cannot execute osquery: %s", exc)
        return False

    @property
    def available(self) -> bool:
        return self._available

    def run_query(self, sql: str) -> list[dict]:
        """Run SQL via osqueryi --json, return list of row dicts."""
        if not self._available:
            logger.warning("osquery unavailable, skipping query")
            return []
        try:
            result = subprocess.run(
                [self._path, "--json", sql],
                capture_output=True, text=True, timeout=QUERY_TIMEOUT,
                creationflags=CREATE_NO_WINDOW,
            )
            if result.returncode != 0:
                logger.error("osquery error (rc=%d): %s", result.returncode, result.stderr.strip())
                return []
            output = result.stdout.strip()
            if not output:
                return []
            data = json.loads(output)
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                rows = data.get("data", [])
                return rows if isinstance(rows, list) else []
            return []
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse osquery JSON: %s", exc)
            return []
        except subprocess.TimeoutExpired:
            logger.error("osquery query timed out after %ds", QUERY_TIMEOUT)
            return []
        except OSError as exc:
            logger.error("Failed to execute osquery: %s", exc)
            return []

    def run_query_safe(self, sql: str) -> list[dict]:
        """Run query with full exception safety."""
        try:
            return self.run_query(sql)
        except Exception as exc:
            logger.error("Unexpected error in osquery: %s", exc)
            return []

    def get_installed_packs(self) -> dict[str, str]:
        """Return {pack_name: md5_hash} of installed osquery packs."""
        packs = self.run_query_safe("SELECT name, md5 FROM osquery_packs;")
        result = {}
        for row in packs:
            name = row.get("name", "")
            md5 = row.get("md5", "")
            if name:
                result[name] = md5
        return result
