"""Baseline management for integrity monitoring."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Dict, List, Union

logger = logging.getLogger(__name__)

MAX_ENTRIES_PER_FIELD = 10000


class BaselineStore:
    """Stores and compares baselines for osquery tables.

    Internal cache uses lists (not sets) to preserve insertion order,
    which is required for deterministic FIFO capping in save().
    """

    def __init__(self, baseline_dir: str | Path, max_entries: int = MAX_ENTRIES_PER_FIELD):
        self._dir = Path(baseline_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._max_entries = max_entries
        self._cache: dict[str, dict[str, list[str]]] = {}

    def _path(self, table_name: str) -> Path:
        safe = table_name.replace("/", "_").replace("\\", "_")
        return self._dir / f"baseline_{safe}.json"

    def load(self, table_name: str) -> dict[str, list[str]]:
        """Load baseline for a table, return {field: [values]} (ordered)."""
        if table_name in self._cache:
            return {k: list(v) for k, v in self._cache[table_name].items()}
        path = self._path(table_name)
        if not path.exists():
            self._cache[table_name] = {}
            return {}
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            data: dict[str, list[str]] = {}
            for field, values in raw.items():
                if isinstance(values, list):
                    data[field] = values[-self._max_entries:]
                else:
                    data[field] = []
            self._cache[table_name] = data
            return {k: list(v) for k, v in data.items()}
        except (json.JSONDecodeError, KeyError) as exc:
            logger.error("Failed to load baseline %s: %s", table_name, exc)
            self._cache[table_name] = {}
            return {}

    def save(self, table_name: str, data: dict[str, list[str]]):
        """Persist baseline to disk. Deduplicates while preserving insertion order."""
        serialized: dict[str, list[str]] = {}
        for field, values in data.items():
            seen: dict[str, bool] = {}
            ordered: list[str] = []
            for v in values:
                if v not in seen:
                    seen[v] = True
                    ordered.append(v)
            serialized[field] = ordered[-self._max_entries:]
        path = self._path(table_name)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(serialized, indent=2), encoding="utf-8")
        tmp.replace(path)
        self._cache[table_name] = data

    def update(self, table_name: str, osquery_rows: list[dict]) -> dict[str, list[str]]:
        """Add current row values to baseline and persist."""
        baseline = self.load(table_name)
        for row in osquery_rows:
            for field, value in row.items():
                val_str = str(value)
                if field not in baseline:
                    baseline[field] = []
                if val_str not in baseline[field]:
                    baseline[field].append(val_str)
        self.save(table_name, baseline)
        return baseline

    def diff(self, table_name: str, osquery_rows: list[dict]) -> dict[str, list[str]]:
        """Compare rows against baseline, return new values not in baseline."""
        baseline = self.load(table_name)
        new_values: dict[str, list[str]] = {}
        for row in osquery_rows:
            for field, value in row.items():
                val_str = str(value)
                if field not in baseline:
                    new_values.setdefault(field, []).append(val_str)
                    continue
                if val_str not in baseline[field]:
                    new_values.setdefault(field, []).append(val_str)
        return new_values

    def is_new(self, table_name: str, field: str, value: str) -> bool:
        """Check if a specific value is new (not in baseline)."""
        baseline = self.load(table_name)
        if field not in baseline:
            return True
        return str(value) not in baseline[field]

    def snapshot_hash(self, table_name: str) -> str:
        """Compute deterministic hash of the entire baseline."""
        baseline = self.load(table_name)
        canonical = json.dumps(
            {k: sorted(v) for k, v in sorted(baseline.items())},
            sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def populate_initial(self, table_name: str, osquery_rows: list[dict]):
        """Populate baseline from current state (first run, no alerts)."""
        self.update(table_name, osquery_rows)
        logger.info(
            "Populated baseline for %s with %d rows",
            table_name, len(osquery_rows),
        )

    def field_count(self, table_name: str) -> int:
        """Count fields tracked in a table's baseline."""
        baseline = self.load(table_name)
        return len(baseline)

    def total_values(self, table_name: str) -> int:
        """Count total tracked values in a table's baseline."""
        baseline = self.load(table_name)
        return sum(len(v) for v in baseline.values())
