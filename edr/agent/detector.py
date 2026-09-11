"""Detection engine: evaluates rules against osquery results.

Delegates per-row matching to edr.rules.schema.evaluate_condition and
check_rule_against_rows, which already implement all 11 detect ops.
The agent is responsible for running osquery queries, managing baselines
for new_in_baseline/changed ops, applying per-device overrides, and
collecting DetectionResults.
"""

from __future__ import annotations

import logging
import re
import sys
import time
from typing import Any, Dict, List, Optional

from edr.agent.baseline import BaselineStore
from edr.agent.osquery import OsqueryRunner
from edr.rules.schema import (
    DetectionResult as SchemaDetectionResult,
    DetectionRule as SchemaDetectionRule,
    DetectCondition,
    check_rule_against_rows,
    evaluate_condition,
    resolve_dot_path,
)

logger = logging.getLogger(__name__)

CURRENT_PLATFORM = "windows" if sys.platform == "win32" else "linux"


class Detector:
    """Evaluates detection rules against live osquery data."""

    def __init__(
        self,
        runner: OsqueryRunner,
        baseline: BaselineStore,
        rules: list[SchemaDetectionRule] | None = None,
        device_uuid: str = "",
    ):
        self._runner = runner
        self._baseline = baseline
        self._rules: list[SchemaDetectionRule] = rules or []
        self._device_uuid = device_uuid
        self._first_run = True
        self._query_cache: dict[str, list[dict]] = {}

    def set_rules(self, rules: list[SchemaDetectionRule]):
        self._rules = rules

    def mark_first_run_done(self):
        self._first_run = False

    @property
    def is_first_run(self) -> bool:
        return self._first_run

    def evaluate_all(self) -> list[dict]:
        """Evaluate all rules, return detection results as dicts."""
        self._query_cache.clear()
        results: list[dict] = []
        for rule in self._rules:
            if not rule.enabled:
                continue
            if rule.platform not in ("all", "", CURRENT_PLATFORM):
                continue
            if self._device_uuid and rule.override_for:
                override = rule.override_for.get(self._device_uuid)
                if override and override.enabled is False:
                    logger.debug("Rule %s disabled for device %s", rule.id, self._device_uuid)
                    continue
            rows = self._get_rows(rule)
            if not rows:
                continue
            if self._first_run:
                self._baseline.update(rule.id, rows)
                continue
            result = self._evaluate_rule(rule, rows)
            if result:
                results.append(result)
            self._baseline.update(rule.id, rows)
        return results

    def _get_rows(self, rule: SchemaDetectionRule) -> list[dict]:
        """Run osquery and cache results (avoids double-query per rule)."""
        query = rule.osquery.query
        if query in self._query_cache:
            return self._query_cache[query]
        rows = self._runner.run_query_safe(query)
        self._query_cache[query] = rows
        return rows

    def _evaluate_rule(self, rule: SchemaDetectionRule, rows: list[dict]) -> dict | None:
        """Evaluate a single rule against osquery rows."""
        condition = rule.detect
        op = condition.op

        # Handle baseline ops separately (need BaselineStore)
        if op == "new_in_baseline" and condition.field:
            new_vals = self._baseline.diff(rule.id, rows)
            matched = []
            for row in rows:
                field_val = str(resolve_dot_path(row, condition.field) or "")
                if condition.field in new_vals and field_val in new_vals[condition.field]:
                    matched.append(row)
            if not matched:
                return None
            return self._build_result(rule, matched, new_vals)

        if op == "changed" and condition.field:
            baseline_data = self._baseline.load(rule.id)
            matched = []
            for row in rows:
                field_val = str(resolve_dot_path(row, condition.field) or "")
                if condition.field in baseline_data:
                    if field_val not in baseline_data[condition.field]:
                        matched.append(row)
                else:
                    matched.append(row)
            if not matched:
                return None
            return self._build_result(rule, matched, {})

        # All other ops: delegate to the rules schema's evaluate_condition
        # This handles: eq, neq, gt, lt, gte, lte, contains, not_contains, regex
        if condition.threshold is not None and condition.group_by is not None:
            matched = check_rule_against_rows(rows, condition)
        else:
            matched = [row for row in rows if evaluate_condition(row, condition)]

        if not matched:
            return None

        # Apply per-device threshold override
        effective_threshold = condition.threshold
        if self._device_uuid and rule.override_for:
            override = rule.override_for.get(self._device_uuid)
            if override and override.threshold is not None:
                effective_threshold = override.threshold

        return self._build_result(rule, matched, {})

    def _build_result(
        self,
        rule: SchemaDetectionRule,
        matched: list[dict],
        new_values: dict[str, set],
    ) -> dict:
        """Build a DetectionResult dict from matched rows."""
        actions = [a.name for a in rule.response] if rule.response else []
        return {
            "rule_id": rule.id,
            "rule_name": rule.name,
            "severity": rule.severity,
            "platform": rule.platform,
            "timestamp": time.time(),
            "device_uuid": self._device_uuid,
            "matched_rows": matched[:100],
            "new_values": {k: list(v) for k, v in new_values.items()},
            "response_actions_triggered": actions,
        }
