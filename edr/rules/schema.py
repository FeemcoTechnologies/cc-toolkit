"""
EDR Detection Rule Schema

Pydantic models for YAML-based detection rules. These models validate
rule files at load time, ensuring every rule conforms to the schema
before the agent attempts evaluation.

Usage:
    from edr.rules.schema import DetectionRule, DetectionResult, ResponseAction
    rule = DetectionRule(**yaml.safe_load(open("rule.yaml")))

The detect field supports these operations:
    eq, neq             -- exact match
    gt, lt, gte, lte    -- numeric comparison
    contains, not_contains -- substring match
    regex               -- regex match
    new_in_baseline     -- value not in baseline set
    changed             -- value differs from baseline

For threshold + group_by: count rows per group, alert if count > threshold.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enums / Literals
# ---------------------------------------------------------------------------

SeverityLevel = Literal["info", "low", "medium", "high", "critical"]
PlatformType = Literal["linux", "windows", "all"]
DetectOp = Literal[
    "eq",
    "neq",
    "gt",
    "lt",
    "gte",
    "lte",
    "contains",
    "not_contains",
    "regex",
    "new_in_baseline",
    "changed",
]
ResponseType = Literal[
    "log",
    "alert",
    "isolate",
    "kill_process",
    "block_ip",
    "quarantine_file",
    "notify",
]


# ---------------------------------------------------------------------------
# Nested Models
# ---------------------------------------------------------------------------


class DetectCondition(BaseModel):
    """A single detection condition applied to osquery result rows.

    Attributes:
        field: Dot-path into the row dict (e.g. "listening.port").
        op: Comparison operator.
        value: Primary value for the comparison (used by gt/lt/eq/neq/contains/regex).
        threshold: Optional; alert if more than N rows match after filtering.
        group_by: Optional; group rows by this field before threshold check.
    """

    field: str = Field(..., min_length=1, description="Dot-path into the osquery row dict")
    op: DetectOp = Field(..., description="Comparison operator")
    value: Any = Field(default=None, description="Comparison value (used by most ops)")
    threshold: Optional[int] = Field(default=None, ge=0, description="Alert if matched row count exceeds this")
    group_by: Optional[str] = Field(default=None, description="Group rows by this field before threshold check")

    @field_validator("op")
    @classmethod
    def validate_op(cls, v: str) -> str:
        valid_ops = {
            "eq", "neq", "gt", "lt", "gte", "lte",
            "contains", "not_contains", "regex",
            "new_in_baseline", "changed",
        }
        if v not in valid_ops:
            raise ValueError(f"Invalid operator '{v}'. Must be one of: {sorted(valid_ops)}")
        return v

    @model_validator(mode="after")
    def validate_regex_value(self) -> "DetectCondition":
        """If op is regex, validate that value is a compilable regex."""
        if self.op == "regex" and self.value is not None:
            try:
                re.compile(str(self.value))
            except re.error as exc:
                raise ValueError(
                    f"Invalid regex pattern in value: {exc}"
                ) from exc
        return self


class ResponseAction(BaseModel):
    """A response action triggered when a rule matches.

    Attributes:
        name: Human-readable name for this action (used in alert records).
        type: Action type -- log, alert, isolate, kill_process, block_ip,
              quarantine_file, or notify.
        params: Arbitrary parameters for the action (e.g. process_name, port).
    """

    name: str = Field(..., min_length=1, description="Human-readable action name")
    type: ResponseType = Field(..., description="Action type")
    params: Dict[str, Any] = Field(default_factory=dict, description="Action-specific parameters")


class OsqueryQuery(BaseModel):
    """Defines the osquery query to run for this rule.

    Attributes:
        query: The SQL query string.
        interval: Optional override for how often to run (seconds). If omitted,
                  the agent uses its default schedule interval.
        differential: If true, the agent tracks added/removed rows for efficient
                      change detection.
    """

    query: str = Field(..., min_length=1, description="Osquery SQL query")
    interval: Optional[int] = Field(default=None, ge=30, description="Query interval in seconds (min 30)")
    differential: bool = Field(default=False, description="Use differential results for change detection")


class DeviceOverride(BaseModel):
    """Per-device overrides for a detection rule.

    Attributes:
        enabled: Override the enabled flag for this device.
        threshold: Override the detection threshold.
        params: Override arbitrary parameters.
    """

    enabled: Optional[bool] = Field(default=None, description="Override enabled flag")
    threshold: Optional[int] = Field(default=None, ge=0, description="Override threshold value")
    params: Optional[Dict[str, Any]] = Field(default=None, description="Override params")


# ---------------------------------------------------------------------------
# Top-Level Rule Model
# ---------------------------------------------------------------------------


class DetectionRule(BaseModel):
    """A complete detection rule definition.

    This is the primary model for YAML rule files. Each rule specifies:
    - Identity and metadata (id, name, severity, platform, tags)
    - What to query (osquery block)
    - How to detect (detect block)
    - What to do on match (response block)
    - Per-device overrides (optional)

    Attributes:
        id: Unique rule identifier (e.g. "EDR-RULE-001").
        name: Human-readable rule name.
        description: What this rule detects and why it matters.
        severity: Detection severity level.
        platform: Target platform(s).
        tags: Categorization tags for filtering and grouping.
        osquery: The osquery query configuration.
        detect: Detection logic describing how to match result rows.
        response: Response actions triggered on match.
        enabled: Whether this rule is active.
        override_for: Per-device overrides keyed by device UUID.
    """

    id: str = Field(..., min_length=1, description="Unique rule identifier")
    name: str = Field(..., min_length=1, description="Human-readable rule name")
    description: str = Field(..., min_length=1, description="What this rule detects")
    severity: SeverityLevel = Field(..., description="Detection severity")
    platform: PlatformType = Field(default="all", description="Target platform")
    tags: List[str] = Field(default_factory=list, description="Categorization tags")
    osquery: OsqueryQuery = Field(..., description="Osquery query configuration")
    detect: DetectCondition = Field(..., description="Detection logic")
    response: List[ResponseAction] = Field(default_factory=list, description="Response actions on match")
    enabled: bool = Field(default=True, description="Whether rule is active")
    override_for: Optional[Dict[str, DeviceOverride]] = Field(
        default=None,
        description="Per-device overrides keyed by device UUID",
    )

    @field_validator("id")
    @classmethod
    def validate_id_format(cls, v: str) -> str:
        if not re.match(r"^[A-Za-z][A-Za-z0-9_-]*$", v):
            raise ValueError(
                f"Rule ID '{v}' must start with a letter and contain only "
                "letters, digits, hyphens, and underscores."
            )
        return v

    @field_validator("tags", mode="before")
    @classmethod
    def normalize_tags(cls, v: Any) -> List[str]:
        if isinstance(v, str):
            return [t.strip() for t in v.split(",") if t.strip()]
        return v


# ---------------------------------------------------------------------------
# Detection Result Model
# ---------------------------------------------------------------------------


class DetectionResult(BaseModel):
    """The output of evaluating a detection rule against osquery results.

    Generated by the agent after each rule evaluation cycle. Contains the
    matched data and which response actions were triggered.

    Attributes:
        rule_id: The rule that matched.
        rule_name: Human-readable rule name.
        severity: Severity of the detection.
        platform: Platform where the detection occurred.
        timestamp: UTC timestamp of the detection.
        device_uuid: UUID of the device where the match occurred.
        matched_rows: The osquery rows that triggered the rule.
        response_actions_triggered: Names of response actions that were executed.
    """

    rule_id: str = Field(..., description="Rule that matched")
    rule_name: str = Field(..., description="Human-readable rule name")
    severity: SeverityLevel = Field(..., description="Detection severity")
    platform: PlatformType = Field(..., description="Platform where detection occurred")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="UTC detection timestamp")
    device_uuid: str = Field(..., description="Device UUID")
    matched_rows: List[Dict[str, Any]] = Field(default_factory=list, description="Matched osquery rows")
    response_actions_triggered: List[str] = Field(default_factory=list, description="Actions executed")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def resolve_dot_path(row: Dict[str, Any], dot_path: str) -> Any:
    """Resolve a dot-separated path into a nested dict.

    Example:
        resolve_dot_path({"listening": {"port": 443}}, "listening.port") => 443

    Returns None if any segment is missing.
    """
    parts = dot_path.split(".")
    current: Any = row
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def evaluate_condition(row: Dict[str, Any], condition: DetectCondition) -> bool:
    """Evaluate a single DetectCondition against one osquery result row.

    Returns True if the row matches the condition.
    """
    actual = resolve_dot_path(row, condition.field)
    if actual is None:
        return False

    op = condition.op
    expected = condition.value

    # Numeric comparisons
    if op in ("gt", "lt", "gte", "lte"):
        try:
            actual_num = float(actual)
            expected_num = float(expected)
        except (TypeError, ValueError):
            return False
        if op == "gt":
            return actual_num > expected_num
        if op == "lt":
            return actual_num < expected_num
        if op == "gte":
            return actual_num >= expected_num
        if op == "lte":
            return actual_num <= expected_num

    # Equality
    if op == "eq":
        return str(actual) == str(expected)
    if op == "neq":
        return str(actual) != str(expected)

    # Substring
    if op == "contains":
        return str(expected) in str(actual)
    if op == "not_contains":
        return str(expected) not in str(actual)

    # Regex
    if op == "regex":
        try:
            return bool(re.search(str(expected), str(actual)))
        except re.error:
            return False

    # Baseline ops are handled by the agent's baseline manager, not here.
    # These return True to signal "needs baseline check".
    if op in ("new_in_baseline", "changed"):
        return True

    return False


def check_rule_against_rows(
    rows: List[Dict[str, Any]],
    condition: DetectCondition,
) -> List[Dict[str, Any]]:
    """Filter osquery rows that match a DetectCondition.

    If condition.threshold is set, applies group_by + threshold logic.
    Otherwise returns all rows matching the condition.
    """
    if condition.threshold is not None and condition.group_by is not None:
        # Group-by + threshold: count per group, return groups exceeding threshold
        from collections import Counter

        groups: Counter[str] = Counter()
        for row in rows:
            group_val = str(resolve_dot_path(row, condition.group_by) or "unknown")
            if evaluate_condition(row, condition):
                groups[group_val] += 1

        # Return the original rows for groups that exceed threshold
        triggered_groups = {g for g, c in groups.items() if c > condition.threshold}
        return [
            row for row in rows
            if str(resolve_dot_path(row, condition.group_by) or "unknown") in triggered_groups
        ]

    # Simple row-level matching
    return [row for row in rows if evaluate_condition(row, condition)]
