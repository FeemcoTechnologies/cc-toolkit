"""
EDR Detection Rules Package

Exposes the core schema models and the rule loader for convenient importing.
"""

from edr.rules.loader import load_rules, load_rules_from_file, merge_rules
from edr.rules.schema import (
    DetectCondition,
    DetectionResult,
    DetectionRule,
    DeviceOverride,
    OsqueryQuery,
    ResponseAction,
)

__all__ = [
    "DetectCondition",
    "DetectionResult",
    "DetectionRule",
    "DeviceOverride",
    "OsqueryQuery",
    "ResponseAction",
    "load_rules",
    "load_rules_from_file",
    "merge_rules",
]
