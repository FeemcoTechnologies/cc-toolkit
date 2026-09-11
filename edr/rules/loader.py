"""
EDR Detection Rule Loader

Loads YAML detection rule files from a directory, validates them against
the Pydantic schema, and returns a list of DetectionRule objects.

Bad YAML files are logged and skipped -- they never crash the loader.

Usage:
    from edr.rules.loader import load_rules
    rules = load_rules("/path/to/rules/")
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import List, Optional

import yaml

from edr.rules.schema import DetectionRule

logger = logging.getLogger(__name__)

# Default rule file extensions
_YAML_EXTENSIONS = {".yaml", ".yml"}


def load_rules(
    directory: str | Path,
    *,
    enabled_only: bool = False,
    platform_filter: Optional[str] = None,
) -> List[DetectionRule]:
    """Load and validate all detection rules from a directory.

    Scans the directory for .yaml/.yml files, parses each, validates
    against the DetectionRule schema, and returns the valid rules.

    Args:
        directory: Path to the directory containing YAML rule files.
        enabled_only: If True, only return rules with enabled=True.
        platform_filter: If set, only return rules matching this platform
                        ("linux", "windows", or "all").

    Returns:
        List of validated DetectionRule objects. Invalid files are logged
        and skipped.
    """
    directory = Path(directory)
    if not directory.is_dir():
        logger.error("Rules directory does not exist: %s", directory)
        return []

    rules: List[DetectionRule] = []
    yaml_files = sorted(
        p for p in directory.iterdir()
        if p.is_file() and p.suffix.lower() in _YAML_EXTENSIONS
    )

    if not yaml_files:
        logger.warning("No YAML rule files found in %s", directory)
        return []

    for filepath in yaml_files:
        file_rules = _load_single_file(filepath)
        rules.extend(file_rules)

    # Apply filters
    if enabled_only:
        rules = [r for r in rules if r.enabled]

    if platform_filter is not None:
        rules = [
            r for r in rules
            if r.platform == platform_filter or r.platform == "all"
        ]

    logger.info(
        "Loaded %d rules from %d files in %s",
        len(rules),
        len(yaml_files),
        directory,
    )
    return rules


def load_rules_from_file(filepath: str | Path) -> List[DetectionRule]:
    """Load rules from a single YAML file.

    The file may contain a single rule dict or a list of rule dicts.

    Args:
        filepath: Path to a YAML file containing one or more rules.

    Returns:
        List of validated DetectionRule objects (empty on error).
    """
    filepath = Path(filepath)
    if not filepath.is_file():
        logger.error("Rule file does not exist: %s", filepath)
        return []
    return _load_single_file(filepath)


def merge_rules(
    base_rules: List[DetectionRule],
    override_rules: List[DetectionRule],
) -> List[DetectionRule]:
    """Merge base rules with override rules.

    Rules with the same ID are merged: override fields take precedence.
    New rules from the override set are appended.

    Args:
        base_rules: The base rule set (e.g. built-in defaults).
        override_rules: Override rules (e.g. device-specific customizations).

    Returns:
        Merged list of DetectionRule objects.
    """
    base_by_id = {r.id: r for r in base_rules}
    override_by_id = {r.id: r for r in override_rules}

    merged: List[DetectionRule] = []

    for rule_id, override in override_by_id.items():
        if rule_id in base_by_id:
            # Merge: override takes precedence for non-default fields
            base = base_by_id[rule_id]
            merged_rule = _merge_single_rule(base, override)
            merged.append(merged_rule)
        else:
            # New rule from override
            merged.append(override)

    # Add base rules that were not overridden
    for rule_id, base in base_by_id.items():
        if rule_id not in override_by_id:
            merged.append(base)

    return merged


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_single_file(filepath: Path) -> List[DetectionRule]:
    """Parse a single YAML file into validated DetectionRule objects."""
    rules: List[DetectionRule] = []

    try:
        raw_text = filepath.read_text(encoding="utf-8")
    except OSError as exc:
        logger.error("Failed to read %s: %s", filepath, exc)
        return []

    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        logger.error("Invalid YAML in %s: %s", filepath, exc)
        return []

    if data is None:
        logger.warning("Empty YAML file: %s", filepath)
        return []

    # Support both single rule and list of rules
    if isinstance(data, dict):
        data = [data]
    elif not isinstance(data, list):
        logger.error(
            "Unexpected YAML structure in %s: expected dict or list, got %s",
            filepath,
            type(data).__name__,
        )
        return []

    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            logger.error(
                "Skipping non-dict entry at index %d in %s",
                idx,
                filepath,
            )
            continue

        try:
            rule = DetectionRule(**item)
            rules.append(rule)
        except Exception as exc:
            logger.error(
                "Validation error in %s (entry %d): %s",
                filepath,
                idx,
                exc,
            )
            continue

    return rules


def _merge_single_rule(base: DetectionRule, override: DetectionRule) -> DetectionRule:
    """Merge an override rule into a base rule.

    Only fields explicitly set in the override take precedence (uses
    model_dump(exclude_unset=True) so Pydantic defaults don't clobber
    base rule values). The base rule's ID is always preserved.
    """
    base_data = base.model_dump()
    override_data = override.model_dump(exclude_unset=True)

    # Override only explicitly-set fields
    for key, value in override_data.items():
        if key == "id":
            continue
        base_data[key] = value

    # Preserve base ID
    base_data["id"] = base.id

    return DetectionRule(**base_data)
