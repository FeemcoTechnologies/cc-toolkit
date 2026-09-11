"""Server-side detection correlation engine."""

import json
import logging
from datetime import datetime, timezone, timedelta

from edr.server import models

logger = logging.getLogger("edr.correlation")

# Minimum distinct devices to trigger a "coordinated activity" alert
COORDINATION_THRESHOLD = 3
# Time window for coordination detection (minutes)
COORDINATION_WINDOW_MINUTES = 30
# Maximum age before flagging a device offline (hours)
OFFLINE_THRESHOLD_HOURS = 24


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _iso_minus_hours(hours: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


def _iso_minus_minutes(minutes: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()


def run_correlation(db_path: str) -> list[dict]:
    results: list[dict] = []

    results.extend(_check_coordinated_alerts(db_path))
    results.extend(_check_offline_devices(db_path))
    results.extend(_check_baseline_drift(db_path))

    for r in results:
        models.insert_correlation_alert(
            db_path,
            rule_name=r["rule_name"],
            description=r["description"],
            severity=r.get("severity", "info"),
            affected_devices=r.get("affected_devices", []),
        )

    if results:
        logger.info("Correlation engine produced %d alert(s)", len(results))

    return results


def _check_coordinated_alerts(db_path: str) -> list[dict]:
    window_start = _iso_minus_minutes(COORDINATION_WINDOW_MINUTES)
    alerts = models.get_alerts(
        db_path,
        since=window_start,
        limit=10000,
    )

    rule_device_map: dict[str, set[str]] = {}
    for alert in alerts:
        rule_id = alert.get("rule_id") or alert.get("rule_name", "unknown")
        device = alert["device_uuid"]
        rule_device_map.setdefault(rule_id, set()).add(device)

    results = []
    for rule_id, devices in rule_device_map.items():
        if len(devices) >= COORDINATION_THRESHOLD:
            results.append({
                "rule_name": "coordinated_activity",
                "description": (
                    f"Rule '{rule_id}' triggered on {len(devices)} devices "
                    f"within {COORDINATION_WINDOW_MINUTES} minutes"
                ),
                "severity": "high",
                "affected_devices": list(devices),
            })
    return results


def _check_offline_devices(db_path: str) -> list[dict]:
    cutoff = _iso_minus_hours(OFFLINE_THRESHOLD_HOURS)
    devices = models.list_devices(db_path, status="active")
    results = []
    for device in devices:
        last_seen = device.get("last_seen", "")
        if last_seen and last_seen < cutoff:
            results.append({
                "rule_name": "device_offline",
                "description": (
                    f"Device {device['device_uuid']} ({device.get('hostname', 'unknown')}) "
                    f"has not checked in since {last_seen}"
                ),
                "severity": "medium",
                "affected_devices": [device["device_uuid"]],
            })
            models.set_device_status(db_path, device["device_uuid"], "disabled")
    return results


def _check_baseline_drift(db_path: str) -> list[dict]:
    alerts = models.get_alerts(
        db_path,
        since=_iso_minus_hours(1),
        limit=5000,
    )

    table_devices: dict[str, set[str]] = {}
    for alert in alerts:
        matched = alert.get("matched_rows", "[]")
        try:
            rows = json.loads(matched) if isinstance(matched, str) else matched
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(rows, list):
            continue
        for row in rows:
            if isinstance(row, dict) and "table_name" in row:
                table_devices.setdefault(row["table_name"], set()).add(
                    alert["device_uuid"]
                )

    results = []
    for table_name, devices in table_devices.items():
        if len(devices) >= COORDINATION_THRESHOLD:
            results.append({
                "rule_name": "baseline_drift",
                "description": (
                    f"Baseline change detected on table '{table_name}' "
                    f"across {len(devices)} devices within the correlation window"
                ),
                "severity": "medium",
                "affected_devices": list(devices),
            })
    return results
