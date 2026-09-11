"""MCP tool functions for the EDR server REST API.

Each function is a standalone tool that can be registered with a FastMCP server.
All functions use stdlib (urllib.request, json) -- no third-party dependencies.

Server URL and admin API key are resolved from environment variables:
  EDR_SERVER_URL    (default: http://127.0.0.1:8900)
  EDR_ADMIN_API_KEY (fallback: read from ~/.config/kali-command-center/config.json)
"""

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Optional

_DEFAULT_SERVER = "http://127.0.0.1:8900"


def _resolve_server_url() -> str:
    return os.environ.get("EDR_SERVER_URL", _DEFAULT_SERVER).rstrip("/")


def _resolve_api_key() -> str:
    key = os.environ.get("EDR_ADMIN_API_KEY", "")
    if key:
        return key
    config_path = Path.home() / ".config" / "kali-command-center" / "config.json"
    try:
        cfg = json.loads(config_path.read_text(encoding="utf-8"))
        return cfg.get("admin_api_key", "")
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        return ""


def _api_get(path: str, params: Optional[dict] = None) -> str:
    """GET request to the EDR server. Returns response body string."""
    base = _resolve_server_url()
    url = f"{base}{path}"
    if params:
        filtered = {k: v for k, v in params.items() if v is not None}
        if filtered:
            url += "?" + urllib.parse.urlencode(filtered)
    api_key = _resolve_api_key()
    req = urllib.request.Request(url, method="GET")
    req.add_header("X-API-Key", api_key)
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        return f"Error {exc.code}: {body}"
    except urllib.error.URLError as exc:
        return f"Error: EDR server unreachable at {base} -- {exc.reason}"
    except Exception as exc:
        return f"Error: {exc}"


def _api_put(path: str, body: Optional[dict] = None) -> str:
    """PUT request to the EDR server. Returns response body string."""
    base = _resolve_server_url()
    url = f"{base}{path}"
    api_key = _resolve_api_key()
    data = json.dumps(body).encode("utf-8") if body else None
    req = urllib.request.Request(url, data=data, method="PUT")
    req.add_header("X-API-Key", api_key)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        return f"Error {exc.code}: {body_text}"
    except urllib.error.URLError as exc:
        return f"Error: EDR server unreachable at {base} -- {exc.reason}"
    except Exception as exc:
        return f"Error: {exc}"


def _api_post(path: str, body: Optional[dict] = None) -> str:
    """POST request to the EDR server. Returns response body string."""
    base = _resolve_server_url()
    url = f"{base}{path}"
    api_key = _resolve_api_key()
    data = json.dumps(body).encode("utf-8") if body else None
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("X-API-Key", api_key)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        return f"Error {exc.code}: {body_text}"
    except urllib.error.URLError as exc:
        return f"Error: EDR server unreachable at {base} -- {exc.reason}"
    except Exception as exc:
        return f"Error: {exc}"


def _parse_json(raw: str) -> Optional[Any]:
    """Parse a JSON string. Returns None on error."""
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


def _fmt_agents(agents: list[dict]) -> str:
    """Format a list of agents as a readable table."""
    if not agents:
        return "No agents found."
    lines = [
        f"{'UUID':<38} {'Hostname':<24} {'OS':<10} {'Status':<14} {'Last Seen':<20}"
    ]
    lines.append("-" * 110)
    for a in agents:
        uuid = (a.get("device_uuid") or "")[:38]
        host = (a.get("hostname") or "")[:24]
        os_name = (a.get("os") or "")[:10]
        status = (a.get("status") or "")[:14]
        last = (a.get("last_seen") or "")[:20]
        lines.append(f"{uuid:<38} {host:<24} {os_name:<10} {status:<14} {last:<20}")
    lines.append(f"\nTotal: {len(agents)} agent(s)")
    return "\n".join(lines)


def _fmt_alerts(alerts: list[dict]) -> str:
    """Format a list of alerts as a readable table."""
    if not alerts:
        return "No alerts found."
    lines = [
        f"{'ID':>6} {'Severity':<10} {'Device':<38} {'Rule':<30} {'Created':<20}"
    ]
    lines.append("-" * 108)
    for a in alerts:
        aid = a.get("alert_id", "?")
        sev = (a.get("severity") or "?")[:10]
        dev = (a.get("device_uuid") or "")[:38]
        rule = (a.get("rule_name") or a.get("rule_id") or "")[:30]
        created = (a.get("created_at") or "")[:20]
        lines.append(f"{aid:>6} {sev:<10} {dev:<38} {rule:<30} {created:<20}")
    lines.append(f"\nTotal: {len(alerts)} alert(s)")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool functions
# ---------------------------------------------------------------------------


def edr_agents_list(status_filter: str = "", os_filter: str = "") -> str:
    """List all registered EDR agents with status, OS, last checkin, and alert count.
    Phase: EDR
    Related: edr_agent_detail, edr_quarantine, edr_unquarantine
    """
    params = {}
    if status_filter:
        params["status"] = status_filter
    raw = _api_get("/api/admin/devices", params)
    data = _parse_json(raw)
    if data is None:
        return raw if raw.startswith("Error") else "Error: unexpected response from server"
    if not isinstance(data, list):
        return f"Error: expected list, got {type(data).__name__}"
    filtered = data
    if os_filter:
        filtered = [a for a in data if (a.get("os") or "").lower() == os_filter.lower()]
    return _fmt_agents(filtered)


def edr_agent_detail(device_uuid: str) -> str:
    """Get detailed info about a specific EDR agent: hostname, OS, arch, IP, first/last seen, config overrides, recent alerts, and baseline status.
    Phase: EDR
    Related: edr_agents_list, edr_config_push, edr_baseline_reset
    """
    raw = _api_get(f"/api/admin/devices/{urllib.parse.quote(device_uuid, safe='')}")
    data = _parse_json(raw)
    if data is None:
        return raw if raw.startswith("Error") else "Error: unexpected response"
    if not isinstance(data, dict):
        return f"Error: expected dict, got {type(data).__name__}"

    lines = [
        "Agent Detail",
        "=" * 60,
        f"  UUID:        {data.get('device_uuid', '?')}",
        f"  Hostname:    {data.get('hostname', '?')}",
        f"  OS:          {data.get('os', '?')}",
        f"  Arch:        {data.get('arch', '?')}",
        f"  IP:          {data.get('ip_address', '?')}",
        f"  Status:      {data.get('status', '?')}",
        f"  First seen:  {data.get('first_seen', '?')}",
        f"  Last seen:   {data.get('last_seen', '?')}",
    ]

    overrides = data.get("config_overrides")
    if overrides:
        try:
            ov = json.loads(overrides) if isinstance(overrides, str) else overrides
            lines.append(f"  Config overrides: {json.dumps(ov, indent=2)}")
        except (json.JSONDecodeError, TypeError):
            lines.append(f"  Config overrides: {overrides}")
    else:
        lines.append("  Config overrides: none")

    if data.get("notes"):
        lines.append(f"  Notes: {data['notes']}")

    # Fetch recent alerts for this device
    alert_raw = _api_get("/api/admin/alerts", {
        "device_uuid": device_uuid,
        "limit": 10,
    })
    alert_data = _parse_json(alert_raw)
    if isinstance(alert_data, list) and alert_data:
        lines.append(f"\n  Recent alerts ({len(alert_data)}):")
        for a in alert_data[:10]:
            lines.append(
                f"    [{a.get('severity','?'):>8}] {a.get('rule_name') or a.get('rule_id','?')} "
                f"(id={a.get('alert_id','?')}, {a.get('created_at','')})"
            )
    else:
        lines.append("\n  Recent alerts: none")

    return "\n".join(lines)


def edr_alerts_list(
    severity: str = "",
    device_uuid: str = "",
    rule_id: str = "",
    acknowledged: str = "",
    limit: int = 20,
    offset: int = 0,
) -> str:
    """List alerts with optional filters (severity, device, rule, acknowledged). Supports pagination.
    Phase: EDR
    Related: edr_alert_detail, edr_alert_acknowledge, edr_alert_resolve, edr_alert_stats
    """
    params: dict = {"limit": limit, "offset": offset}
    if severity:
        params["severity"] = severity
    if device_uuid:
        params["device_uuid"] = device_uuid
    if acknowledged:
        params["acknowledged"] = acknowledged.lower() in ("true", "1", "yes")
    raw = _api_get("/api/admin/alerts", params)
    data = _parse_json(raw)
    if data is None:
        return raw if raw.startswith("Error") else "Error: unexpected response"
    if not isinstance(data, list):
        return f"Error: expected list, got {type(data).__name__}"

    if rule_id:
        data = [a for a in data if a.get("rule_id") == rule_id]

    header = f"Alerts (offset={offset}, limit={limit})"
    if severity:
        header += f" [severity={severity}]"
    if device_uuid:
        header += f" [device={device_uuid}]"
    return header + "\n" + _fmt_alerts(data)


def edr_alert_detail(alert_id: str) -> str:
    """Get full detail of a single alert including matched rows and response actions.
    Phase: EDR
    Related: edr_alerts_list, edr_alert_acknowledge, edr_alert_resolve
    """
    raw = _api_get("/api/admin/alerts", {"limit": 200})
    data = _parse_json(raw)
    if data is None:
        return raw if raw.startswith("Error") else "Error: unexpected response"
    if not isinstance(data, list):
        return f"Error: expected list, got {type(data).__name__}"

    target_id = int(alert_id) if alert_id.isdigit() else -1
    match = next((a for a in data if a.get("alert_id") == target_id), None)
    if not match:
        return f"Error: alert {alert_id} not found (searched {len(data)} alerts)"

    lines = [
        f"Alert Detail #{match.get('alert_id', '?')}",
        "=" * 60,
        f"  Device:     {match.get('device_uuid', '?')}",
        f"  Rule ID:    {match.get('rule_id', '?')}",
        f"  Rule Name:  {match.get('rule_name', '?')}",
        f"  Severity:   {match.get('severity', '?')}",
        f"  Platform:   {match.get('platform', '?')}",
        f"  Created:    {match.get('created_at', '?')}",
        f"  Acknowledged: {'yes' if match.get('acknowledged') else 'no'}",
        f"  Resolved:   {'yes' if match.get('resolved') else 'no'}",
    ]

    matched_rows = match.get("matched_rows", "[]")
    try:
        rows = json.loads(matched_rows) if isinstance(matched_rows, str) else matched_rows
        if rows:
            lines.append(f"\n  Matched rows ({len(rows)}):")
            for i, row in enumerate(rows[:20], 1):
                lines.append(f"    {i}. {json.dumps(row, default=str)}")
            if len(rows) > 20:
                lines.append(f"    ... and {len(rows) - 20} more rows")
        else:
            lines.append("\n  Matched rows: none")
    except (json.JSONDecodeError, TypeError):
        lines.append(f"\n  Matched rows: {matched_rows}")

    response_actions = match.get("response_actions", "[]")
    try:
        actions = json.loads(response_actions) if isinstance(response_actions, str) else response_actions
        if actions:
            lines.append(f"\n  Response actions:")
            for act in actions:
                lines.append(f"    - {act}")
        else:
            lines.append("\n  Response actions: none")
    except (json.JSONDecodeError, TypeError):
        lines.append(f"\n  Response actions: {response_actions}")

    return "\n".join(lines)


def edr_alert_acknowledge(alert_id: str, notes: str = "") -> str:
    """Mark an alert as acknowledged.
    Phase: EDR
    Related: edr_alerts_list, edr_alert_resolve
    """
    raw = _api_put(f"/api/admin/alerts/{alert_id}/acknowledge", {"notes": notes} if notes else None)
    data = _parse_json(raw)
    if data and isinstance(data, dict) and data.get("status") == "ok":
        return f"Alert {alert_id} acknowledged."
    return raw if raw.startswith("Error") else f"Error: {raw}"


def edr_alert_resolve(alert_id: str, notes: str = "") -> str:
    """Mark an alert as resolved.
    Phase: EDR
    Related: edr_alerts_list, edr_alert_acknowledge
    """
    raw = _api_put(f"/api/admin/alerts/{alert_id}/resolve", {"notes": notes} if notes else None)
    data = _parse_json(raw)
    if data and isinstance(data, dict) and data.get("status") == "ok":
        return f"Alert {alert_id} resolved."
    return raw if raw.startswith("Error") else f"Error: {raw}"


def edr_quarantine(device_uuid: str, reason: str) -> str:
    """Quarantine a device. Sets status to quarantined -- agent enters read-only mode and stops response actions.
    Phase: EDR
    Related: edr_unquarantine, edr_agents_list
    """
    body = {"status": "quarantined", "notes": reason}
    raw = _api_put(
        f"/api/admin/devices/{urllib.parse.quote(device_uuid, safe='')}",
        body,
    )
    data = _parse_json(raw)
    if data and isinstance(data, dict) and data.get("status") == "quarantined":
        return f"Device {device_uuid} quarantined.\nReason: {reason}"
    if data and isinstance(data, dict):
        return f"Device {device_uuid} updated. Status: {data.get('status', '?')}"
    return raw if raw.startswith("Error") else f"Error: {raw}"


def edr_unquarantine(device_uuid: str) -> str:
    """Remove quarantine from a device. Sets status back to active.
    Phase: EDR
    Related: edr_quarantine, edr_agents_list
    """
    body = {"status": "active"}
    raw = _api_put(
        f"/api/admin/devices/{urllib.parse.quote(device_uuid, safe='')}",
        body,
    )
    data = _parse_json(raw)
    if data and isinstance(data, dict) and data.get("status") == "active":
        return f"Device {device_uuid} restored to active."
    if data and isinstance(data, dict):
        return f"Device {device_uuid} updated. Status: {data.get('status', '?')}"
    return raw if raw.startswith("Error") else f"Error: {raw}"


def edr_threat_hunt(query: str, device_uuid: str = "", description: str = "") -> str:
    """Run a custom osquery query against a device (or all devices) for ad-hoc investigation.
    The query is forwarded to the EDR server which proxies it to the target device(s).
    Phase: EDR
    Related: edr_agents_list, edr_agent_detail
    """
    body: dict = {"query": query}
    if device_uuid:
        body["device_uuid"] = device_uuid
    if description:
        body["description"] = description
    raw = _api_post("/api/admin/threat-hunt", body)
    data = _parse_json(raw)
    if data is None:
        return raw if raw.startswith("Error") else "Error: unexpected response"
    if isinstance(data, dict) and data.get("status") == "not_implemented":
        return (
            "Threat hunt endpoint is not yet implemented on the server.\n"
            "This is a stretch feature -- the server needs a /api/admin/threat-hunt\n"
            "endpoint that forwards osquery queries to agents.\n"
            f"Query received: {query}"
        )
    if isinstance(data, list):
        lines = [f"Threat hunt results ({len(data)} device(s)):"]
        for r in data:
            dev = r.get("device_uuid", "?")
            rows = r.get("rows", r.get("result", []))
            if isinstance(rows, list):
                lines.append(f"\n  [{dev}] {len(rows)} row(s):")
                for row in rows[:50]:
                    lines.append(f"    {json.dumps(row, default=str)}")
            else:
                lines.append(f"\n  [{dev}] {json.dumps(rows, default=str)[:500]}")
        return "\n".join(lines)
    if isinstance(data, dict):
        return json.dumps(data, indent=2, default=str)[:4000]
    return str(data)[:4000]


def edr_config_push(device_uuid: str) -> str:
    """Force a config update to all devices. Re-upserts the default config to bump updated_at so devices re-fetch on next checkin. Note: device_uuid is accepted for interface consistency but config push is server-wide.
    Phase: EDR
    Related: edr_agent_detail, edr_agents_list
    """
    # Read current default config, re-upsert it to bump updated_at
    configs_raw = _api_get("/api/admin/configs")
    configs = _parse_json(configs_raw)
    default_name = ""
    default_data = "{}"
    if isinstance(configs, list):
        for c in configs:
            if c.get("is_default"):
                default_name = c.get("config_name", "")
                default_data = c.get("config_data", "{}")
                break
    if not default_name:
        return "Error: no default config found on the server"

    raw = _api_post("/api/admin/configs", {
        "config_name": default_name,
        "config_data": default_data,
        "is_default": True,
    })
    result = _parse_json(raw)
    if result and isinstance(result, dict):
        updated = result.get("updated_at", "?")
        return f"Config pushed for device {device_uuid}.\nDefault config '{default_name}' updated at {updated}.\nDevice will re-fetch config on next checkin."
    return raw if raw.startswith("Error") else f"Error: {raw}"


def edr_alert_stats(days: int = 7) -> str:
    """Get alert statistics: counts by severity, by device, acknowledged/resolved totals. The days param is accepted for interface consistency; the server returns all-time stats.
    Phase: EDR
    Related: edr_alerts_list, edr_alert_detail
    """
    raw = _api_get("/api/admin/alerts/stats")
    data = _parse_json(raw)
    if data is None:
        return raw if raw.startswith("Error") else "Error: unexpected response"
    if not isinstance(data, dict):
        return f"Error: expected dict, got {type(data).__name__}"

    lines = [
        "Alert Statistics",
        "=" * 40,
        f"  Total:       {data.get('total', 0)}",
        f"  Acknowledged: {data.get('acknowledged', 0)}",
        f"  Resolved:    {data.get('resolved', 0)}",
        "",
        "By severity:",
    ]
    by_sev = data.get("by_severity", {})
    if by_sev:
        for sev in ("critical", "high", "medium", "low", "info"):
            cnt = by_sev.get(sev, 0)
            if cnt:
                lines.append(f"  {sev:<12} {cnt}")
        for sev, cnt in by_sev.items():
            if sev not in ("critical", "high", "medium", "low", "info"):
                lines.append(f"  {sev:<12} {cnt}")
    else:
        lines.append("  (none)")

    by_dev = data.get("by_device", {})
    if by_dev:
        lines.append("")
        lines.append("Top devices by alert count:")
        for dev, cnt in list(by_dev.items())[:10]:
            lines.append(f"  {dev:<40} {cnt}")

    return "\n".join(lines)


def edr_baseline_reset(device_uuid: str, table_name: str) -> str:
    """Reset the baseline for a specific table on a device. The device will rebuild its baseline on next checkin.
    Phase: EDR
    Related: edr_agent_detail, edr_agents_list
    """
    body = {"device_uuid": device_uuid, "table_name": table_name}
    raw = _api_post("/api/admin/baseline/reset", body)
    data = _parse_json(raw)
    if data and isinstance(data, dict):
        if data.get("status") == "ok":
            return f"Baseline reset for device {device_uuid}, table '{table_name}'.\nDevice will rebuild baseline on next checkin."
        if data.get("status") == "not_implemented":
            return (
                f"Baseline reset endpoint not yet implemented on the server.\n"
                f"Requested: device={device_uuid}, table={table_name}\n"
                "The server needs a POST /api/admin/baseline/reset endpoint."
            )
    return raw if raw.startswith("Error") else f"Error: {raw}"
