#!/usr/bin/env python3
"""EDR CLI - Command-line interface for KCC EDR server or local agent."""

import argparse
import json
import os
import sys
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from pathlib import Path

VERSION = "1.0.0"
DEFAULT_SERVER = "http://127.0.0.1:8900"

# -- Color helpers -----------------------------------------------------------

def _is_tty():
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

_BOLD = "\033[1m" if _is_tty() else ""
_RESET = "\033[0m" if _is_tty() else ""
_RED = "\033[91m" if _is_tty() else ""
_YEL = "\033[93m" if _is_tty() else ""
_GRN = "\033[92m" if _is_tty() else ""
_CYN = "\033[96m" if _is_tty() else ""
_DIM = "\033[2m" if _is_tty() else ""

SEV_COLORS = {
    "critical": _RED, "high": "\033[91m" if _is_tty() else "",
    "medium": _YEL, "low": _CYN, "info": _DIM,
}

def color_sev(sev: str) -> str:
    c = SEV_COLORS.get(sev, "")
    return f"{c}{sev}{_RESET}" if c else sev

# -- Config ------------------------------------------------------------------

def load_config():
    server = os.environ.get("EDR_SERVER_URL", "")
    api_key = os.environ.get("EDR_ADMIN_API_KEY", "")
    if not server or not api_key:
        cfg_path = Path.home() / ".config" / "kali-command-center" / "config.json"
        if cfg_path.exists():
            try:
                data = json.loads(cfg_path.read_text())
                server = server or data.get("edr_server_url", "") or data.get("EDR_SERVER_URL", "")
                api_key = api_key or data.get("admin_api_key", "") or data.get("EDR_ADMIN_API_KEY", "")
            except (json.JSONDecodeError, KeyError):
                pass
    return server or DEFAULT_SERVER, api_key

# -- API client --------------------------------------------------------------

class EDRClient:
    def __init__(self, base_url: str, api_key: str):
        self.base = base_url.rstrip("/")
        self.api_key = api_key

    def _request(self, method: str, path: str, body=None, params=None):
        url = f"{self.base}/api{path}"
        if params:
            filtered = {k: v for k, v in params.items() if v is not None}
            if filtered:
                url = f"{url}?{urllib.parse.urlencode(filtered)}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("X-API-Key", self.api_key)
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            body_text = ""
            try:
                body_text = exc.read().decode()
            except Exception:
                pass
            try:
                detail = json.loads(body_text)
                msg = detail.get("error", detail.get("detail", body_text))
            except (json.JSONDecodeError, ValueError):
                msg = body_text or str(exc)
            print(f"{_RED}Error {exc.code}: {msg}{_RESET}", file=sys.stderr)
            sys.exit(1)
        except urllib.error.URLError as exc:
            print(f"{_RED}Cannot connect to EDR server at {self.base}{_RESET}", file=sys.stderr)
            print(f"  {exc.reason}", file=sys.stderr)
            sys.exit(1)

    def get(self, path, **params):
        return self._request("GET", path, params=params)

    def post(self, path, body=None):
        return self._request("POST", path, body=body)

    def put(self, path, body=None):
        return self._request("PUT", path, body=body)

# -- Table formatting --------------------------------------------------------

def _col_widths(headers, rows):
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    return widths

def _format_row(cells, widths):
    parts = []
    for cell, w in zip(cells, widths):
        parts.append(str(cell).ljust(w))
    return "  ".join(parts)

def print_table(headers, rows, json_output=False):
    if json_output:
        obj = [dict(zip(headers, row)) for row in rows]
        print(json.dumps(obj, indent=2))
        return
    if not rows:
        print("  (no results)")
        return
    widths = _col_widths(headers, rows)
    print(f"{_BOLD}{_format_row(headers, widths)}{_RESET}")
    print(f"{_DIM}{'  '.join('-' * w for w in widths)}{_RESET}")
    for row in rows:
        print(_format_row(row, widths))

# -- Command handlers --------------------------------------------------------

def cmd_agents_list(client, args):
    data = client.get("/admin/devices", status=args.status, os=args.os)
    agents = data.get("agents", data if isinstance(data, list) else [])
    headers = ["UUID", "Hostname", "OS", "Arch", "Status", "Last Checkin"]
    rows = []
    for a in agents:
        last = a.get("last_checkin", a.get("last_seen", ""))
        if last and len(last) > 19:
            last = last[:19]
        rows.append((
            a.get("uuid", a.get("id", ""))[:12],
            a.get("hostname", ""),
            a.get("os", ""),
            a.get("arch", ""),
            a.get("status", ""),
            last,
        ))
    print_table(headers, rows, json_output=args.json)

def cmd_agents_detail(client, args):
    data = client.get(f"/admin/devices/{args.uuid}")
    if args.json:
        print(json.dumps(data, indent=2))
        return
    print(f"{_BOLD}Agent Detail{_RESET}")
    for key in ("uuid", "id", "hostname", "os", "arch", "ip_address",
                "first_seen", "last_checkin", "last_seen", "status"):
        val = data.get(key)
        if val:
            label = key.replace("_", " ").title()
            print(f"  {label}: {val}")
    overrides = data.get("config_overrides", {})
    if overrides:
        print(f"\n  {_BOLD}Config Overrides:{_RESET}")
        for k, v in overrides.items():
            print(f"    {k}: {v}")
    recent = data.get("recent_alerts", [])
    if recent:
        print(f"\n  {_BOLD}Recent Alerts:{_RESET}")
        for alert in recent[:5]:
            sev = alert.get("severity", "")
            title = alert.get("title", alert.get("rule_name", ""))
            print(f"    [{color_sev(sev)}] {title}")

def cmd_agents_quarantine(client, args):
    body = {"reason": args.reason or "Manual quarantine via CLI"}
    data = client.post(f"/admin/devices/{args.uuid}/quarantine", body=body)
    print(f"{_GRN}Agent {args.uuid} quarantined.{_RESET}")
    if data.get("message"):
        print(f"  {data['message']}")

def cmd_agents_unquarantine(client, args):
    data = client.post(f"/admin/devices/{args.uuid}/unquarantine")
    print(f"{_GRN}Agent {args.uuid} unquarantined.{_RESET}")
    if data.get("message"):
        print(f"  {data['message']}")

def cmd_alerts_list(client, args):
    data = client.get("/admin/alerts", severity=args.severity,
                      device_uuid=args.device, limit=args.limit)
    alerts = data.get("alerts", data if isinstance(data, list) else [])
    headers = ["ID", "Severity", "Title", "Device", "Time"]
    rows = []
    for a in alerts:
        ts = a.get("created_at", a.get("timestamp", ""))
        if ts and len(ts) > 19:
            ts = ts[:19]
        rows.append((
            str(a.get("id", ""))[:8],
            a.get("severity", ""),
            a.get("title", a.get("rule_name", ""))[:40],
            str(a.get("device_id", a.get("agent_uuid", "")))[:12],
            ts,
        ))
    print_table(headers, rows, json_output=args.json)

def cmd_alerts_detail(client, args):
    data = client.get(f"/admin/alerts/{args.alert_id}")
    if args.json:
        print(json.dumps(data, indent=2))
        return
    print(f"{_BOLD}Alert Detail{_RESET}")
    for key in ("id", "severity", "title", "rule_name", "rule_id",
                "device_id", "agent_uuid", "created_at", "status", "description"):
        val = data.get(key)
        if val:
            label = key.replace("_", " ").title()
            if key == "severity":
                print(f"  {label}: {color_sev(val)}")
            else:
                print(f"  {label}: {val}")
    matched = data.get("matched_rows", data.get("rows", []))
    if matched:
        print(f"\n  {_BOLD}Matched Rows:{_RESET}")
        for row in matched[:10]:
            if isinstance(row, dict):
                print(f"    {json.dumps(row)}")
            else:
                print(f"    {row}")

def cmd_alerts_acknowledge(client, args):
    body = {"notes": args.notes or ""}
    data = client.put(f"/admin/alerts/{args.alert_id}/acknowledge", body=body)
    print(f"{_GRN}Alert {args.alert_id} acknowledged.{_RESET}")

def cmd_alerts_resolve(client, args):
    body = {"notes": args.notes or ""}
    data = client.put(f"/admin/alerts/{args.alert_id}/resolve", body=body)
    print(f"{_GRN}Alert {args.alert_id} resolved.{_RESET}")

def cmd_alerts_stats(client, args):
    data = client.get("/admin/alerts/stats", days=args.days)
    if args.json:
        print(json.dumps(data, indent=2))
        return
    print(f"{_BOLD}Alert Statistics{_RESET}")
    by_sev = data.get("by_severity", data.get("severity_breakdown", {}))
    if by_sev:
        print(f"\n  {_BOLD}By Severity:{_RESET}")
        for sev in ("critical", "high", "medium", "low", "info"):
            count = by_sev.get(sev, 0)
            if count:
                print(f"    {color_sev(sev):>20s}: {count}")
    total = data.get("total", data.get("total_count"))
    if total is not None:
        print(f"\n  Total: {total}")
    period = data.get("period_days", args.days)
    if period:
        print(f"  Period: last {period} days")

def cmd_hunt(client, args):
    body = {"query": args.query}
    if args.description:
        body["description"] = args.description
    path = f"/hunt"
    if args.device:
        path = f"/agents/{args.device}/hunt"
    data = client.post(path, body=body)
    if args.json:
        print(json.dumps(data, indent=2))
        return
    status = data.get("status", "unknown")
    hunt_id = data.get("hunt_id", data.get("id", ""))
    print(f"{_BOLD}Hunt {_CYN}{hunt_id}{_RESET} - status: {status}")
    results = data.get("results", data.get("rows", []))
    if results:
        print(f"\n  {_BOLD}Results ({len(results)} rows):{_RESET}")
        for row in results[:50]:
            if isinstance(row, dict):
                print(f"    {json.dumps(row)}")
            else:
                print(f"    {row}")
    msg = data.get("message", "")
    if msg:
        print(f"\n  {msg}")

def cmd_config_list_rules(client, args):
    data = client.get("/config/rules")
    rules = data.get("rules", data if isinstance(data, list) else [])
    headers = ["Rule ID", "Name", "Severity", "Platform", "Enabled"]
    rows = []
    for r in rules:
        rows.append((
            str(r.get("id", r.get("rule_id", "")))[:16],
            r.get("name", "")[:30],
            r.get("severity", ""),
            r.get("platform", r.get("os", "all")),
            "yes" if r.get("enabled", True) else "no",
        ))
    print_table(headers, rows, json_output=args.json)

def cmd_config_show_rule(client, args):
    data = client.get(f"/config/rules/{args.rule_id}")
    if args.json:
        print(json.dumps(data, indent=2))
        return
    print(f"{_BOLD}Detection Rule{_RESET}")
    for key in ("id", "rule_id", "name", "description", "severity",
                "platform", "query", "enabled", "interval"):
        val = data.get(key)
        if val:
            label = key.replace("_", " ").title()
            print(f"  {label}: {val}")

def cmd_config_push(client, args):
    data = client.post(f"/admin/devices/{args.uuid}/config/push")
    print(f"{_GRN}Config push triggered for agent {args.uuid}.{_RESET}")
    if data.get("message"):
        print(f"  {data['message']}")

def cmd_baseline_show(client, args):
    params = {}
    if args.table:
        params["table"] = args.table
    data = client.get(f"/admin/devices/{args.uuid}/baseline", **params)
    if args.json:
        print(json.dumps(data, indent=2))
        return
    print(f"{_BOLD}Baseline for {args.uuid}{_RESET}")
    tables = data.get("tables", data.get("baselines", []))
    if isinstance(tables, list):
        for t in tables:
            name = t.get("table", t.get("name", ""))
            count = t.get("entry_count", t.get("count", "?"))
            hsh = t.get("hash", "")
            print(f"  {name}: {count} entries  {hsh[:16] if hsh else ''}")
    elif isinstance(tables, dict):
        for name, info in tables.items():
            if isinstance(info, dict):
                count = info.get("entry_count", info.get("count", "?"))
                hsh = info.get("hash", "")
            else:
                count = info
                hsh = ""
            print(f"  {name}: {count} entries  {str(hsh)[:16]}")

def cmd_baseline_reset(client, args):
    data = client.post(f"/agents/{args.uuid}/baseline/{args.table}/reset")
    print(f"{_GRN}Baseline reset for table '{args.table}' on agent {args.uuid}.{_RESET}")

def cmd_status(client, args):
    data = client.get("/admin/devices")
    if args.json:
        print(json.dumps(data, indent=2))
        return
    print(f"{_BOLD}EDR System Status{_RESET}")
    print(f"  Server: {_GRN}{client.base}{_RESET}")
    agents = data.get("total_agents", data.get("agent_count", "?"))
    print(f"  Total Agents: {agents}")
    alerts = data.get("alerts_by_severity", data.get("alerts", {}))
    if isinstance(alerts, dict):
        print(f"\n  {_BOLD}Alerts by Severity:{_RESET}")
        for sev in ("critical", "high", "medium", "low", "info"):
            count = alerts.get(sev, 0)
            if count:
                print(f"    {color_sev(sev):>20s}: {count}")
    last_corr = data.get("last_correlation_run")
    if last_corr:
        print(f"\n  Last Correlation: {last_corr}")
    version = data.get("version", "")
    if version:
        print(f"  Version: {version}")

# -- Argument parser ---------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="cc-edr",
        description="KCC EDR CLI",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    p.add_argument("--json", action="store_true", dest="global_json",
                   help="JSON output (global)")
    sub = p.add_subparsers(dest="command")

    # agents
    ag = sub.add_parser("agents", help="Manage/list EDR agents")
    ag_sub = ag.add_subparsers(dest="subcommand")

    al = ag_sub.add_parser("list", help="List agents")
    al.add_argument("--status", choices=["active", "quarantined", "disabled"])
    al.add_argument("--os", choices=["linux", "windows"])
    al.add_argument("--json", action="store_true")
    al.set_defaults(func=cmd_agents_list)

    ad = ag_sub.add_parser("detail", help="Show agent detail")
    ad.add_argument("uuid")
    ad.add_argument("--json", action="store_true")
    ad.set_defaults(func=cmd_agents_detail)

    aq = ag_sub.add_parser("quarantine", help="Quarantine agent")
    aq.add_argument("uuid")
    aq.add_argument("--reason", help="Reason for quarantine")
    aq.set_defaults(func=cmd_agents_quarantine)

    au = ag_sub.add_parser("unquarantine", help="Remove quarantine")
    au.add_argument("uuid")
    au.set_defaults(func=cmd_agents_unquarantine)

    # alerts
    al2 = sub.add_parser("alerts", help="Manage/list alerts")
    al2_sub = al2.add_subparsers(dest="subcommand")

    all_ = al2_sub.add_parser("list", help="List alerts")
    all_.add_argument("--severity", choices=["info", "low", "medium", "high", "critical"])
    all_.add_argument("--device", help="Filter by device UUID")
    all_.add_argument("--limit", type=int, default=50)
    all_.add_argument("--json", action="store_true")
    all_.set_defaults(func=cmd_alerts_list)

    ald = al2_sub.add_parser("detail", help="Show alert detail")
    ald.add_argument("alert_id")
    ald.add_argument("--json", action="store_true")
    ald.set_defaults(func=cmd_alerts_detail)

    ala = al2_sub.add_parser("acknowledge", help="Acknowledge alert")
    ala.add_argument("alert_id")
    ala.add_argument("--notes", help="Notes")
    ala.set_defaults(func=cmd_alerts_acknowledge)

    alr = al2_sub.add_parser("resolve", help="Resolve alert")
    alr.add_argument("alert_id")
    alr.add_argument("--notes", help="Notes")
    alr.set_defaults(func=cmd_alerts_resolve)

    als = al2_sub.add_parser("stats", help="Alert statistics")
    als.add_argument("--days", type=int, default=30)
    als.add_argument("--json", action="store_true")
    als.set_defaults(func=cmd_alerts_stats)

    # hunt
    ht = sub.add_parser("hunt", help="Run ad-hoc threat hunt query")
    ht.add_argument("query", help="osquery SQL query")
    ht.add_argument("--device", help="Target device UUID (omit for all)")
    ht.add_argument("--description", help="Description of the hunt")
    ht.add_argument("--json", action="store_true")
    ht.set_defaults(func=cmd_hunt)

    # config
    cf = sub.add_parser("config", help="Detection rules and configs")
    cf_sub = cf.add_subparsers(dest="subcommand")

    clr = cf_sub.add_parser("list-rules", help="List detection rules")
    clr.add_argument("--json", action="store_true")
    clr.set_defaults(func=cmd_config_list_rules)

    csr = cf_sub.add_parser("show-rule", help="Show rule detail")
    csr.add_argument("rule_id")
    csr.add_argument("--json", action="store_true")
    csr.set_defaults(func=cmd_config_show_rule)

    cp = cf_sub.add_parser("push", help="Force config push to agent")
    cp.add_argument("uuid")
    cp.set_defaults(func=cmd_config_push)

    # baseline
    bl = sub.add_parser("baseline", help="Manage baselines")
    bl_sub = bl.add_subparsers(dest="subcommand")

    bs = bl_sub.add_parser("show", help="Show baseline status")
    bs.add_argument("uuid")
    bs.add_argument("--table", help="Show specific table baseline")
    bs.add_argument("--json", action="store_true")
    bs.set_defaults(func=cmd_baseline_show)

    br = bl_sub.add_parser("reset", help="Reset baseline for a table")
    br.add_argument("uuid")
    br.add_argument("table_name")
    br.set_defaults(func=cmd_baseline_reset)

    # status
    st = sub.add_parser("status", help="Show system status")
    st.add_argument("--json", action="store_true")
    st.set_defaults(func=cmd_status)

    return p

# -- Main --------------------------------------------------------------------

def main():
    parser = build_parser()
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)
    # propagate global --json to subcommands that don't have their own
    if getattr(args, "global_json", False):
        if not hasattr(args, "json"):
            args.json = True
    server_url, api_key = load_config()
    if not api_key:
        print(f"{_DIM}Warning: no API key configured. Set EDR_ADMIN_API_KEY or add to config.json{_RESET}",
              file=sys.stderr)
    client = EDRClient(server_url, api_key)
    handler = getattr(args, "func", None)
    if handler:
        handler(client, args)
    else:
        parser.parse_args([args.command, "--help"])

if __name__ == "__main__":
    main()
