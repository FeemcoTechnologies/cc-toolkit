import logging
"""DNS resolution and monitoring engine.

One-shot resolution + persistent monitoring with change detection.
History stored as append-only JSONL per domain.
"""

import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set
logger = logging.getLogger(__name__)

try:
    from .constants import CC_DIR
except ImportError:
    CC_DIR = Path("/workspace")

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

DNS_DATA_DIR = CC_DIR / "data" / "dns_monitors"
DNS_DATA_DIR.mkdir(parents=True, exist_ok=True)

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV", "CAA"]

# ── Helpers ────────────────────────────────────────────────────────────────


def _domain_dir(domain: str) -> Path:
    import hashlib
    h = hashlib.sha256(domain.lower().encode()).hexdigest()[:16]
    return DNS_DATA_DIR / h


def _resolve_one(domain: str, rtype: str) -> List[Dict]:
    """Resolve a single record type. Returns list of {value, ttl} dicts."""
    if not HAS_DNSPYTHON:
        return [{"value": "dnspython not installed", "ttl": 0}]
    try:
        answers = dns.resolver.resolve(domain, rtype, lifetime=10)
        return [
            {"value": str(r), "ttl": answers.rrset.ttl if answers.rrset else 0}
            for r in answers
        ]
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return [{"value": "NXDOMAIN", "ttl": 0}]
    except Exception as e:
        return [{"value": f"ERROR: {e}", "ttl": 0}]


# ── One-shot resolution ────────────────────────────────────────────────────


def resolve(domain: str, types: Optional[List[str]] = None) -> dict:
    """Resolve one or all record types for a domain. Returns {type: [{value, ttl}]}."""
    types = types or RECORD_TYPES
    result = {"domain": domain, "timestamp": datetime.now(timezone.utc).isoformat(), "records": {}}
    for rt in types:
        result["records"][rt] = _resolve_one(domain, rt)
    return result


# ── Monitor persistence ────────────────────────────────────────────────────


def _load_config(domain: str) -> dict:
    cfg_file = _domain_dir(domain) / "config.json"
    if cfg_file.exists():
        return json.loads(cfg_file.read_text())
    return {}


def _save_config(domain: str, cfg: dict):
    d = _domain_dir(domain)
    d.mkdir(parents=True, exist_ok=True)
    (d / "config.json").write_text(json.dumps(cfg, indent=2))


def _append_history(domain: str, records: dict, prev_records: dict):
    """Append resolution results to history.jsonl."""
    d = _domain_dir(domain)
    d.mkdir(parents=True, exist_ok=True)
    path = d / "history.jsonl"
    ts = datetime.now(timezone.utc).isoformat()
    lines = []
    for rtype, entries in records.items():
        prev_entries = prev_records.get(rtype, [])
        prev_values = {e["value"] for e in prev_entries}
        for e in entries:
            changed = e["value"] not in prev_values if prev_values else False
            lines.append(json.dumps({
                "ts": ts, "type": rtype, "value": e["value"],
                "ttl": e["ttl"], "prev_value": list(prev_values)[0] if prev_values and changed else None,
                "changed": changed,
            }))
    with open(path, "a", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")


def list_monitors() -> List[dict]:
    """List all monitored domains with their current config."""
    results = []
    for d in sorted(DNS_DATA_DIR.iterdir()):
        if not d.is_dir():
            continue
        cfg_file = d / "config.json"
        if not cfg_file.exists():
            continue
        cfg = json.loads(cfg_file.read_text())
        # Count history entries
        hist_file = d / "history.jsonl"
        entry_count = 0
        if hist_file.exists():
            with open(hist_file) as _f:
                entry_count = sum(1 for _ in _f)
        cfg["history_count"] = entry_count
        results.append(cfg)
    return results


# ── Monitor lifecycle ──────────────────────────────────────────────────────


def start_monitor(domain: str, types: Optional[List[str]] = None,
                  interval: int = 300, duration: int = 0) -> dict:
    """Start monitoring a domain for DNS changes."""
    types = types or ["A", "AAAA"]
    d = _domain_dir(domain)
    existing = _load_config(domain)
    if existing.get("active"):
        return {"error": f"Already monitoring {domain}", "config": existing}

    # Initial resolution
    records = resolve(domain, types)["records"]
    cfg = {
        "domain": domain,
        "record_types": types,
        "interval": interval,
        "duration": duration,
        "created": datetime.now(timezone.utc).isoformat(),
        "last_check": datetime.now(timezone.utc).isoformat(),
        "next_check": datetime.now(timezone.utc).isoformat(),
        "active": True,
        "change_count": 0,
    }
    _save_config(domain, cfg)
    _append_history(domain, records, {})
    return {"status": "started", "config": cfg}


def stop_monitor(domain: str) -> dict:
    """Deactivate monitoring for a domain."""
    cfg = _load_config(domain)
    if not cfg:
        return {"error": f"Not monitoring {domain}"}
    cfg["active"] = False
    _save_config(domain, cfg)
    return {"status": "stopped", "domain": domain}


def remove_monitor(domain: str) -> dict:
    """Remove a monitor and all its data."""
    import shutil
    d = _domain_dir(domain)
    if d.exists():
        shutil.rmtree(d)
        return {"status": "removed", "domain": domain}
    return {"error": f"Not found: {domain}"}


def get_history(domain: str, limit: int = 100) -> List[dict]:
    """Get resolution history for a domain, newest first."""
    d = _domain_dir(domain)
    path = d / "history.jsonl"
    if not path.exists():
        return []
    with open(path) as f:
        lines = [json.loads(line) for line in f if line.strip()]
    lines.reverse()
    return lines[:limit]


# ── Background monitor loop ─────────────────────────────────────────────────


_monitor_thread: Optional[threading.Thread] = None
_monitor_stop = threading.Event()


def _check_all_monitors():
    """Check all active monitors and resolve if due."""
    for cfg in list_monitors():
        if not cfg.get("active"):
            continue
        now = datetime.now(timezone.utc).isoformat()
        next_check = cfg.get("next_check", "")
        if next_check and next_check > now:
            continue

        domain = cfg["domain"]
        types = cfg.get("record_types", ["A", "AAAA"])
        prev_records = resolve(domain, types)["records"]
        # Wait a moment, then resolve again to compare
        time.sleep(0.5)
        records = resolve(domain, types)["records"]

        changed = False
        for rtype, entries in records.items():
            prev = {e["value"] for e in prev_records.get(rtype, [])}
            for e in entries:
                if e["value"] not in prev:
                    changed = True
                    break

        _append_history(domain, records, prev_records)

        interval = cfg.get("interval", 300)
        next_dt = datetime.now(timezone.utc).timestamp() + interval
        cfg["last_check"] = datetime.now(timezone.utc).isoformat()
        cfg["next_check"] = datetime.fromtimestamp(next_dt, tz=timezone.utc).isoformat()
        if changed:
            cfg["change_count"] = cfg.get("change_count", 0) + 1
        _save_config(domain, cfg)


def _monitor_loop():
    """Background loop — checks all monitors every 30s."""
    while not _monitor_stop.is_set():
        try:
            _check_all_monitors()
        except Exception:

            logger.debug("Exception in dns_wrapper.py", exc_info=True)
        _monitor_stop.wait(30)


def start_background_monitor():
    global _monitor_thread
    if _monitor_thread and _monitor_thread.is_alive():
        return
    _monitor_stop.clear()
    _monitor_thread = threading.Thread(target=_monitor_loop, daemon=True)
    _monitor_thread.start()


def stop_background_monitor():
    _monitor_stop.set()
    if _monitor_thread:
        _monitor_thread.join(timeout=5)