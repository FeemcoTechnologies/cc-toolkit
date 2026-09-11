"""SQLite database models using stdlib sqlite3 (no ORM)."""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def get_conn(db_path: str):
    conn = _connect(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: str) -> None:
    with get_conn(db_path) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS devices (
                device_uuid TEXT PRIMARY KEY,
                hostname TEXT,
                os TEXT,
                arch TEXT,
                ip_address TEXT,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                status TEXT DEFAULT 'active',
                config_overrides TEXT,
                notes TEXT
            );

            CREATE TABLE IF NOT EXISTS alerts (
                alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_uuid TEXT NOT NULL,
                rule_id TEXT,
                rule_name TEXT,
                severity TEXT,
                platform TEXT,
                matched_rows TEXT,
                response_actions TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                acknowledged BOOLEAN DEFAULT 0,
                resolved BOOLEAN DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS baseline_snapshots (
                device_uuid TEXT NOT NULL,
                table_name TEXT NOT NULL,
                snapshot_hash TEXT,
                created_at TIMESTAMP,
                PRIMARY KEY (device_uuid, table_name)
            );

            CREATE TABLE IF NOT EXISTS configs (
                config_name TEXT PRIMARY KEY,
                config_data TEXT,
                is_default BOOLEAN DEFAULT 0,
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS checkins (
                checkin_id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_uuid TEXT NOT NULL,
                timestamp TIMESTAMP,
                alerts_sent INTEGER,
                baseline_hashes TEXT,
                config_version TEXT
            );

            CREATE TABLE IF NOT EXISTS correlation_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT,
                description TEXT,
                severity TEXT,
                affected_devices TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                acknowledged BOOLEAN DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_device ON alerts(device_uuid);
            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
            CREATE INDEX IF NOT EXISTS idx_checkins_device ON checkins(device_uuid);
            CREATE INDEX IF NOT EXISTS idx_checkins_timestamp ON checkins(timestamp);
        """)


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------

def insert_device(
    db_path: str,
    device_uuid: str,
    hostname: str = "",
    os: str = "",
    arch: str = "",
    ip_address: str = "",
    config_overrides: Optional[dict] = None,
    notes: str = "",
) -> dict:
    now = _now_iso()
    with get_conn(db_path) as conn:
        conn.execute(
            """INSERT OR REPLACE INTO devices
               (device_uuid, hostname, os, arch, ip_address,
                first_seen, last_seen, status, config_overrides, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)""",
            (
                device_uuid,
                hostname,
                os,
                arch,
                ip_address,
                now,
                now,
                json.dumps(config_overrides) if config_overrides else None,
                notes,
            ),
        )
    return get_device(db_path, device_uuid)


def get_device(db_path: str, device_uuid: str) -> Optional[dict]:
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM devices WHERE device_uuid = ?", (device_uuid,)
        ).fetchone()
        return dict(row) if row else None


def list_devices(
    db_path: str, status: Optional[str] = None
) -> list[dict]:
    with get_conn(db_path) as conn:
        if status:
            rows = conn.execute(
                "SELECT * FROM devices WHERE status = ? ORDER BY last_seen DESC",
                (status,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM devices ORDER BY last_seen DESC"
            ).fetchall()
        return [dict(r) for r in rows]


def update_device(db_path: str, device_uuid: str, **fields) -> Optional[dict]:
    allowed = {
        "hostname", "os", "arch", "ip_address", "status",
        "config_overrides", "notes",
    }
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return get_device(db_path, device_uuid)
    set_parts = []
    values = []
    for k, v in updates.items():
        set_parts.append(f"{k} = ?")
        if k == "config_overrides" and isinstance(v, dict):
            values.append(json.dumps(v))
        else:
            values.append(v)
    set_parts.append("last_seen = ?")
    values.append(_now_iso())
    values.append(device_uuid)
    with get_conn(db_path) as conn:
        conn.execute(
            f"UPDATE devices SET {', '.join(set_parts)} WHERE device_uuid = ?",
            values,
        )
    return get_device(db_path, device_uuid)


def touch_device_last_seen(db_path: str, device_uuid: str) -> None:
    with get_conn(db_path) as conn:
        conn.execute(
            "UPDATE devices SET last_seen = ? WHERE device_uuid = ?",
            (_now_iso(), device_uuid),
        )


def set_device_status(db_path: str, device_uuid: str, status: str) -> None:
    with get_conn(db_path) as conn:
        conn.execute(
            "UPDATE devices SET status = ?, last_seen = ? WHERE device_uuid = ?",
            (status, _now_iso(), device_uuid),
        )


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

def insert_alert(
    db_path: str,
    device_uuid: str,
    rule_id: str = "",
    rule_name: str = "",
    severity: str = "info",
    platform: str = "",
    matched_rows: Optional[list] = None,
    response_actions: Optional[list] = None,
) -> int:
    with get_conn(db_path) as conn:
        cur = conn.execute(
            """INSERT INTO alerts
               (device_uuid, rule_id, rule_name, severity, platform,
                matched_rows, response_actions)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                device_uuid,
                rule_id,
                rule_name,
                severity,
                platform,
                json.dumps(matched_rows) if matched_rows else "[]",
                json.dumps(response_actions) if response_actions else "[]",
            ),
        )
        return cur.lastrowid


def get_alerts(
    db_path: str,
    device_uuid: Optional[str] = None,
    severity: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    resolved: Optional[bool] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    clauses = []
    params: list[Any] = []
    if device_uuid:
        clauses.append("device_uuid = ?")
        params.append(device_uuid)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if acknowledged is not None:
        clauses.append("acknowledged = ?")
        params.append(int(acknowledged))
    if resolved is not None:
        clauses.append("resolved = ?")
        params.append(int(resolved))
    if since:
        clauses.append("created_at >= ?")
        params.append(since)
    if until:
        clauses.append("created_at <= ?")
        params.append(until)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.extend([limit, offset])
    with get_conn(db_path) as conn:
        rows = conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params,
        ).fetchall()
        return [dict(r) for r in rows]


def get_alert_count(
    db_path: str,
    device_uuid: Optional[str] = None,
    severity: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    resolved: Optional[bool] = None,
) -> int:
    clauses = []
    params: list[Any] = []
    if device_uuid:
        clauses.append("device_uuid = ?")
        params.append(device_uuid)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if acknowledged is not None:
        clauses.append("acknowledged = ?")
        params.append(int(acknowledged))
    if resolved is not None:
        clauses.append("resolved = ?")
        params.append(int(resolved))
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with get_conn(db_path) as conn:
        row = conn.execute(
            f"SELECT COUNT(*) as cnt FROM alerts {where}", params
        ).fetchone()
        return row["cnt"] if row else 0


def get_alert_stats(db_path: str) -> dict:
    with get_conn(db_path) as conn:
        by_severity = conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"
        ).fetchall()
        by_device = conn.execute(
            """SELECT device_uuid, COUNT(*) as cnt
               FROM alerts GROUP BY device_uuid ORDER BY cnt DESC LIMIT 20"""
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) as cnt FROM alerts").fetchone()
        acked = conn.execute(
            "SELECT COUNT(*) as cnt FROM alerts WHERE acknowledged = 1"
        ).fetchone()
        resolved = conn.execute(
            "SELECT COUNT(*) as cnt FROM alerts WHERE resolved = 1"
        ).fetchone()
        return {
            "total": total["cnt"] if total else 0,
            "acknowledged": acked["cnt"] if acked else 0,
            "resolved": resolved["cnt"] if resolved else 0,
            "by_severity": {r["severity"]: r["cnt"] for r in by_severity},
            "by_device": {r["device_uuid"]: r["cnt"] for r in by_device},
        }


def acknowledge_alert(db_path: str, alert_id: int) -> bool:
    with get_conn(db_path) as conn:
        cur = conn.execute(
            "UPDATE alerts SET acknowledged = 1 WHERE alert_id = ?",
            (alert_id,),
        )
        return cur.rowcount > 0


def resolve_alert(db_path: str, alert_id: int) -> bool:
    with get_conn(db_path) as conn:
        cur = conn.execute(
            "UPDATE alerts SET resolved = 1 WHERE alert_id = ?",
            (alert_id,),
        )
        return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Baseline Snapshots
# ---------------------------------------------------------------------------

def save_baseline_snapshot(
    db_path: str,
    device_uuid: str,
    table_name: str,
    snapshot_hash: str,
) -> None:
    with get_conn(db_path) as conn:
        conn.execute(
            """INSERT OR REPLACE INTO baseline_snapshots
               (device_uuid, table_name, snapshot_hash, created_at)
               VALUES (?, ?, ?, ?)""",
            (device_uuid, table_name, snapshot_hash, _now_iso()),
        )


def get_baseline_snapshot(
    db_path: str, device_uuid: str, table_name: str
) -> Optional[dict]:
    with get_conn(db_path) as conn:
        row = conn.execute(
            """SELECT * FROM baseline_snapshots
               WHERE device_uuid = ? AND table_name = ?""",
            (device_uuid, table_name),
        ).fetchone()
        return dict(row) if row else None


def get_all_baseline_snapshots(
    db_path: str, device_uuid: str
) -> list[dict]:
    with get_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM baseline_snapshots WHERE device_uuid = ?",
            (device_uuid,),
        ).fetchall()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Configs
# ---------------------------------------------------------------------------

def upsert_config(
    db_path: str,
    config_name: str,
    config_data: str,
    is_default: bool = False,
) -> dict:
    now = _now_iso()
    with get_conn(db_path) as conn:
        if is_default:
            conn.execute(
                "UPDATE configs SET is_default = 0 WHERE is_default = 1"
            )
        conn.execute(
            """INSERT INTO configs (config_name, config_data, is_default, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(config_name) DO UPDATE SET
                 config_data = excluded.config_data,
                 is_default = excluded.is_default,
                 updated_at = excluded.updated_at""",
            (config_name, config_data, int(is_default), now, now),
        )
    return get_config(db_path, config_name)


def get_config(db_path: str, config_name: str) -> Optional[dict]:
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM configs WHERE config_name = ?", (config_name,)
        ).fetchone()
        return dict(row) if row else None


def list_configs(db_path: str) -> list[dict]:
    with get_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM configs ORDER BY config_name"
        ).fetchall()
        return [dict(r) for r in rows]


def get_default_config(db_path: str) -> Optional[dict]:
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM configs WHERE is_default = 1"
        ).fetchone()
        return dict(row) if row else None


# ---------------------------------------------------------------------------
# Checkins
# ---------------------------------------------------------------------------

def insert_checkin(
    db_path: str,
    device_uuid: str,
    alerts_sent: int = 0,
    baseline_hashes: Optional[dict] = None,
    config_version: str = "",
) -> int:
    now = _now_iso()
    with get_conn(db_path) as conn:
        cur = conn.execute(
            """INSERT INTO checkins
               (device_uuid, timestamp, alerts_sent, baseline_hashes, config_version)
               VALUES (?, ?, ?, ?, ?)""",
            (
                device_uuid,
                now,
                alerts_sent,
                json.dumps(baseline_hashes) if baseline_hashes else "{}",
                config_version,
            ),
        )
        return cur.lastrowid


def get_checkins(
    db_path: str,
    device_uuid: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict]:
    with get_conn(db_path) as conn:
        if device_uuid:
            rows = conn.execute(
                """SELECT * FROM checkins
                   WHERE device_uuid = ?
                   ORDER BY timestamp DESC LIMIT ? OFFSET ?""",
                (device_uuid, limit, offset),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT * FROM checkins
                   ORDER BY timestamp DESC LIMIT ? OFFSET ?""",
                (limit, offset),
            ).fetchall()
        return [dict(r) for r in rows]


def get_last_checkin(db_path: str, device_uuid: str) -> Optional[dict]:
    with get_conn(db_path) as conn:
        row = conn.execute(
            """SELECT * FROM checkins
               WHERE device_uuid = ?
               ORDER BY timestamp DESC LIMIT 1""",
            (device_uuid,),
        ).fetchone()
        return dict(row) if row else None


# ---------------------------------------------------------------------------
# Correlation Alerts
# ---------------------------------------------------------------------------

def insert_correlation_alert(
    db_path: str,
    rule_name: str,
    description: str,
    severity: str = "info",
    affected_devices: Optional[list] = None,
) -> int:
    with get_conn(db_path) as conn:
        cur = conn.execute(
            """INSERT INTO correlation_alerts
               (rule_name, description, severity, affected_devices)
               VALUES (?, ?, ?, ?)""",
            (
                rule_name,
                description,
                severity,
                json.dumps(affected_devices or []),
            ),
        )
        return cur.lastrowid


def get_correlation_alerts(
    db_path: str, limit: int = 50
) -> list[dict]:
    with get_conn(db_path) as conn:
        rows = conn.execute(
            """SELECT * FROM correlation_alerts
               ORDER BY created_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
