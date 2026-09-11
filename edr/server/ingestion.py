"""FastAPI router for alert ingestion from agents."""

import gzip
import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Header, HTTPException, Request, Response

from edr.server import models

logger = logging.getLogger("edr.ingestion")

router = APIRouter(prefix="/ingest", tags=["ingestion"])


def _decompress(data: bytes) -> bytes:
    if len(data) >= 2:
        if data[0] == 0x28 and data[1] == 0xB5:
            try:
                import zstandard as zstd
                dctx = zstd.ZstdDecompressor()
                return dctx.decompress(data)
            except Exception:
                pass
        if data[0] == 0x1F and data[1] == 0x8B:
            return gzip.decompress(data)
    return data


@router.post("/{device_uuid}")
async def ingest_alerts(
    device_uuid: str,
    request: Request,
):
    db_path = request.app.state.db_path

    device = models.get_device(db_path, device_uuid)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    raw = await request.body()
    try:
        decompressed = _decompress(raw)
        payload = json.loads(decompressed)
    except Exception as exc:
        logger.warning("Failed to decompress/parse payload from %s: %s", device_uuid, exc)
        raise HTTPException(status_code=400, detail="Invalid payload")

    alerts = payload.get("alerts", [])
    baseline_hashes = payload.get("baseline_hashes", {})
    timestamp = payload.get("timestamp", datetime.now(timezone.utc).isoformat())

    alerts_received = 0
    high_alerts = []
    for alert in alerts:
        severity = alert.get("severity", "info")
        models.insert_alert(
            db_path,
            device_uuid=device_uuid,
            rule_id=alert.get("rule_id", ""),
            rule_name=alert.get("rule_name", ""),
            severity=severity,
            platform=alert.get("platform", ""),
            matched_rows=alert.get("matched_rows"),
            response_actions=alert.get("response_actions"),
        )
        alerts_received += 1
        if severity in ("high", "critical"):
            high_alerts.append(alert)

    for table_name, snapshot_hash in baseline_hashes.items():
        models.save_baseline_snapshot(
            db_path,
            device_uuid=device_uuid,
            table_name=table_name,
            snapshot_hash=snapshot_hash,
        )

    models.touch_device_last_seen(db_path, device_uuid)

    if high_alerts:
        logger.warning(
            "Device %s sent %d high/critical alerts",
            device_uuid,
            len(high_alerts),
        )

    return {"status": "ok", "alerts_received": alerts_received}


@router.post("/{device_uuid}/heartbeat")
async def heartbeat(
    device_uuid: str,
    request: Request,
):
    db_path = request.app.state.db_path

    device = models.get_device(db_path, device_uuid)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    models.touch_device_last_seen(db_path, device_uuid)
    return {"status": "ok"}
