"""FastAPI router for config delivery to agents."""

import gzip
import hashlib
import json
import logging
import os
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Request, Response

from edr.server import models

logger = logging.getLogger("edr.config")

router = APIRouter(prefix="/cfg", tags=["config"])


def _compress(data: bytes, accept_encoding: str) -> tuple[bytes, str]:
    if "zstd" in accept_encoding:
        try:
            import zstandard as zstd
            ctx = zstd.ZstdCompressor()
            return ctx.compress(data), "zstd"
        except ImportError:
            pass
    if "gzip" in accept_encoding or "*/*" in accept_encoding:
        return gzip.compress(data), "gzip"
    return data, "identity"


def _load_rules(rules_dir: str, os_filter: Optional[str] = None) -> list[dict]:
    rules = []
    if not os.path.isdir(rules_dir):
        return rules
    for fname in sorted(os.listdir(rules_dir)):
        if not fname.endswith((".yaml", ".yml", ".json")):
            continue
        fpath = os.path.join(rules_dir, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
            if fname.endswith(".json"):
                rule = json.loads(content)
            else:
                try:
                    import yaml
                    rule = yaml.safe_load(content)
                except ImportError:
                    rule = {"_raw": content, "_filename": fname}
            if not isinstance(rule, dict):
                continue
            rule.setdefault("_filename", fname)
            enabled = rule.get("enabled", True)
            if not enabled:
                continue
            platforms = rule.get("platform", rule.get("platforms", []))
            if os_filter and platforms:
                if isinstance(platforms, str):
                    platforms = [platforms]
                if os_filter.lower() not in [p.lower() for p in platforms]:
                    continue
            rules.append(rule)
        except Exception as exc:
            logger.warning("Failed to load rule %s: %s", fname, exc)
    return rules


@router.get("/{device_uuid}")
async def get_config(
    device_uuid: str,
    request: Request,
    accept_encoding: str = Header(default="*/*"),
):
    db_path = request.app.state.db_path

    device = models.get_device(db_path, device_uuid)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    default_cfg = models.get_default_config(db_path)
    config_data = {}
    if default_cfg and default_cfg.get("config_data"):
        try:
            config_data = json.loads(default_cfg["config_data"])
        except (json.JSONDecodeError, TypeError):
            config_data = {}

    overrides_raw = device.get("config_overrides")
    if overrides_raw:
        try:
            overrides = json.loads(overrides_raw) if isinstance(overrides_raw, str) else overrides_raw
            if isinstance(overrides, dict):
                config_data.update(overrides)
        except (json.JSONDecodeError, TypeError):
            pass

    rules_dir = request.app.state.rules_dir
    rules = _load_rules(rules_dir, os_filter=device.get("os"))
    config_data["detection_rules"] = rules

    body = json.dumps(config_data, indent=2).encode("utf-8")
    etag = hashlib.sha256(body).hexdigest()[:16]
    if_none_match = request.headers.get("if-none-match")
    if if_none_match and if_none_match.strip('"') == etag:
        return Response(status_code=304)

    compressed, encoding = _compress(body, accept_encoding)

    models.insert_checkin(
        db_path,
        device_uuid=device_uuid,
        alerts_sent=0,
        baseline_hashes={},
        config_version=default_cfg["updated_at"] if default_cfg else "",
    )
    models.touch_device_last_seen(db_path, device_uuid)

    return Response(
        content=compressed,
        media_type="application/json",
        headers={
            "Content-Encoding": encoding,
            "ETag": f'"{etag}"',
            "Cache-Control": "no-cache",
        },
    )


@router.get("/{device_uuid}/rules")
async def get_rules(
    device_uuid: str,
    request: Request,
    accept_encoding: str = Header(default="*/*"),
):
    db_path = request.app.state.db_path

    device = models.get_device(db_path, device_uuid)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    rules_dir = request.app.state.rules_dir
    rules = _load_rules(rules_dir, os_filter=device.get("os"))
    body = json.dumps(rules, indent=2).encode("utf-8")
    compressed, encoding = _compress(body, accept_encoding)

    return Response(
        content=compressed,
        media_type="application/json",
        headers={"Content-Encoding": encoding},
    )


@router.get("/{device_uuid}/status")
async def get_status(device_uuid: str, request: Request):
    db_path = request.app.state.db_path

    device = models.get_device(db_path, device_uuid)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    last_checkin = models.get_last_checkin(db_path, device_uuid)
    default_cfg = models.get_default_config(db_path)

    return {
        "device_uuid": device_uuid,
        "last_config_push": (
            default_cfg["updated_at"] if default_cfg else None
        ),
        "last_checkin": last_checkin["timestamp"] if last_checkin else None,
        "config_version": (
            last_checkin["config_version"] if last_checkin else ""
        ),
    }
