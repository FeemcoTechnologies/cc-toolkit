"""Main FastAPI application factory."""

import hashlib
import hmac
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import APIRouter, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from edr.server import models
from edr.server.config_api import router as config_router
from edr.server.detection import run_correlation
from edr.server.ingestion import router as ingest_router

logger = logging.getLogger("edr.server")

DEFAULT_CONFIG = {
    "db_path": "./edr.db",
    "rules_dir": "./rules",
    "secret_key": "",
    "admin_api_key": "",
    "bind_host": "0.0.0.0",
    "bind_port": 8900,
    "cors_origins": ["*"],
}

VERSION = "0.1.0"


def _verify_hmac(secret: str, payload: str, signature: str) -> bool:
    expected = hmac.new(
        secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


async def _auth_middleware(request: Request, call_next):
    path = request.url.path

    if path.startswith("/ingest/"):
        device_uuid_header = request.headers.get("X-Device-UUID", "")
        signature = request.headers.get("X-Signature", "")
        timestamp = request.headers.get("X-Timestamp", "")
        if not all([device_uuid_header, signature, timestamp]):
            return Response(
                content=json.dumps({"detail": "Missing auth headers"}),
                status_code=401,
                media_type="application/json",
            )
        body = await request.body()
        body_hash = hashlib.sha256(body).hexdigest()
        payload = f"{device_uuid_header}:{timestamp}:{body_hash}"
        secret = request.app.state.secret_key
        if secret and not _verify_hmac(secret, payload, signature):
            return Response(
                content=json.dumps({"detail": "Invalid signature"}),
                status_code=403,
                media_type="application/json",
            )

    elif path.startswith("/cfg/"):
        url_uuid = path.split("/")[2] if len(path.split("/")) > 2 else ""
        device_uuid_header = request.headers.get("X-Device-UUID", "")
        signature = request.headers.get("X-Signature", "")
        timestamp = request.headers.get("X-Timestamp", "")
        if not all([device_uuid_header, signature, timestamp]):
            return Response(
                content=json.dumps({"detail": "Missing auth headers"}),
                status_code=401,
                media_type="application/json",
            )
        if device_uuid_header != url_uuid:
            return Response(
                content=json.dumps({"detail": "X-Device-UUID does not match URL"}),
                status_code=403,
                media_type="application/json",
            )
        secret = request.app.state.secret_key
        payload = f"{device_uuid_header}:{timestamp}:"
        if secret and not _verify_hmac(secret, payload, signature):
            return Response(
                content=json.dumps({"detail": "Invalid signature"}),
                status_code=403,
                media_type="application/json",
            )

    return await call_next(request)


def _require_admin(api_key: str, request: Request):
    configured = request.app.state.admin_api_key
    if configured and api_key != configured:
        raise HTTPException(status_code=403, detail="Invalid API key")


def _periodic_correlation(db_path: str):
    try:
        results = run_correlation(db_path)
        if results:
            logger.info("Correlation produced %d result(s)", len(results))
    except Exception as exc:
        logger.error("Correlation engine error: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    db_path = app.state.db_path
    models.init_db(db_path)
    logger.info("Database initialized at %s", db_path)

    import asyncio

    async def _correlation_loop():
        while True:
            await asyncio.sleep(300)
            _periodic_correlation(db_path)

    task = asyncio.create_task(_correlation_loop())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


def create_app(config: Optional[dict] = None) -> FastAPI:
    cfg = {**DEFAULT_CONFIG}
    if config:
        cfg.update(config)

    env_overrides = {
        "db_path": "EDR_DB_PATH",
        "secret_key": "EDR_SECRET_KEY",
        "admin_api_key": "EDR_ADMIN_API_KEY",
        "rules_dir": "EDR_RULES_DIR",
        "bind_host": "EDR_BIND_HOST",
        "bind_port": "EDR_BIND_PORT",
    }
    for key, env_var in env_overrides.items():
        val = os.environ.get(env_var)
        if val:
            if key == "bind_port":
                cfg[key] = int(val)
            else:
                cfg[key] = val

    app = FastAPI(
        title="EDR Server",
        version=VERSION,
        lifespan=lifespan,
    )

    app.state.db_path = cfg["db_path"]
    app.state.rules_dir = cfg["rules_dir"]
    app.state.secret_key = cfg["secret_key"]
    app.state.admin_api_key = cfg["admin_api_key"]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg["cors_origins"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        return await _auth_middleware(request, call_next)

    app.include_router(config_router)
    app.include_router(ingest_router)

    # -----------------------------------------------------------------------
    # Health
    # -----------------------------------------------------------------------

    @app.get("/health")
    async def health():
        return {"status": "ok", "version": VERSION}

    # -----------------------------------------------------------------------
    # Admin API
    # -----------------------------------------------------------------------

    admin = APIRouter(prefix="/api/admin", tags=["admin"])

    @admin.get("/devices")
    async def admin_list_devices(
        request: Request,
        api_key: str = Header(alias="X-API-Key"),
        status: Optional[str] = Query(default=None),
    ):
        _require_admin(api_key, request)
        return models.list_devices(request.app.state.db_path, status=status)

    @admin.get("/devices/{uuid}")
    async def admin_get_device(
        uuid: str,
        request: Request,
        api_key: str = Header(alias="X-API-Key"),
    ):
        _require_admin(api_key, request)
        device = models.get_device(request.app.state.db_path, uuid)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        return device

    @admin.put("/devices/{uuid}")
    async def admin_update_device(
        uuid: str,
        request: Request,
        api_key: str = Header(alias="X-API-Key"),
    ):
        _require_admin(api_key, request)
        body = await request.json()
        device = models.update_device(request.app.state.db_path, uuid, **body)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        return device

    @admin.get("/alerts")
    async def admin_list_alerts(
        request: Request,
        api_key: str = Header(alias="X-API-Key"),
        device_uuid: Optional[str] = Query(default=None),
        severity: Optional[str] = Query(default=None),
        acknowledged: Optional[bool] = Query(default=None),
        resolved: Optional[bool] = Query(default=None),
        since: Optional[str] = Query(default=None),
        until: Optional[str] = Query(default=None),
        limit: int = Query(default=100, le=1000),
        offset: int = Query(default=0),
    ):
        _require_admin(api_key, request)
        return models.get_alerts(
            request.app.state.db_path,
            device_uuid=device_uuid,
            severity=severity,
            acknowledged=acknowledged,
            resolved=resolved,
            since=since,
            until=until,
            limit=limit,
            offset=offset,
        )

    @admin.put("/alerts/{alert_id}/acknowledge")
    async def admin_acknowledge_alert(
        alert_id: int,
        request: Request,
        api_key: str = Header(alias="X-API-Key"),
    ):
        _require_admin(api_key, request)
        if not models.acknowledge_alert(request.app.state.db_path, alert_id):
            raise HTTPException(status_code=404, detail="Alert not found")
        return {"status": "ok"}

    @admin.put("/alerts/{alert_id}/resolve")
    async def admin_resolve_alert(
        alert_id: int,
        request: Request,
        api_key: str = Header(alias="X-API-Key"),
    ):
        _require_admin(api_key, request)
        if not models.resolve_alert(request.app.state.db_path, alert_id):
            raise HTTPException(status_code=404, detail="Alert not found")
        return {"status": "ok"}

    @admin.get("/alerts/stats")
    async def admin_alert_stats(
        request: Request,
        api_key: str = Header(alias="X-API-Key"),
    ):
        _require_admin(api_key, request)
        return models.get_alert_stats(request.app.state.db_path)

    @admin.get("/configs")
    async def admin_list_configs(
        request: Request,
        api_key: str = Header(alias="X-API-Key"),
    ):
        _require_admin(api_key, request)
        return models.list_configs(request.app.state.db_path)

    @admin.post("/configs")
    async def admin_upsert_config(
        request: Request,
        api_key: str = Header(alias="X-API-Key"),
    ):
        _require_admin(api_key, request)
        body = await request.json()
        config_name = body.get("config_name")
        config_data = body.get("config_data")
        is_default = body.get("is_default", False)
        if not config_name or not config_data:
            raise HTTPException(
                status_code=400,
                detail="config_name and config_data required",
            )
        if isinstance(config_data, dict):
            config_data = json.dumps(config_data)
        return models.upsert_config(
            request.app.state.db_path,
            config_name=config_name,
            config_data=config_data,
            is_default=is_default,
        )

    @admin.get("/checkins")
    async def admin_list_checkins(
        request: Request,
        api_key: str = Header(alias="X-API-Key"),
        device_uuid: Optional[str] = Query(default=None),
        limit: int = Query(default=50, le=500),
    ):
        _require_admin(api_key, request)
        return models.get_checkins(
            request.app.state.db_path,
            device_uuid=device_uuid,
            limit=limit,
        )

    @admin.get("/correlation")
    async def admin_correlation_alerts(
        request: Request,
        api_key: str = Header(alias="X-API-Key"),
        limit: int = Query(default=50, le=500),
    ):
        _require_admin(api_key, request)
        return models.get_correlation_alerts(
            request.app.state.db_path, limit=limit
        )

    @admin.post("/rules/test")
    async def admin_test_rule(
        request: Request,
        api_key: str = Header(alias="X-API-Key"),
    ):
        _require_admin(api_key, request)
        body = await request.json()
        return {
            "status": "not_implemented",
            "message": "Stretch goal: send rule to device for live testing",
            "received": body,
        }

    app.include_router(admin)

    return app


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    import uvicorn
    cfg = dict(DEFAULT_CONFIG)
    for key, env_var in {
        "bind_host": "EDR_BIND_HOST",
        "bind_port": "EDR_BIND_PORT",
    }.items():
        val = os.environ.get(env_var)
        if val:
            cfg[key] = int(val) if key == "bind_port" else val
    app = create_app(cfg)
    uvicorn.run(
        app,
        host=cfg["bind_host"],
        port=cfg["bind_port"],
    )


if __name__ == "__main__":
    main()
