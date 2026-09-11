"""Alert batching, compression, and delivery."""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple

from edr.agent.config import AgentConfig

logger = logging.getLogger(__name__)


def _try_compress(data: bytes, mode: str) -> tuple[bytes, str]:
    """Compress data using zstd or gzip."""
    if mode == "zstd":
        try:
            import zstandard
            compressor = zstandard.ZstdCompressor()
            return compressor.compress(data), ".zst"
        except ImportError:
            logger.debug("zstandard not available, falling back to gzip")
    import gzip
    return gzip.compress(data), ".gz"


def _try_decompress(data: bytes, suffix: str) -> bytes:
    """Decompress data by file suffix."""
    if suffix == ".zst":
        import zstandard
        dctx = zstandard.ZstdDecompressor()
        return dctx.decompress(data)
    if suffix == ".gz":
        import gzip
        return gzip.decompress(data)
    return data


class Reporter:
    """Queues alerts, compresses, and sends to server."""

    def __init__(self, config: AgentConfig):
        self._config = config
        self._queue_dir = config.alert_queue_dir
        self._queue_dir.mkdir(parents=True, exist_ok=True)
        self._compression = config.compression

    def queue_alert(self, result: dict):
        """Write a detection result as a JSON file in the queue."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        day_dir = self._queue_dir / today
        day_dir.mkdir(parents=True, exist_ok=True)
        rule_id = result.get("rule_id", "unknown")
        ts = result.get("timestamp", time.time())
        filename = f"{int(ts)}_{rule_id}_{uuid.uuid4().hex[:8]}.json"
        path = day_dir / filename
        payload = json.dumps(result, indent=2, default=str)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(payload, encoding="utf-8")
        tmp.replace(path)
        rule_id = result.get("rule_id", "unknown")
        logger.info("Queued alert: %s -> %s", rule_id, path)

    def _collect_queued(self) -> list[tuple[Path, dict]]:
        """Read all queued alert files, return list of (path, parsed_dict)."""
        alerts = []
        for day_dir in sorted(self._queue_dir.iterdir()):
            if not day_dir.is_dir():
                continue
            for fpath in sorted(day_dir.iterdir()):
                if not fpath.is_file() or not fpath.suffix == ".json":
                    continue
                try:
                    data = json.loads(fpath.read_text(encoding="utf-8"))
                    alerts.append((fpath, data))
                except (json.JSONDecodeError, OSError) as exc:
                    logger.error("Failed to read alert %s: %s", fpath, exc)
        return alerts

    def send_batch(self) -> int:
        """Compress and POST all queued alerts to the server."""
        if self._config.offline_mode:
            logger.info("Offline mode, skipping send")
            return 0
        queued = self._collect_queued()
        if not queued:
            return 0
        alerts = [item for _, item in queued]
        file_paths = [p for p, _ in queued]
        baseline_hashes = self._collect_baseline_hashes()
        payload = {
            "device_uuid": self._config.device_uuid,
            "alerts": alerts,
            "baseline_hashes": baseline_hashes,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        compressed, suffix = _try_compress(
            json.dumps(payload, default=str).encode("utf-8"),
            self._compression,
        )
        endpoint = f"{self._config.server_url}/ingest/{self._config.device_uuid}"
        sent = self._send_to_server(endpoint, compressed, suffix)
        if sent:
            for fpath in file_paths:
                try:
                    fpath.unlink(missing_ok=True)
                except OSError as exc:
                    logger.error("Failed to delete sent alert %s: %s", fpath, exc)
            logger.info("Sent %d alerts to server", len(alerts))
        return len(alerts) if sent else 0

    def send_batch_retry(self) -> int:
        """Attempt send; leave files in place on failure for next retry."""
        queued = self._collect_queued()
        if not queued:
            return 0
        alerts = [item for _, item in queued]
        baseline_hashes = self._collect_baseline_hashes()
        payload = {
            "device_uuid": self._config.device_uuid,
            "alerts": alerts,
            "baseline_hashes": baseline_hashes,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        compressed, suffix = _try_compress(
            json.dumps(payload, default=str).encode("utf-8"),
            self._compression,
        )
        endpoint = f"{self._config.server_url}/ingest/{self._config.device_uuid}"
        sent = self._send_to_server(endpoint, compressed, suffix)
        if sent:
            for fpath, _ in queued:
                try:
                    fpath.unlink(missing_ok=True)
                except OSError:
                    pass
        return len(alerts) if sent else 0

    def _send_to_server(self, url: str, data: bytes, suffix: str) -> bool:
        """POST compressed payload to server. Returns True on success."""
        import urllib.request
        import urllib.error
        headers = {
            "Content-Type": "application/octet-stream",
            "X-Device-UUID": self._config.device_uuid,
            "X-Compression": suffix.lstrip("."),
        }
        if self._config.server_api_key:
            headers["Authorization"] = f"Bearer {self._config.server_api_key}"
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return 200 <= resp.status < 300
        except urllib.error.URLError as exc:
            logger.error("Server unreachable: %s", exc)
            return False
        except OSError as exc:
            logger.error("Network error: %s", exc)
            return False

    def _collect_baseline_hashes(self) -> dict[str, str]:
        """Collect baseline hashes for all tables with baselines."""
        from edr.agent.baseline import BaselineStore
        store = BaselineStore(self._config.baseline_dir)
        hashes = {}
        baseline_dir = self._config.baseline_dir
        if not baseline_dir.exists():
            return hashes
        for fpath in baseline_dir.iterdir():
            if fpath.name.startswith("baseline_") and fpath.suffix == ".json":
                table_name = fpath.name.removeprefix("baseline_").removesuffix(".json")
                hashes[table_name] = store.snapshot_hash(table_name)
        return hashes

    @property
    def queued_count(self) -> int:
        """Count queued alert files."""
        return len(self._collect_queued())
