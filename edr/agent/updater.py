"""Config fetch, caching, and effective config resolution."""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

from edr.agent.config import AgentConfig

logger = logging.getLogger(__name__)


def _try_load_yaml(path: Path):
    """Load YAML with PyYAML or basic parser."""
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except ImportError:
        pass
    result = {}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if ":" not in stripped:
                continue
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip()
            if not val:
                result[key] = None
            elif val.lower() in ("true", "yes"):
                result[key] = True
            elif val.lower() in ("false", "no"):
                result[key] = False
            elif val.isdigit():
                result[key] = int(val)
            else:
                result[key] = val.strip("\"'")
    return result


def _try_save_yaml(data: dict, path: Path):
    """Save YAML with PyYAML or basic formatter."""
    try:
        import yaml
        with open(path, "w", encoding="utf-8") as fh:
            yaml.dump(data, fh, default_flow_style=False, sort_keys=False)
        return
    except ImportError:
        pass
    lines = []
    for k, v in data.items():
        if v is None:
            lines.append(f"{k}:")
        elif isinstance(v, bool):
            lines.append(f"{k}: {'true' if v else 'false'}")
        elif isinstance(v, (int, float)):
            lines.append(f"{k}: {v}")
        else:
            lines.append(f"{k}: \"{v}\"")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class ConfigUpdater:
    """Fetches config from server with caching and fallback."""

    def __init__(self, config: AgentConfig):
        self._config = config
        self._cache_path = config.baseline_dir / "config_cache.yaml"

    def fetch_config(self) -> dict | None:
        """Try VPN endpoint first, then public fallback."""
        device_uuid = self._config.device_uuid
        vpn_url = f"{self._config.server_url}/cfg/{device_uuid}"
        result = self._fetch_url(vpn_url)
        if result is not None:
            return result
        if self._config.public_endpoint:
            logger.info("VPN unreachable, trying public endpoint")
            pub_url = f"{self._config.public_endpoint}/cfg/{device_uuid}"
            result = self._fetch_url(pub_url)
            if result is not None:
                return result
        logger.warning("Could not fetch config from any endpoint")
        return None

    def _fetch_url(self, url: str) -> dict | None:
        """Fetch config from a single URL, handle decompression."""
        headers = {
            "Accept": "application/x-yaml, application/json, */*",
            "X-Device-UUID": self._config.device_uuid,
        }
        if self._config.server_api_key:
            headers["Authorization"] = f"Bearer {self._config.server_api_key}"
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = resp.read()
                content_type = resp.headers.get("Content-Type", "")
                if resp.status == 404:
                    logger.warning("Server returned 404 — device may not be registered")
                    return None
                if resp.status != 200:
                    logger.warning("Server returned HTTP %d", resp.status)
                    return None
                return self._parse_response(data, content_type)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                logger.warning("Server returned 404 for %s", url)
                return None
            logger.error("HTTP error fetching config: %s", exc)
        except urllib.error.URLError as exc:
            logger.error("Cannot reach %s: %s", url, exc)
        except OSError as exc:
            logger.error("Network error fetching config: %s", exc)
        return None

    def _parse_response(self, data: bytes, content_type: str) -> dict | None:
        """Parse server response as YAML or JSON."""
        if b"zstd" in data[:4]:
            try:
                import zstandard
                dctx = zstandard.ZstdDecompressor()
                data = dctx.decompress(data)
            except ImportError:
                logger.warning("Received zstd but zstandard not installed")
                return None
        try:
            return json.loads(data)
        except (json.JSONDecodeError, ValueError):
            pass
        try:
            import yaml
            return yaml.safe_load(data)
        except ImportError:
            pass
        tmp_path = self._config.baseline_dir / "_config_tmp.yaml"
        tmp_path.write_bytes(data)
        result = _try_load_yaml(tmp_path)
        tmp_path.unlink(missing_ok=True)
        return result

    def cache_config(self, config: dict):
        """Save config to cache file."""
        try:
            _try_save_yaml(config, self._cache_path)
            logger.debug("Cached config to %s", self._cache_path)
        except OSError as exc:
            logger.error("Failed to cache config: %s", exc)

    def load_cached_config(self) -> dict | None:
        """Load cached config if not expired."""
        if not self._cache_path.exists():
            return None
        try:
            mtime = self._cache_path.stat().st_mtime
            age_hours = (time.time() - mtime) / 3600
            if age_hours > self._config.cache_max_age_hours:
                logger.info("Cached config expired (%.1fh old)", age_hours)
                return None
            return _try_load_yaml(self._cache_path)
        except OSError as exc:
            logger.error("Failed to read cached config: %s", exc)
            return None

    def get_effective_config(self) -> dict:
        """Fetch from server, fall back to cache, fall back to defaults."""
        fetched = self.fetch_config()
        if fetched:
            self.cache_config(fetched)
            return fetched
        cached = self.load_cached_config()
        if cached:
            logger.info("Using cached config")
            return cached
        logger.info("Using default config")
        return {}

    def is_quarantined(self, config: dict) -> bool:
        """Check if device status is quarantined."""
        status = config.get("status", "normal")
        return status == "quarantined"
