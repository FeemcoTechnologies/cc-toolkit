"""Agent configuration management."""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Optional, Union

logger = logging.getLogger(__name__)

if sys.platform == "win32":
    DEFAULT_CONFIG_DIR = Path("C:\\ProgramData\\cc-edr")
else:
    DEFAULT_CONFIG_DIR = Path("/etc/cc-edr")

DEFAULT_CONFIG = {
    "device_uuid": None,
    "server_url": "",
    "server_api_key": "",
    "checkin_interval_seconds": 43200,
    "osquery_path": "osqueryi",
    "rules_dir": "",
    "baseline_dir": "",
    "alert_queue_dir": "",
    "compression": "zstd",
    "offline_mode": False,
    "vpn_interface": "wg0",
    "public_endpoint": "",
    "cache_max_age_hours": 72,
    "response_actions_enabled": False,
}


def _try_load_yaml(path: Path):
    """Try PyYAML first, fall back to basic parser."""
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except ImportError:
        pass
    return _basic_yaml_parse(path)


def _basic_yaml_parse(path: Path) -> dict:
    """Minimal YAML parser for our config subset."""
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
            elif val.isdigit() or (val.startswith("-") and val[1:].isdigit()):
                result[key] = int(val)
            else:
                result[key] = val.strip("\"'")
    return result


def _try_save_yaml(data: dict, path: Path):
    """Try PyYAML first, fall back to simple key-value."""
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
    _atomic_write(path, "\n".join(lines) + "\n")


def _atomic_write(path: Path, content: str):
    """Write atomically via temp file + rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


class AgentConfig:
    """Manages agent configuration from YAML file."""

    def __init__(self, config_path: str | Path | None = None):
        if config_path is None:
            config_path = DEFAULT_CONFIG_DIR / "config.yaml"
        self.config_path = Path(config_path)
        self._data: dict = dict(DEFAULT_CONFIG)
        self._response_actions: dict = {}
        self._load()

    def _load(self):
        if self.config_path.exists():
            loaded = _try_load_yaml(self.config_path)
            if loaded:
                for k in DEFAULT_CONFIG:
                    if k in loaded:
                        self._data[k] = loaded[k]
        if not self._data.get("device_uuid"):
            self._data["device_uuid"] = str(uuid.uuid4())
            self._save()
        dirs_to_create = [
            self._data.get("rules_dir"),
            self._data.get("baseline_dir"),
            self._data.get("alert_queue_dir"),
        ]
        for d in dirs_to_create:
            if d:
                Path(d).mkdir(parents=True, exist_ok=True)
        self._load_response_actions()

    def _load_response_actions(self):
        if not self._data.get("baseline_dir"):
            return
        ra_path = Path(self._data["baseline_dir"]).parent / "response_actions.yaml"
        if ra_path.exists():
            self._response_actions = _try_load_yaml(ra_path) or {}

    def _save(self):
        _try_save_yaml(self._data, self.config_path)

    @property
    def device_uuid(self) -> str:
        return self._data["device_uuid"]

    @property
    def server_url(self) -> str:
        return self._data.get("server_url", "")

    @property
    def server_api_key(self) -> str:
        return self._data.get("server_api_key", "")

    @property
    def checkin_interval(self) -> int:
        return int(self._data.get("checkin_interval_seconds", 43200))

    @property
    def osquery_path(self) -> str:
        return self._data.get("osquery_path", "osqueryi")

    @property
    def rules_dir(self) -> Path:
        return Path(self._data.get("rules_dir", ""))

    @property
    def baseline_dir(self) -> Path:
        return Path(self._data.get("baseline_dir", ""))

    @property
    def alert_queue_dir(self) -> Path:
        return Path(self._data.get("alert_queue_dir", ""))

    @property
    def compression(self) -> str:
        return self._data.get("compression", "zstd")

    @property
    def offline_mode(self) -> bool:
        return bool(self._data.get("offline_mode", False))

    @property
    def vpn_interface(self) -> str:
        return self._data.get("vpn_interface", "wg0")

    @property
    def public_endpoint(self) -> str:
        return self._data.get("public_endpoint", "")

    @property
    def cache_max_age_hours(self) -> int:
        return int(self._data.get("cache_max_age_hours", 72))

    @property
    def response_actions_enabled(self) -> bool:
        return bool(self._data.get("response_actions_enabled", False))

    @property
    def response_actions(self) -> dict:
        return dict(self._response_actions)

    @property
    def raw(self) -> dict:
        return dict(self._data)

    def set(self, key: str, value):
        self._data[key] = value
        self._save()

    def update_from_dict(self, data: dict):
        self._data.update(data)
        self._save()

    def validate(self) -> list[str]:
        """Validate config: create missing dirs, check osquery. Returns warnings."""
        warnings = []
        for field in ("rules_dir", "baseline_dir", "alert_queue_dir"):
            p = Path(self._data.get(field, ""))
            if not p.exists():
                p.mkdir(parents=True, exist_ok=True)
                warnings.append(f"Created missing directory: {p}")
        if not self._data.get("server_url"):
            warnings.append("server_url is not configured")
        try:
            result = subprocess.run(
                [self.osquery_path, "--version"],
                capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if result.returncode != 0:
                warnings.append(f"osquery returned non-zero exit: {result.returncode}")
        except FileNotFoundError:
            warnings.append(f"osquery not found at '{self.osquery_path}'")
        except subprocess.TimeoutExpired:
            warnings.append("osquery --version timed out")
        except OSError as exc:
            warnings.append(f"Cannot execute osquery: {exc}")
        return warnings
