"""Wrapper for Burp Suite Professional built-in REST API (Burp 2025+).

API structure:  http://<host>:<port>/<API-KEY>/v0.1/<endpoint>
"""

import logging
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)


class BurpClient:
    """Wrapper for Burp Suite Professional built-in REST API."""

    def __init__(self, api_url: str = "", api_key: str = "",
                 proxy_url: str = "", verify_tls: bool = False):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.proxy_url = proxy_url
        self.verify_tls = verify_tls
        self._session = requests.Session()
        self._session.headers.update({"Accept": "application/json"})
        # Built-in Burp REST API: key goes in URL path, not header

    def _base(self) -> str:
        """Build base URL with API key embedded in path."""
        return f"{self.api_url}/{self.api_key}/v0.1"

    def _get(self, path: str, **kw) -> requests.Response:
        kw.setdefault("timeout", 10)
        kw.setdefault("verify", self.verify_tls)
        return self._session.get(f"{self._base()}{path}", **kw)

    def _post(self, path: str, **kw) -> requests.Response:
        kw.setdefault("timeout", 30)
        kw.setdefault("verify", self.verify_tls)
        return self._session.post(f"{self._base()}{path}", **kw)

    def _put(self, path: str, **kw) -> requests.Response:
        kw.setdefault("timeout", 10)
        kw.setdefault("verify", self.verify_tls)
        return self._session.put(f"{self._base()}{path}", **kw)

    def _delete(self, path: str, **kw) -> requests.Response:
        kw.setdefault("timeout", 10)
        kw.setdefault("verify", self.verify_tls)
        return self._session.delete(f"{self._base()}{path}", **kw)

    # ------------------------------------------------------------------
    # Health / info
    # ------------------------------------------------------------------
    def health(self) -> dict:
        """Check Burp REST API is reachable. Hitting the root returns HTML docs."""
        try:
            r = self._session.get(f"{self.api_url}/{self.api_key}/v0.1/",
                                  timeout=5, verify=self.verify_tls)
            return {"status": "ok", "code": r.status_code,
                    "body": r.text[:300]}
        except requests.ConnectionError:
            return {"status": "unreachable",
                    "error": f"Cannot connect to {self.api_url}"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def versions(self) -> dict:
        """Built-in API doesn't have /versions; return the Burp version header if any."""
        try:
            r = self._session.get(f"{self.api_url}/{self.api_key}/v0.1/",
                                  timeout=5, verify=self.verify_tls)
            ver = r.headers.get("X-Burp-Version", "unknown")
            return {"burpVersion": ver, "apiVersion": "v0.1"}
        except Exception as e:
            return {"burpVersion": "unknown", "error": str(e)}

    # ------------------------------------------------------------------
    # Scan management
    # ------------------------------------------------------------------
    def scan_start(self, urls: list, scope: Optional[dict] = None,
                   scan_name: str = "", protocol: str = "https") -> dict:
        # Desktop Burp doesn't support the 'name' field
        payload: dict = {"urls": urls, "protocol": protocol}
        if scope:
            payload["scope"] = scope
        try:
            r = self._post("/scan", json=payload)
            if r.ok:
                # 201 Created → task_id in Location header: /scan/<id>
                loc = r.headers.get("Location", "")
                task_id = loc.split("/")[-1] if loc else ""
                return {"scan_id": task_id, "status": "created",
                        "location": loc}
            return {"error": r.text[:500]}
        except Exception as e:
            return {"error": str(e)}

    def scan_stop(self, scan_id: str) -> dict:
        """Built-in API: DELETE /scan/{id} to cancel."""
        try:
            r = self._delete(f"/scan/{scan_id}")
            return {"status": "ok"} if r.ok else {"error": r.text[:200]}
        except Exception as e:
            return {"error": str(e)}

    def scan_status(self, scan_id: str) -> dict:
        try:
            r = self._get(f"/scan/{scan_id}")
            return r.json() if r.ok else {"error": r.text[:200]}
        except Exception as e:
            return {"error": str(e)}

    def issues_list(self, scan_id: str, severity: str = "") -> list:
        """Issues are embedded in the scan status response under 'issue_events'."""
        status = self.scan_status(scan_id)
        if "error" in status:
            return [status]
        issues = status.get("issue_events", [])
        if severity:
            issues = [i for i in issues
                      if i.get("severity", "").lower() == severity.lower()]
        return issues

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------
    def config_set(self, config: dict) -> dict:
        """Set Burp configuration. Expects config dict like:
        {"configurations": [{"key": "...", "value": "..."}]}
        """
        payload = {"configuration_request": {"configurations": config.get("configurations", [])}}
        try:
            r = self._put("/configuration", json=payload)
            return {"status": "ok" if r.ok else "error",
                    "code": r.status_code}
        except Exception as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Proxy pass-through — send traffic through Burp proxy (port 4080)
    # ------------------------------------------------------------------
    def proxy_request(self, method: str, url: str, headers: Optional[dict] = None,
                      body: Any = None) -> dict:
        if not self.proxy_url:
            return {"error": "No proxy URL configured"}
        proxies = {"http": self.proxy_url, "https": self.proxy_url}
        try:
            r = requests.request(method, url, headers=headers, data=body,
                                 proxies=proxies, timeout=60,
                                 verify=self.verify_tls)
            return {"status_code": r.status_code, "headers": dict(r.headers),
                    "body": r.text[:10000], "size": len(r.content)}
        except Exception as e:
            return {"error": str(e)}
