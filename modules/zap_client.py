"""OWASP ZAP DAST client (ZAP 2.x REST/JSON API) with daemon auto-start.

Uses plain HTTP/JSON so it works wherever ZAP runs (local Kali daemon or a
remote instance). If ``ensure_running`` is used and no ZAP answers at
``api_url``, it launches ``zaproxy -daemon`` in the background and waits for
the API to come up.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

import requests


class ZapClient:
    def __init__(self, api_url: str = "http://127.0.0.1:8080",
                 api_key: str = ""):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self._s = requests.Session()

    # -- transport ---------------------------------------------------------
    def _json(self, component: str, kind: str, action: str,
              params: Optional[dict] = None, timeout: int = 60) -> dict:
        if kind not in ("view", "action"):
            raise ValueError("kind must be view or action")
        url = f"{self.api_url}/JSON/{component}/{kind}/{action}/"
        data = dict(params or {})
        if self.api_key:
            data["apikey"] = self.api_key
        r = self._s.get(url, params=data, timeout=timeout)
        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text[:400]}
        if isinstance(body, dict) and body.get("code") not in (None, 200) and not body.get("result"):
            return {"error": body.get("message") or body.get("raw") or r.text[:400]}
        return body

    def _post(self, component: str, kind: str, action: str,
              params: Optional[dict] = None, timeout: int = 60) -> dict:
        if kind not in ("view", "action"):
            raise ValueError("kind must be view or action")
        url = f"{self.api_url}/JSON/{component}/{kind}/{action}/"
        data = dict(params or {})
        if self.api_key:
            data["apikey"] = self.api_key
        try:
            r = self._s.post(url, data=data, timeout=timeout)
            return r.json()
        except Exception as e:
            return {"error": str(e)}

    # -- lifecycle ---------------------------------------------------------
    def health(self, timeout: int = 8) -> dict:
        try:
            v = self._json("core", "view", "version", timeout=timeout)
            return {"status": "ok", "version": v.get("version", "?")}
        except requests.ConnectionError:
            return {"status": "unreachable", "error": f"{self.api_url} not reachable"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def ensure_running(self, zap_bin: str = "zaproxy",
                       zap_dir: str = "", port: int = 0,
                       wait: int = 150, tmux_session: str = "zap") -> dict:
        """Ensure a ZAP API is reachable, starting a daemon if not.

        The daemon runs inside a detached tmux session named ``zap``
        (``tmux attach -t zap``) with output also teed to a log file. If tmux
        is unavailable, falls back to a plain detached background process.
        """
        h = self.health()
        if h.get("status") == "ok":
            return h
        binp = shutil.which(zap_bin)
        if not binp:
            return {"status": "error", "error": f"zap binary not found: {zap_bin}"}
        port = port or int(self.api_url.rsplit(":", 1)[-1])
        host = "127.0.0.1"
        zap_data = zap_dir or str(Path.home() / ".zap-kcc")
        key = self.api_key or "changeme"
        self.api_key = key
        args = [
            binp, "-daemon", "-host", host, "-port", str(port),
            "-config", f"api.key={key}",
            "-config", "api.disablekey=false",
            "-config", "api.addrs.addr.name=.*",
            "-config", "api.addrs.addr.regex=true",
            "-config", "extension.autoupdate.checkonstart=false",
            "-config", "extension.autoupdate.download=false",
            "-dir", zap_data,
        ]
        tmux_bin = shutil.which("tmux")
        try:
            if tmux_bin:
                # Replace any stale session with the same name.
                subprocess.run([tmux_bin, "kill-session", "-t", tmux_session],
                               capture_output=True, check=False, timeout=20)
                run_cmd = shlex.join(args) + " 2>&1 | tee " + \
                    shlex.quote(str(Path(zap_data + "-tmux.log")))
                subprocess.run(
                    [tmux_bin, "new-session", "-d", "-s", tmux_session, run_cmd],
                    capture_output=True, timeout=30)
                self._tmux_session = tmux_session
            else:
                with open(Path(zap_data + "-stdout.log"), "w") as out, \
                     open(Path(zap_data + "-stderr.log"), "w") as err:
                    proc = subprocess.Popen(args, stdout=out, stderr=err,
                                            start_new_session=True)
                self._proc = proc
        except Exception as e:
            return {"status": "error", "error": str(e)}
        deadline = time.time() + wait
        while time.time() < deadline:
            h = self.health()
            if h.get("status") == "ok":
                return {**h, "started": True,
                        "pid": self._zap_pid(port),
                        "tmux": tmux_session if tmux_bin else None}
            time.sleep(2)
        return {"status": "error", "error": f"ZAP daemon did not become ready within {wait}s",
                "log": str(Path(zap_data + "-stderr.log"))}

    @staticmethod
    def _zap_pid(port: int) -> int:
        try:
            r = subprocess.run(
                ["pgrep", "-f", f"zaproxy.*-port {port}"],
                capture_output=True, text=True, timeout=10)
            pids = [int(p) for p in r.stdout.split() if p.strip()]
            for pid in pids:
                try:
                    cmd = Path(f"/proc/{pid}/cmdline").read_bytes().decode(errors="ignore")
                except Exception:
                    continue
                if "-jar" in cmd or "java" in cmd.split("\x00")[0]:
                    return pid
            return pids[0] if pids else 0
        except Exception:
            return 0

    # -- session / scope ---------------------------------------------------
    def new_session(self, name: str = "cc-toolkit", overwrite: bool = True) -> dict:
        return self._post("core", "action", "newSession",
                          {"name": name, "overwrite": str(overwrite).lower()})

    def import_url(self, url: str) -> dict:
        """Add a URL to the session so ZAP will stay in scope for it."""
        return self._post("core", "action", "accessUrl",
                          {"url": url, "followRedirects": "false"})

    # -- spider / active scan ---------------------------------------------
    def spider_start(self, url: str, max_children: int = 0,
                     recurse: bool = True) -> dict:
        r = self._post("spider", "action", "scan", {
            "url": url, "maxChildren": str(max_children),
            "recurse": str(recurse).lower(),
            "subtreeOnly": "false"})
        if "error" in r:
            return r
        return {"scan_id": r.get("scanid") or r.get("scan", ""), "started": True}

    def spider_status(self, scan_id: str) -> dict:
        r = self._json("spider", "view", "status", {"scanId": scan_id})
        if "error" in r:
            return r
        return {"status": r.get("status", "0")}

    def ajax_spider_start(self, url: str) -> dict:
        r = self._post("ajaxSpider", "action", "scan", {"url": url})
        if "error" in r:
            return r
        return {"started": True, "result": r.get("result", "")}

    def ajax_spider_status(self) -> dict:
        r = self._json("ajaxSpider", "view", "status")
        if "error" in r:
            return r
        return {"status": r.get("status", "stopped")}

    def active_scan_start(self, url: str, recurse: bool = True,
                          policy: str = "", in_scope: bool = False) -> dict:
        params = {"url": url, "recurse": str(recurse).lower(),
                  "inScopeOnly": str(in_scope).lower()}
        if policy:
            params["scanPolicyName"] = policy
        r = self._post("ascan", "action", "scan", params)
        if "error" in r:
            return r
        return {"scan_id": r.get("scanid") or r.get("scan", ""), "started": True}

    def active_scan_status(self, scan_id: str) -> dict:
        r = self._json("ascan", "view", "status", {"scanId": scan_id})
        if "error" in r:
            return r
        return {"status": r.get("status", "0")}

    # -- results -----------------------------------------------------------
    def alerts(self, baseurl: str = "", risk: str = "",
               start: int = 0, count: int = 1000) -> list:
        """Fetch alerts; risk: High/Medium/Low/Informational (any) filters."""
        params = {"start": str(start), "count": str(count)}
        if baseurl:
            params["baseurl"] = baseurl
        if risk:
            risk_id = {"informational": "0", "info": "0", "low": "1",
                       "medium": "2", "high": "3"}.get(risk.lower())
            if risk_id:
                params["riskId"] = risk_id
        r = self._json("core", "view", "alerts", params, timeout=90)
        if "error" in r:
            return [r]
        alerts = r.get("alerts", [])
        if risk:
            wanted = risk.lower()
            alerts = [a for a in alerts
                      if (a.get("risk") or "").lower() == wanted]
        out = []
        for a in alerts:
            out.append({
                "risk": a.get("risk"),
                "confidence": a.get("confidence"),
                "url": a.get("url"),
                "name": a.get("alert"),
                "cwe": a.get("cweid"),
                "wasc": a.get("wascid"),
                "desc": (a.get("desc") or "")[:300],
                "solution": (a.get("solution") or "")[:200],
            })
        return out
