"""Caido DAST client (live GraphQL integration).

Caido (https://caido.io) runs its JSON GraphQL endpoint at ``<base_url>/graphql``.
This client authenticates two ways:

1. A UI-minted API key (settings -> API keys) used directly as a Bearer token.
2. The OAuth2 device flow against Caido Cloud using a Personal Access Token
   (PAT, ``caido_...``). The PAT itself is never stored in the git repo; it
   lives in the (non-synced) config file ``~/.config/kali-command-center/config.json``
   under ``caido_api_token``. Access/refresh tokens are cached to
   ``~/.config/kali-command-center/caido_tokens.json`` and auto-refreshed.

Live capabilities (all verified against Caido 0.57.x):
- ``detect()``: probe ``/graphql`` and report API + auth status.
- ``list_workflows()`` / ``get_workflow()`` / ``toggle_workflow()``.
- ``create_request(url)``: materialise a target as a sitemap request (with an
  optional synthetic response so ACTIVE workflows actually execute).
- ``run_active_workflow()`` / ``run_workflow_on_url()``: trigger a workflow.
- ``list_findings()`` / ``count_findings()``: read findings back (reporter is
  set by the workflow, e.g. ``CORSMisconfig`` for the CORS Checker workflow).

The offline import workflow (parsing a Caido JSON export) is still handled by
:func:`modules.tool_wrappers.caido_import_json`.
"""

from __future__ import annotations

import base64
import json
import re
import time
import urllib.parse
from pathlib import Path
from typing import Optional

import requests
from cryptography.fernet import Fernet

DEFAULT_CLOUD_URL = "https://api.caido.io"

_SEVERITY_KEYWORDS = [
    ("critical", ("critical", "rce", "remote code execution", "unauthenticated rce")),
    ("high", ("high", "sql injection", "sqli", "command injection", "shell injection",
              "arbitrary file", "path traversal", "ssrf", "xxe", "deserialization")),
    ("medium", ("medium", "misconfig", "misconfiguration", "xss", "open redirect",
                "csrf", "information disclosure", "weak")),
    ("low", ("low", "info", "fingerprint", "version disclosure", "cookie")),
]


def _severity_from(text: str) -> str:
    t = (text or "").lower()
    for sev, kws in _SEVERITY_KEYWORDS:
        if any(k in t for k in kws):
            return sev
    return "info"


# ── Fernet helpers (token cache at rest) ────────────────────────────────────

def _vault_key() -> bytes:
    """Same vault-key convention as modules.asset_tracker: CC_VAULT_KEY env or
    ~/.config/kali-command-center/.vault_key (auto-generated on first use)."""
    import os
    env = os.environ.get("CC_VAULT_KEY")
    if env:
        return env.encode() if isinstance(env, str) else env
    key_file = Path.home() / ".config" / "kali-command-center" / ".vault_key"
    if key_file.exists():
        return key_file.read_bytes()
    key = Fernet.generate_key()
    key_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.write_bytes(key)
    try:
        key_file.chmod(0o600)
    except OSError:
        pass
    return key


def _encrypt_token(value: str) -> str:
    if not value:
        return ""
    return Fernet(_vault_key()).encrypt(value.encode()).decode()


def _decrypt_token(value: str) -> str:
    if not value:
        return ""
    try:
        return Fernet(_vault_key()).decrypt(value.encode()).decode()
    except Exception:
        return ""


class CaidoError(Exception):
    """Raised when Caido returns a GraphQL error or is unreachable."""


class CaidoClient:
    def __init__(self, base_url: str = "http://192.168.56.1:8080",
                 api_key: str = "",
                 api_token: str = "",
                 cloud_url: str = DEFAULT_CLOUD_URL,
                 token_cache: Optional[str] = None,
                 timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.api_key = (api_key or "").strip()
        self.api_token = (api_token or "").strip()
        self.cloud_url = cloud_url.rstrip("/")
        self.timeout = timeout
        self._graphql_url = f"{self.base_url}/graphql"
        if token_cache is None:
            token_cache = str(Path.home() / ".config" / "kali-command-center" / "caido_tokens.json")
        self._token_cache = token_cache
        self._access_token: Optional[str] = None
        self._session = requests.Session()

    # ------------------------------------------------------------------ raw
    def _gql(self, query: str, variables: Optional[dict] = None,
             token: Optional[str] = None) -> dict:
        headers = {"Content-Type": "application/json"}
        if token is None:
            tok = self._access_token or self._get_token()
        elif token:
            tok = token
        else:
            tok = None
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        try:
            r = self._session.post(self._graphql_url,
                                   json={"query": query, "variables": variables or {}},
                                   headers=headers, timeout=self.timeout)
        except requests.RequestException as e:
            raise CaidoError(f"unreachable: {e}") from e
        try:
            j = r.json()
        except ValueError:
            raise CaidoError(f"non-JSON response ({r.status_code}): {r.text[:200]}")
        if "errors" in j:
            errs = "; ".join(e.get("message", str(e)) for e in j["errors"])
            raise CaidoError(f"graphql error: {errs}")
        if r.status_code >= 400 and not j.get("data"):
            raise CaidoError(f"http {r.status_code}: {json.dumps(j)[:200]}")
        return j.get("data") or {}

    @staticmethod
    def _first(data: dict, *path, default=None):
        cur = data
        for k in path:
            if not isinstance(cur, dict):
                return default
            cur = cur.get(k)
        return cur if cur is not None else default

    # ----------------------------------------------------------------- auth
    def _load_cache(self) -> dict:
        try:
            data = json.loads(Path(self._token_cache).read_text())
        except Exception:
            return {}
        for k in ("access_token", "refresh_token"):
            raw = data.get(k)
            if not raw:
                continue
            dec = _decrypt_token(raw)
            if dec:
                # current format: Fernet-encrypted
                data[k] = dec
            # else: legacy plaintext value from an older version — keep as-is
        return data

    def _save_cache(self, tok: dict) -> None:
        Path(self._token_cache).parent.mkdir(parents=True, exist_ok=True)
        Path(self._token_cache).write_text(json.dumps({
            "access_token": _encrypt_token(tok.get("accessToken")),
            "refresh_token": _encrypt_token(tok.get("refreshToken")),
            "expires_at": self._epoch(tok.get("expiresAt")),
        }))

    @staticmethod
    def _epoch(iso: Optional[str]) -> Optional[float]:
        if not iso:
            return None
        try:
            from datetime import datetime, timezone
            dt = iso.replace("Z", "+00:00")
            return datetime.fromisoformat(dt).astimezone(timezone.utc).timestamp()
        except Exception:
            return None

    def _refresh_token(self, refresh_token: str) -> Optional[str]:
        try:
            data = self._gql(
                """mutation Refresh($refreshToken: String!) {
                    refreshAuthenticationToken(refreshToken: $refreshToken) {
                        token { accessToken refreshToken expiresAt }
                    }
                }""", {"refreshToken": refresh_token}, token="")
        except CaidoError:
            return None
        tok = self._first(data, "refreshAuthenticationToken", "token")
        if not tok or not tok.get("accessToken"):
            return None
        self._save_cache(tok)
        self._access_token = tok["accessToken"]
        return tok["accessToken"]

    def _device_flow(self) -> str:
        if not self.api_token:
            raise CaidoError("no Caido PAT configured (set caido_api_token in config.json)")
        try:
            import websocket  # websocket-client
        except ImportError:
            raise CaidoError("websocket-client not installed; pip install websocket-client")
        data = self._gql("""mutation {
            startAuthenticationFlow {
                request { id userCode verificationUrl expiresAt }
                error { __typename }
            }
        }""", token="")
        req = self._first(data, "startAuthenticationFlow", "request")
        if not req or not req.get("userCode"):
            raise CaidoError("failed to start Caido authentication flow")
        try:
            r = self._session.get(
                f"{self.cloud_url}/oauth2/device/information",
                params={"user_code": req["userCode"]},
                headers={"Authorization": f"Bearer {self.api_token}"}, timeout=30)
            info = r.json()
            scopes = ",".join(s.get("name", "") for s in (info.get("scopes") or []))
            self._session.post(
                f"{self.cloud_url}/oauth2/device/approve",
                params={"user_code": req["userCode"], "scope": scopes},
                headers={"Authorization": f"Bearer {self.api_token}",
                         "Content-Type": "application/json"}, timeout=30)
        except requests.RequestException as e:
            raise CaidoError(f"Caido Cloud approval failed: {e}") from e

        parsed = urllib.parse.urlparse(self.base_url)
        ws_host = parsed.hostname or "127.0.0.1"
        ws_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        ws_url = f"ws://{ws_host}:{ws_port}/ws/graphql"
        try:
            ws = websocket.create_connection(ws_url, subprotocols=["graphql-transport-ws"],
                                             timeout=120)
            ws.settimeout(60)
            ws.send(json.dumps({"type": "connection_init", "payload": {}}))
            sub = {"id": "1", "type": "subscribe", "payload": {
                "query": """subscription CreatedAuthenticationToken($requestId: ID!) {
                    createdAuthenticationToken(requestId: $requestId) {
                        token { accessToken expiresAt refreshToken scopes }
                        error { __typename }
                    }
                }""", "variables": {"requestId": req["id"]}}}
            sent = False
            while True:
                msg = json.loads(ws.recv())
                t = msg.get("type")
                if t == "connection_ack" and not sent:
                    ws.send(json.dumps(sub))
                    sent = True
                elif t == "next":
                    tok = self._first(msg, "payload", "data",
                                      "createdAuthenticationToken", "token")
                    ws.close()
                    if not tok or not tok.get("accessToken"):
                        raise CaidoError("device flow did not return an access token")
                    self._save_cache(tok)
                    self._access_token = tok["accessToken"]
                    return tok["accessToken"]
        except CaidoError:
            raise
        except Exception as e:  # ws errors
            raise CaidoError(f"device flow websocket failed: {e}") from e

    def _get_token(self) -> Optional[str]:
        if self.api_key:
            return self.api_key
        if self._access_token:
            return self._access_token
        cache = self._load_cache()
        exp = cache.get("expires_at")
        if cache.get("access_token") and (not exp or time.time() < exp - 300):
            self._access_token = cache["access_token"]
            return self._access_token
        if cache.get("refresh_token"):
            tok = self._refresh_token(cache["refresh_token"])
            if tok:
                return tok
        return self._device_flow()

    # -------------------------------------------------------------- detect
    def detect(self, timeout: int = 8) -> dict:
        """Probe the GraphQL endpoint and report API + auth status."""
        base_up = False
        try:
            r = self._session.get(self.base_url, timeout=timeout)
            ui = r.status_code
        except requests.RequestException:
            ui = 0
        out = {"base_url": self.base_url, "web_ui": ui,
               "api_reachable": False, "auth_ok": False,
               "version": "", "workflows": [], "error": ""}
        try:
            data = self._gql("{ __typename }", token="")
            base_up = data.get("__typename") == "QueryRoot"
        except CaidoError as e:
            out["error"] = str(e)
        out["api_reachable"] = base_up
        if not base_up:
            return out
        try:
            self._gql("{ viewer { __typename } }")
            out["auth_ok"] = True
        except CaidoError:
            out["auth_ok"] = False
        try:
            wfs = self.list_workflows()
            out["workflows"] = wfs
        except Exception:
            pass
        return out

    # ----------------------------------------------------------- workflows
    def list_workflows(self) -> list:
        data = self._gql("""query {
            workflows { id name kind enabled }
        }""")
        return self._first(data, "workflows", default=[]) or []

    def get_workflow(self, workflow_id: str) -> dict:
        data = self._gql("""query Workflow($id: ID!) {
            workflow(id: $id) { id name kind enabled definition }
        }""", {"id": workflow_id})
        return self._first(data, "workflow", default={}) or {}

    def toggle_workflow(self, workflow_id: str, enabled: bool) -> dict:
        data = self._gql("""mutation Toggle($id: ID!, $enabled: Boolean!) {
            toggleWorkflow(id: $id, enabled: $enabled) { id enabled }
        }""", {"id": workflow_id, "enabled": enabled})
        return self._first(data, "toggleWorkflow", default={}) or {}

    def active_workflows(self) -> list:
        return [w for w in self.list_workflows()
                if w.get("kind") == "ACTIVE" and w.get("enabled")]

    def pick_active_workflow(self) -> Optional[dict]:
        """Best enabled ACTIVE workflow: prefer a CORS checker, else the first."""
        active = self.active_workflows()
        if not active:
            return None
        for w in active:
            if "cors" in (w.get("name") or "").lower():
                return w
        return active[0]

    # -------------------------------------------------------------- requests
    @staticmethod
    def _parse_url(url: str) -> dict:
        u = urllib.parse.urlparse(url.strip())
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError(f"invalid URL: {url}")
        is_tls = u.scheme == "https"
        port = u.port or (443 if is_tls else 80)
        path = u.path or "/"
        query = u.query or ""
        host = u.hostname
        return {"host": host, "port": port, "path": path, "query": query,
                "is_tls": is_tls, "scheme": u.scheme}

    def _build_raw_request(self, meta: dict, method: str,
                           headers: Optional[dict],
                           body: Optional[str]) -> str:
        host = meta["host"]
        port = meta["port"]
        default_port = 443 if meta["is_tls"] else 80
        host_hdr = host if port == default_port else f"{host}:{port}"
        lines = [f"{method} {meta['path']}" +
                 (f"?{meta['query']}" if meta["query"] else "") +
                 " HTTP/1.1", f"Host: {host_hdr}",
                 "User-Agent: Kali-Command-Center/1.0", "Accept: */*"]
        for k, v in (headers or {}).items():
            # Strip CR/LF from names and values — raw request text goes
            # straight into Caido, so embedded newlines would allow header
            # injection / request smuggling.
            k = re.sub(r"[\r\n]", "", str(k))
            v = re.sub(r"[\r\n]", "", str(v))
            lines.append(f"{k}: {v}")
        if body:
            lines.append(f"Content-Length: {len(body.encode('utf-8'))}")
        lines.append("Connection: close")
        raw = "\r\n".join(lines) + "\r\n\r\n"
        if body:
            raw += body
        return raw

    def create_request(self, url: str, method: str = "GET",
                       headers: Optional[dict] = None,
                       body: Optional[str] = None,
                       with_response: bool = True) -> dict:
        meta = self._parse_url(url)
        raw_req = self._build_raw_request(meta, method, headers, body)
        inp = {
            "host": meta["host"], "method": method, "path": meta["path"],
            "query": meta["query"], "port": meta["port"],
            "isTls": meta["is_tls"], "source": "INTERCEPT", "alteration": "NONE",
            "raw": base64.b64encode(raw_req.encode()).decode(),
        }
        if with_response:
            resp_raw = ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                        "Content-Length: 2\r\nConnection: close\r\n\r\n{}")
            inp["response"] = {
                "statusCode": 200,
                "raw": base64.b64encode(resp_raw.encode()).decode(),
                "source": "INTERCEPT", "alteration": "NONE", "roundtripTime": 5,
            }
        data = self._gql("""mutation Create($input: CreateRequestInput!) {
            createRequest(input: $input) { id }
        }""", {"input": inp})
        request_id = self._first(data, "createRequest", "id")
        if not request_id:
            raise CaidoError("createRequest returned no id")
        return {**meta, "request_id": request_id, "url": url}

    # ------------------------------------------------------------- workflow run
    def run_active_workflow(self, workflow_id: str, request_id: str) -> dict:
        data = self._gql("""mutation Run($id: ID!, $input: RunActiveWorkflowInput!) {
            runActiveWorkflow(id: $id, input: $input) {
                task { id createdAt workflow { id name } }
                error { __typename }
            }
        }""", {"id": workflow_id, "input": {"requestId": request_id}})
        task = self._first(data, "runActiveWorkflow", "task") or {}
        err = self._first(data, "runActiveWorkflow", "error")
        if err:
            raise CaidoError(f"workflow run failed: {err}")
        return {
            "task_id": task.get("id"),
            "workflow_id": self._first(task, "workflow", "id"),
            "workflow_name": self._first(task, "workflow", "name"),
            "created_at": task.get("createdAt"),
        }

    def run_workflow_on_url(self, url: str, workflow_id: Optional[str] = None,
                            method: str = "GET",
                            headers: Optional[dict] = None,
                            body: Optional[str] = None) -> dict:
        """Materialise ``url`` as a sitemap request and run an ACTIVE workflow.

        Picks the best enabled ACTIVE workflow (CORS checker preferred) unless
        ``workflow_id`` is given. Returns a scan descriptor usable as scan_id.
        """
        if not workflow_id:
            wf = self.pick_active_workflow()
            if not wf:
                raise CaidoError("no enabled ACTIVE workflow to run")
            workflow_id = wf["id"]
            workflow_name = wf.get("name", "")
        else:
            wf = self.get_workflow(workflow_id)
            workflow_name = wf.get("name", workflow_id)
        meta = self.create_request(url, method=method, headers=headers,
                                   body=body, with_response=True)
        run = self.run_active_workflow(workflow_id, meta["request_id"])
        return {
            "scan_id": meta["request_id"],
            "request_id": meta["request_id"],
            "host": meta["host"],
            "url": url,
            "workflow_id": run["workflow_id"],
            "workflow_name": run["workflow_name"],
            "reporter": self._resolve_reporter(run["workflow_name"] or workflow_name),
            "task_id": run["task_id"],
            "started_at": time.time(),
        }

    # --------------------------------------------------------------- findings
    # Reporter hint map: workflow name -> reporter used by its findings.
    _REPORTER_HINTS = {
        "cors": "CORSMisconfig",
    }

    def finding_reporters(self) -> list:
        data = self._gql("{ findingReporters }")
        return self._first(data, "findingReporters", default=[]) or []

    def _resolve_reporter(self, workflow_name: str) -> Optional[str]:
        """Map a workflow name to its findings reporter. Uses a hint map first,
        then a token-overlap scan of the live ``findingReporters`` list."""
        name = (workflow_name or "").lower()
        for kw, reporter in self._REPORTER_HINTS.items():
            if kw in name:
                return reporter
        reporters = self.finding_reporters()
        for r in reporters:
            rl = (r or "").lower()
            for tok in name.split():
                if len(tok) > 2 and tok in rl:
                    return r
        return None

    def list_findings(self, reporter: Optional[str] = None,
                      host: Optional[str] = None,
                      since_epoch_ms: Optional[int] = None,
                      limit: int = 500) -> list:
        """Fetch findings, newest-first when ``reporter`` is given (fast: the
        reporter sets are small, so ordering is cheap and ``since_epoch_ms``
        short-circuits). Without a reporter we cannot sort server-side, so the
        generic scan is bounded by ``_MAX_GENERIC_PAGES`` pages."""
        page = 100
        max_pages = 20 if not reporter else 10000
        out = []
        cur = 0
        pages = 0
        while len(out) < limit:
            filter_arg = ", filter: { reporter: $reporter }" if reporter else ""
            order_arg = ", order: { by: CREATED_AT, ordering: DESC }" if reporter else ""
            variables = {"limit": page, "offset": cur}
            if reporter:
                variables["reporter"] = reporter
            data = self._gql(f"""query Findings($limit: Int!, $offset: Int!{', $reporter: String' if reporter else ''}) {{
                findingsByOffset(limit: $limit, offset: $offset{filter_arg}{order_arg}) {{
                    edges {{ node {{
                        id title description host path reporter hidden createdAt
                    }} }}
                }}
            }}""", variables)
            edges = self._first(data, "findingsByOffset", "edges") or []
            if not edges:
                break
            for e in edges:
                n = e.get("node") or {}
                fh = n.get("host")
                try:
                    ts = int(n.get("createdAt") or 0)
                except (TypeError, ValueError):
                    ts = 0
                if since_epoch_ms and ts and ts < since_epoch_ms:
                    if reporter:
                        return out
                    continue
                if host and fh and fh != host:
                    continue
                out.append({
                    "id": n.get("id"),
                    "title": n.get("title"),
                    "description": n.get("description"),
                    "host": fh,
                    "path": n.get("path"),
                    "reporter": n.get("reporter"),
                    "severity": _severity_from(n.get("title") or n.get("reporter") or ""),
                    "created_at_ms": ts,
                })
                if len(out) >= limit:
                    out.sort(key=lambda f: f["created_at_ms"] or 0, reverse=True)
                    return out
            cur += page
            pages += 1
            if len(edges) < page or pages >= max_pages:
                break
        out.sort(key=lambda f: f["created_at_ms"] or 0, reverse=True)
        return out

    def count_findings(self, reporter: Optional[str] = None,
                       host: Optional[str] = None,
                       since_epoch_ms: Optional[int] = None) -> int:
        data = self._gql("""query Count {
            findingsByOffset(limit: 1) { count { value } }
        }""")
        total = self._first(data, "findingsByOffset", "count", "value", default=0)
        if not host and not reporter and not since_epoch_ms:
            return int(total or 0)
        if reporter:
            return len(self.list_findings(reporter=reporter, host=host,
                                          since_epoch_ms=since_epoch_ms,
                                          limit=1000))
        # Generic path: diff across reporters with small sets. Reporters holding
        # tens of thousands of findings would make the newest-first sort crawl,
        # so we skip them here (the primary flow always resolves the reporter).
        big = 5000
        n = 0
        for r in self.finding_reporters():
            data = self._gql("""query Count($reporter: String) {
                findingsByOffset(limit: 1, filter: { reporter: $reporter }) {
                    count { value }
                }
            }""", {"reporter": r})
            rc = int(self._first(data, "findingsByOffset", "count", "value", default=0) or 0)
            if rc and rc > big:
                continue
            n += len(self.list_findings(reporter=r, host=host,
                                        since_epoch_ms=since_epoch_ms,
                                        limit=1000))
        return n

    def create_finding(self, request_id: str, title: str, reporter: str,
                       description: str = "", dedupe_key: str = "") -> dict:
        inp = {"title": title, "reporter": reporter}
        if description:
            inp["description"] = description
        if dedupe_key:
            inp["dedupeKey"] = dedupe_key
        data = self._gql("""mutation CreateFinding($requestId: ID, $input: CreateFindingInput!) {
            createFinding(requestId: $requestId, input: $input) { id }
        }""", {"requestId": request_id, "input": inp})
        return self._first(data, "createFinding", default={}) or {}
