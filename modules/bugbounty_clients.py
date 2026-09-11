"""Bug bounty platform integrations (HackerOne, Bugcrowd).

Provides encrypted credential storage, a normalized program/scope cache, and
case/asset import so bug bounty scope data can be pulled, browsed offline, and
pushed into the toolkit's case + asset inventory.

Normalized program schema (stored in CC_DIR/bb_cache.json):
  {
    "platform": "hackerone" | "bugcrowd" | "yeswehack" | "intigriti" | "immunefi",
    "slug": "handle/code used in the public URL",
    "name": "Program name",
    "url": "https://...",
    "state": "public" | "invite_only" | "disabled" | "unknown",
    "submission_state": "open" | "closed" | "unknown",
    "offers_bounties": bool | None,
    "currency": str | None,
    "rewards": [{"name": "...", "value": "..."}] | None,
    "in_scope": [{"asset_type", "identifier", "eligible_for_submission",
                   "eligible_for_bounty", "max_severity"}],
    "out_of_scope": [...],
    "last_refreshed": "ISO-8601"
  }

Credentials are stored encrypted in CC_DIR/bb_config.json using the same Fernet
vault as the asset inventory (see asset_tracker).
"""
import json
import re
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

import requests

from .asset_tracker import AssetTracker, _decrypt, _encrypt
from .case_manager import CaseManager
from .config import CC_DIR

BB_CONFIG_PATH = CC_DIR / "bb_config.json"
BB_CACHE_PATH = CC_DIR / "bb_cache.json"

HACKERONE_API = "https://api.hackerone.com/v1/hackers"
HACKERONE_SITE = "https://hackerone.com"
BUGCROWD_SITE = "https://bugcrowd.com"
BUGCROWD_MIRROR = ("https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/"
                   "main/data/bugcrowd_data.json")
YESWEHACK_API = "https://api.yeswehack.com"
YESWEHACK_SITE = "https://yeswehack.com"
INTIGRITI_API = "https://api.intigriti.com/external/researcher/v1"
INTIGRITI_SITE = "https://app.intigriti.com/researcher"
IMMUNEFI_BOUNTIES = "https://immunefi.com/public-api/bounties.json"
IMMUNEFI_SITE = "https://immunefi.com"

UA = "cc-toolkit/1.0 (+local bug bounty dashboard)"


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Credential + cache helpers ─────────────────────────────────────────────

def _load_json(path, default=None):
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return dict(default) if default else {}


def _save_json(path, data):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str, ensure_ascii=False),
                   encoding="utf-8")
    tmp.replace(path)


class _CredStore:
    """Encrypted platform credential storage in bb_config.json."""

    _lock = threading.Lock()

    def load(self) -> dict:
        with self._lock:
            return _load_json(BB_CONFIG_PATH, {})

    def save(self, cfg: dict):
        with self._lock:
            _save_json(BB_CONFIG_PATH, cfg)

    def get_platform(self, platform: str, with_secrets: bool = False) -> dict:
        cfg = self.load().get("platforms", {}).get(platform, {})
        out = dict(cfg)
        if not with_secrets:
            out.pop("token_enc", None)
            out.pop("client_secret_enc", None)
        else:
            if cfg.get("token_enc"):
                out["token"] = _decrypt(cfg["token_enc"])
            if cfg.get("client_secret_enc"):
                out["client_secret"] = _decrypt(cfg["client_secret_enc"])
        return out

    def set_platform(self, platform: str, updates: dict):
        cfg = self.load()
        plat = cfg.setdefault("platforms", {}).setdefault(platform, {})
        plat.update(updates)
        self.save(cfg)


_CREDS = _CredStore()


# ── HackerOne client (official REST API v2, basic auth with API token) ─────

class HackerOneClient:

    def __init__(self, identifier: str = "", token: str = ""):
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": UA,
        })
        if identifier and token:
            self.session.auth = (identifier, token)

    def _request(self, method: str, endpoint: str, params: dict = None) -> dict:
        url = f"{HACKERONE_API}/{endpoint}"
        resp = self.session.request(method, url, params=params, timeout=45)
        if resp.status_code in (401, 403):
            raise PermissionError(
                f"HackerOne {resp.status_code}: invalid/expired API token — "
                "regenerate at https://hackerone.com/settings/api_token/edit")
        if resp.status_code == 429:
            raise RuntimeError("HackerOne rate limited (429) — wait and retry")
        resp.raise_for_status()
        return resp.json()

    def _paginate(self, endpoint: str, params: dict = None) -> List[dict]:
        items: List[dict] = []
        page = 1
        while True:
            p = dict(params or {})
            p["page[number]"] = page
            data = self._request("GET", endpoint, params=p)
            items.extend(data.get("data", []) or [])
            if not data.get("links", {}).get("next") or not data.get("data"):
                break
            page += 1
        return items

    # -- programs --

    def list_programs(self) -> List[dict]:
        out = []
        for it in self._paginate("programs"):
            a = it.get("attributes", {})
            handle = a.get("handle", "")
            out.append({
                "platform": "hackerone",
                "slug": handle,
                "name": a.get("name", ""),
                "url": f"{HACKERONE_SITE}/{handle}" if handle else "",
                "state": self._simplify_state(a.get("state", "")),
                "submission_state": a.get("submission_state", "unknown"),
                "offers_bounties": a.get("offers_bounties"),
                "currency": a.get("currency"),
                "rewards": None,
                "in_scope": [],
                "out_of_scope": [],
                "last_refreshed": _utcnow(),
            })
        return out

    def get_program(self, handle: str) -> dict:
        it = self._request("GET", f"programs/{handle}").get("data", {})
        a = it.get("attributes", {})
        return {
            "platform": "hackerone",
            "slug": handle,
            "name": a.get("name", handle),
            "url": f"{HACKERONE_SITE}/{handle}",
            "state": self._simplify_state(a.get("state", "")),
            "submission_state": a.get("submission_state", "unknown"),
            "offers_bounties": a.get("offers_bounties"),
            "currency": a.get("currency"),
            "rewards": None,
            "in_scope": [],
            "out_of_scope": [],
            "last_refreshed": _utcnow(),
        }

    def get_structured_scope(self, handle: str) -> (List[dict], List[dict]):
        in_scope, out_scope = [], []
        for it in self._paginate(f"programs/{handle}/structured_scope"):
            a = it.get("attributes", {})
            entry = {
                "asset_type": a.get("asset_type", "OTHER"),
                "identifier": a.get("identifier", ""),
                "eligible_for_submission": bool(a.get("eligible_for_submission", True)),
                "eligible_for_bounty": bool(a.get("eligible_for_bounty", False)),
                "max_severity": a.get("max_severity", "") or "",
            }
            if entry["eligible_for_submission"]:
                in_scope.append(entry)
            else:
                out_scope.append(entry)
        return in_scope, out_scope

    def fetch_program(self, handle: str) -> dict:
        prog = self.get_program(handle)
        prog["in_scope"], prog["out_of_scope"] = self.get_structured_scope(handle)
        prog["last_refreshed"] = _utcnow()
        return prog

    # -- reports (the current user's submissions) --

    def get_reports(self, limit: int = 20) -> List[dict]:
        data = self._request("GET", "me/reports", params={"page[size]": limit})
        reports = []
        for it in (data.get("data", []) or []):
            a = it.get("attributes", {}) or {}
            rel = it.get("relationships", {}) or {}
            prog = rel.get("program", {}).get("data", {}) or {}
            sev = rel.get("severity", {}).get("data", {}) or {}
            reports.append({
                "id": it.get("id", ""),
                "title": a.get("title", ""),
                "state": a.get("state", ""),
                "severity": (a.get("severity_rating") or "")
                            or self._severity(sev.get("attributes", {}) or {}),
                "created_at": a.get("created_at", ""),
                "bounty_awarded": bool(a.get("bounty_awarded_at")),
                "program": (prog.get("attributes", {}) or {}).get("handle", ""),
            })
        return reports

    @staticmethod
    def _severity(attrs: dict) -> str:
        if not isinstance(attrs, dict):
            return ""
        sev = attrs.get("severity")
        if isinstance(sev, dict):
            return sev.get("rating", "")
        return attrs.get("rating", "") or attrs.get("severity_rating", "") or ""

    @staticmethod
    def _simplify_state(state: str) -> str:
        s = (state or "").lower()
        if "public" in s:
            return "public"
        if "invite" in s:
            return "invite_only"
        if s == "disabled":
            return "disabled"
        return s or "unknown"


# ── Bugcrowd client (public scope mirror from arkadiyt/bounty-targets-data) ─
# Bugcrowd removed its public program JSON endpoints, so we import the public
# program list + scope from the community-maintained daily mirror on GitHub.
# No credentials required. Only public managed (MBB) programs are listed, so
# invite-only/private programs are not discoverable through this client.

_BUGCROWD_MIRROR_TTL = 900.0  # seconds; avoid hammering GitHub during sweeps
_bc_mirror_lock = threading.Lock()
_bc_mirror_data = None
_bc_mirror_at = 0.0


def _fetch_bugcrowd_mirror(refresh: bool = False) -> list:
    global _bc_mirror_data, _bc_mirror_at
    with _bc_mirror_lock:
        if (not refresh and _bc_mirror_data is not None
                and (time.monotonic() - _bc_mirror_at) < _BUGCROWD_MIRROR_TTL):
            return _bc_mirror_data
        resp = requests.get(BUGCROWD_MIRROR, headers={"User-Agent": UA}, timeout=60)
        resp.raise_for_status()
        data = resp.json() or []
        _bc_mirror_data = data
        _bc_mirror_at = time.monotonic()
        return data


class BugcrowdClient:

    _TYPE_MAP = {
        "website": "WEBSITE",
        "api": "API",
        "android": "ANDROID",
        "ios": "IOS",
        "hardware": "HARDWARE",
        "iot": "IOT",
        "ip_address": "IP",
        "network": "NETWORK",
    }

    def list_programs(self, refresh: bool = False) -> List[dict]:
        return [self._normalize(it) for it in _fetch_bugcrowd_mirror(refresh=refresh)]

    def fetch_program(self, code: str) -> dict:
        slug = code.strip().lower()
        for it in _fetch_bugcrowd_mirror():
            url = it.get("url") or ""
            entry_slug = (url.rstrip("/").rsplit("/", 1)[-1] if url else "").lower()
            if entry_slug == slug:
                return self._normalize(it)
        raise FileNotFoundError(
            f"Bugcrowd program '{code}' not found in the public mirror — it is "
            "likely invite-only/private or retired. Only public managed (MBB) "
            "programs are listed in the mirror.")

    @classmethod
    def _normalize(cls, it: dict) -> dict:
        url = it.get("url") or ""
        slug = url.rstrip("/").rsplit("/", 1)[-1] if url else ""
        if not slug:
            slug = re.sub(r"[^a-zA-Z0-9_-]", "-",
                          (it.get("name") or "")).strip("-") or "unknown"
        max_payout = it.get("max_payout")
        offers = bool(max_payout) if max_payout is not None else None
        in_scope = [cls._target_entry(t)
                    for t in (it.get("targets") or {}).get("in_scope") or []]
        out_scope = [cls._target_entry(t)
                     for t in (it.get("targets") or {}).get("out_of_scope") or []]
        rewards = [{"name": "max", "value": str(max_payout)}] if max_payout else None
        return {
            "platform": "bugcrowd",
            "slug": slug,
            "name": (it.get("name") or "").strip() or slug,
            "url": url or f"{BUGCROWD_SITE}/engagements/{slug}",
            "state": "public",
            "submission_state": "open",
            "offers_bounties": offers,
            "currency": "USD",
            "rewards": rewards,
            "in_scope": in_scope,
            "out_of_scope": out_scope,
            "last_refreshed": _utcnow(),
        }

    @classmethod
    def _target_entry(cls, t: dict) -> dict:
        raw_type = (t.get("type") or "").lower()
        identifier = (t.get("target") or t.get("uri") or t.get("ipAddress")
                      or t.get("name") or "").strip()
        return {
            "asset_type": cls._TYPE_MAP.get(raw_type, raw_type.upper() or "OTHER"),
            "identifier": identifier,
            "eligible_for_submission": True,
            "eligible_for_bounty": True,
            "max_severity": "",
        }


# ── YesWeHack client (public REST API, optional personal access token) ─────
# Program list + program detail (with scopes) are fully public. Auth uses an
# X-AUTH-TOKEN header ("My YesWeHack" -> "Personal Access Token") when provided.

class YesWeHackClient:

    def __init__(self, token: str = ""):
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json", "User-Agent": UA})
        if token:
            self.session.headers["X-AUTH-TOKEN"] = token

    def _request(self, method: str, endpoint: str, params: dict = None) -> dict:
        resp = self.session.request(method, f"{YESWEHACK_API}/{endpoint}",
                                    params=params, timeout=45)
        if resp.status_code == 401:
            raise PermissionError(
                "YesWeHack 401: invalid or expired personal access token — "
                "create a new one at 'My YesWeHack' → 'Personal Access Token'")
        if resp.status_code == 403:
            raise PermissionError(
                "YesWeHack 403: your personal access token lacks permission for "
                "this resource — the token role must be Business Unit "
                "Owner/Manager or Program Manager")
        resp.raise_for_status()
        return resp.json()

    def list_programs(self, page: int = 1, results_per_page: int = 50,
                      search: str = "") -> List[dict]:
        params = {"page": page, "resultsPerPage": results_per_page}
        if search:
            params["filter[search]"] = search
        data = self._request("GET", "programs", params=params)
        return [self._summary(it) for it in (data.get("items") or [])]

    def fetch_program(self, slug: str) -> dict:
        data = self._request("GET", f"programs/{slug}")
        prog = self._summary(data)
        in_scope, out_scope = [], []
        for s in (data.get("scopes") or []):
            ident = s.get("scope") or ""
            if not ident:
                continue
            in_scope.append({
                "asset_type": s.get("scope_type") or "OTHER",
                "identifier": ident,
                "eligible_for_submission": True,
                "eligible_for_bounty": bool(data.get("bounty")),
                "max_severity": s.get("asset_value") or "",
            })
        for s in (data.get("out_of_scope") or []):
            out_scope.append({
                "asset_type": "OTHER",
                "identifier": s if isinstance(s, str) else str(s),
                "eligible_for_submission": False,
                "eligible_for_bounty": False,
                "max_severity": "",
            })
        prog.update({
            "in_scope": in_scope,
            "out_of_scope": out_scope,
            "rewards": self._rewards_from_detail(data),
            "last_refreshed": _utcnow(),
        })
        return prog

    def _summary(self, it: dict) -> dict:
        slug = it.get("slug", "")
        bu = it.get("business_unit") or {}
        rewards = []
        rmin, rmax = it.get("bounty_reward_min"), it.get("bounty_reward_max")
        if rmin is not None or rmax is not None:
            rewards.append({"name": "min", "value": str(rmin or "")})
            rewards.append({"name": "max", "value": str(rmax or "")})
        return {
            "platform": "yeswehack",
            "slug": slug,
            "name": it.get("title") or slug,
            "url": f"{YESWEHACK_SITE}/programs/{slug}" if slug else "",
            "state": self._state(it),
            "submission_state": "open" if it.get("status") == "V" else "unknown",
            "offers_bounties": bool(it.get("bounty")),
            "currency": bu.get("currency"),
            "rewards": rewards or None,
            "in_scope": [],
            "out_of_scope": [],
            "last_refreshed": _utcnow(),
        }

    @staticmethod
    def _state(it: dict) -> str:
        if it.get("disabled") or it.get("archived"):
            return "disabled"
        if it.get("public"):
            return "public"
        return "invite_only"

    @staticmethod
    def _rewards_from_detail(data: dict) -> Optional[List[dict]]:
        sev_order = ["critical", "high", "medium", "low", "very_low"]
        amounts: Dict[str, list] = {}
        for g in sev_order:
            grid = data.get(f"reward_grid_{g}")
            if isinstance(grid, dict):
                for k, v in grid.items():
                    if isinstance(v, (int, float)):
                        amounts.setdefault(k.replace("bounty_", ""), []).append(v)
        out = []
        for sev in sev_order:
            vals = amounts.get(sev)
            if vals:
                out.append({"name": sev, "value": max(vals)})
        return out or None

    # -- reports (requires a Personal Access Token) ---------------------------
    # PATs are only available to Business Unit Owner/Manager and Program Manager
    # roles (My YesWeHack -> Personal Access Token); researcher accounts cannot
    # create them. YesWeHack has no single "all my reports" endpoint, so reports
    # are pulled per program from GET /programs/{slug}/reports.

    def get_reports(self, limit: int = 20,
                    program_slugs: Optional[List[str]] = None) -> List[dict]:
        if "X-AUTH-TOKEN" not in self.session.headers:
            raise RuntimeError(
                "YesWeHack needs a Personal Access Token to read reports. "
                "Create one at 'My YesWeHack' → 'Personal Access Token' — note "
                "it is only available to Business Unit Owner/Manager and Program "
                "Manager roles (researcher accounts can't create PATs).")
        slugs = [s.strip() for s in (program_slugs or []) if s and s.strip()]
        if not slugs:
            raise ValueError(
                "YesWeHack has no single 'all my reports' endpoint — pass the "
                "program slug(s) you manage (e.g. program_slugs=['acme']) and "
                "reports are pulled from GET /programs/{slug}/reports")
        reports: List[dict] = []
        for slug in slugs:
            page = 1
            while len(reports) < limit:
                data = self._request(
                    "GET", f"programs/{slug}/reports",
                    params={"page": page, "resultsPerPage": 50})
                items = data.get("items") or []
                for it in items:
                    reports.append(self._report_entry(it))
                    if len(reports) >= limit:
                        break
                if len(items) < 50:
                    break
                page += 1
        return reports[:limit]

    @staticmethod
    def _report_entry(it: dict) -> dict:
        status = it.get("status") or {}
        if isinstance(status, dict):
            state = status.get("workflow_state") or status.get("label") or ""
        else:
            state = str(status or "")
        cvss = it.get("cvss") or {}
        sev = ""
        if isinstance(cvss, dict) and cvss.get("criticity"):
            sev = str(cvss["criticity"]).lower()
        if not sev:
            s = it.get("severity") or ""
            sev = str(s).lower() if isinstance(s, str) else ""
        hunter = it.get("hunter") or {}
        prog = it.get("program") or {}
        return {
            "id": str(it.get("id", "")),
            "title": it.get("title", ""),
            "state": state,
            "severity": sev,
            "created_at": it.get("created_at", ""),
            "bounty_awarded": bool(it.get("reward")),
            "program": prog.get("slug") or prog.get("title") or "",
            "hunter": hunter.get("username", ""),
        }


# ── Intigriti client (researcher API, requires researcher API token) ────────
# Bearer-token API at app.intigriti.com/profile/api. Scope/BBP only — the
# researcher API does not expose the authenticated hunter's report list.

class IntigritiClient:

    def __init__(self, token: str = ""):
        self.token = token
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json", "User-Agent": UA})

    def _request(self, method: str, endpoint: str, params: dict = None) -> dict:
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        resp = self.session.request(method, f"{INTIGRITI_API}/{endpoint}",
                                    params=params, headers=headers, timeout=45)
        if resp.status_code in (401, 403):
            raise PermissionError(
                "Intigriti 401: invalid API token — generate one at "
                "https://app.intigriti.com/profile/api")
        if resp.status_code == 429:
            raise RuntimeError("Intigriti rate limited (429) — wait and retry")
        resp.raise_for_status()
        return resp.json()

    def list_programs(self) -> List[dict]:
        out: List[dict] = []
        offset, limit, total = 0, 500, None
        while True:
            data = self._request("GET", "programs",
                                 params={"limit": limit, "offset": offset})
            if total is None:
                total = int(data.get("maxCount", 0) or 0)
            records = data.get("records") or []
            for r in records:
                if (r.get("status") or {}).get("id") not in (3, 4):
                    continue
                out.append(self._summary(r))
            offset += len(records)
            if not records or offset >= total:
                break
        return out

    def fetch_program(self, slug: str) -> dict:
        identifier = slug
        if not slug.isdigit():
            target = next((r for r in self.list_programs()
                           if r.get("slug", "").lower() == slug.lower()), None)
            if target is None:
                raise FileNotFoundError(
                    f"Intigriti program '{slug}' not found in your researcher "
                    "program list (private programs you are not a member of are hidden)")
            identifier = target.get("id", slug)
        data = self._request("GET", f"programs/{identifier}")
        in_scope, out_scope = [], []
        for content in ((data.get("domains") or {}).get("content") or []):
            endpoint = content.get("endpoint") or ""
            if not endpoint:
                continue
            tier = content.get("tier") or {}
            is_out = tier.get("id") == 5
            entry = {
                "asset_type": (content.get("type") or {}).get("value") or "OTHER",
                "identifier": endpoint,
                "eligible_for_submission": not is_out,
                "eligible_for_bounty": bool(tier.get("value")) and tier.get("value") != "No Bounty",
                "max_severity": "",
            }
            (out_scope if is_out else in_scope).append(entry)
        return {
            "platform": "intigriti",
            "slug": slug,
            "id": str(identifier),
            "name": data.get("name") or slug,
            "url": f"{INTIGRITI_SITE}/program/{slug}/detail",
            "state": "invite_only",
            "submission_state": "open",
            "offers_bounties": bool(in_scope) and any(
                e["eligible_for_bounty"] for e in in_scope),
            "currency": None,
            "rewards": None,
            "in_scope": in_scope,
            "out_of_scope": out_scope,
            "last_refreshed": _utcnow(),
        }

    def _summary(self, r: dict) -> dict:
        links = r.get("webLinks") or {}
        id_ = str(r.get("id", ""))
        handle = ""
        m = re.search(r"/program/([^/?]+)/detail", links.get("detail", ""))
        if m:
            handle = m.group(1)
        slug = handle or id_
        return {
            "platform": "intigriti",
            "slug": slug,
            "id": id_,
            "name": r.get("name") or slug,
            "url": links.get("detail") or f"{INTIGRITI_SITE}/program/{slug}/detail",
            "state": "public" if (r.get("confidentialityLevel") or {}).get("id") == 4
                     else "invite_only",
            "submission_state": "open",
            "offers_bounties": bool((r.get("maxBounty") or {}).get("value")),
            "currency": None,
            "rewards": None,
            "in_scope": [],
            "out_of_scope": [],
            "last_refreshed": _utcnow(),
        }


# ── Immunefi client (public Web3 bounty API, no auth) ───────────────────────

class ImmunefiClient:

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json", "User-Agent": UA})

    def _raw(self) -> list:
        resp = self.session.get(IMMUNEFI_BOUNTIES, timeout=60)
        resp.raise_for_status()
        return resp.json() or []

    def list_programs(self) -> List[dict]:
        return [self._normalize(it) for it in self._raw()]

    def fetch_program(self, slug: str) -> dict:
        for it in self._raw():
            if (it.get("slug") or "").lower() == slug.lower():
                return self._normalize(it, with_scope=True)
        raise FileNotFoundError(f"Immunefi bounty '{slug}' not found")

    def _normalize(self, it: dict, with_scope: bool = False) -> dict:
        slug = it.get("slug", "")
        in_scope = []
        if with_scope:
            for a in (it.get("assets") or []):
                url = a.get("url") or ""
                if not url:
                    continue
                in_scope.append({
                    "asset_type": a.get("type") or "OTHER",
                    "identifier": url,
                    "eligible_for_submission": True,
                    "eligible_for_bounty": True,
                    "max_severity": "",
                })
        rewards = None
        mb = it.get("maxBounty")
        if mb:
            rewards = [{"name": "max", "value": str(mb)}]
        elif it.get("rewardsToken"):
            rewards = [{"name": "pool", "value": str(it.get("rewardsToken"))}]
        return {
            "platform": "immunefi",
            "slug": slug,
            "name": it.get("project") or slug,
            "url": it.get("websiteUrl") or f"{IMMUNEFI_SITE}/bug-bounty/{slug}/",
            "state": "invite_only" if it.get("inviteOnly") else "public",
            "submission_state": "open",
            "offers_bounties": bool(mb or it.get("rewardsToken") or it.get("rewards")),
            "currency": it.get("rewardsToken"),
            "rewards": rewards,
            "in_scope": in_scope,
            "out_of_scope": [],
            "last_refreshed": _utcnow(),
        }


# ── Orchestrator ───────────────────────────────────────────────────────────

class BugBountyManager:
    PLATFORMS = {"hackerone", "bugcrowd", "yeswehack", "intigriti", "immunefi"}

    def __init__(self):
        self._cache: Optional[dict] = None

    # ---- credentials ----

    def set_credentials(self, platform: str, identifier: str = "",
                        token: str = "", client_id: str = "",
                        client_secret: str = "", public_only: bool = True) -> dict:
        if platform not in self.PLATFORMS:
            raise ValueError(f"Unsupported platform '{platform}' — use {sorted(self.PLATFORMS)}")
        updates = {}
        if platform == "hackerone":
            if not identifier or not token:
                raise ValueError("HackerOne needs 'identifier' (API token name) and 'token' (API token value)")
            updates = {"identifier": identifier, "token_enc": _encrypt(token)}
        elif platform == "bugcrowd":
            if client_id:
                updates["client_id"] = client_id
            if client_secret:
                updates["client_secret_enc"] = _encrypt(client_secret)
            updates["public_only"] = bool(public_only)
        elif platform == "yeswehack":
            if token:
                updates["token_enc"] = _encrypt(token)
        elif platform == "intigriti":
            if not token:
                raise ValueError("Intigriti needs a researcher API token "
                                 "(https://app.intigriti.com/profile/api)")
            updates["token_enc"] = _encrypt(token)
        elif platform == "immunefi":
            pass  # public API, no credentials needed
        _CREDS.set_platform(platform, updates)
        return {"platform": platform, "configured": True,
                "public": self.is_public(platform)}

    def get_credentials(self, platform: str, with_secrets: bool = False) -> dict:
        return _CREDS.get_platform(platform, with_secrets=with_secrets)

    def clear_credentials(self, platform: str):
        cfg = _CREDS.load()
        cfg.get("platforms", {}).pop(platform, None)
        _CREDS.save(cfg)

    def is_public(self, platform: str) -> bool:
        """Whether the platform can be queried without any credentials."""
        if platform in ("bugcrowd", "yeswehack", "immunefi"):
            return True
        return False

    def configured_platforms(self) -> List[dict]:
        out = []
        for p in sorted(self.PLATFORMS):
            raw = _CREDS.load().get("platforms", {}).get(p, {})
            entry = {"platform": p, "public": self.is_public(p),
                     "identifier": raw.get("identifier", ""),
                     "customer_only": False}
            if p == "hackerone":
                entry["configured"] = bool(raw.get("identifier") and raw.get("token_enc"))
            elif p in ("yeswehack", "intigriti"):
                entry["configured"] = bool(raw.get("token_enc"))
            elif p == "bugcrowd":
                entry["configured"] = bool(raw.get("client_id") and raw.get("client_secret"))
                entry["identifier"] = raw.get("client_id", "")
                entry["customer_only"] = True
            else:
                entry["configured"] = False
            out.append(entry)
        return out

    # ---- cache ----

    def _load_cache(self) -> dict:
        if self._cache is None:
            self._cache = _load_json(BB_CACHE_PATH, {"programs": {}, "last_sync": {}})
        return self._cache

    def _save_cache(self):
        _save_json(BB_CACHE_PATH, self._cache)

    @staticmethod
    def _key(platform: str, slug: str) -> str:
        return f"{platform}:{slug.strip().lower()}"

    # ---- fetching ----

    def _fetch(self, platform: str, slug: str) -> dict:
        if platform == "hackerone":
            creds = self.get_credentials("hackerone", with_secrets=True)
            if not creds.get("identifier") or not creds.get("token"):
                raise RuntimeError(
                    "HackerOne credentials not configured — run `cc bb creds set hackerone "
                    "--identifier <token-name> --token <token>`")
            return HackerOneClient(creds["identifier"], creds["token"]).fetch_program(slug)
        if platform == "bugcrowd":
            return BugcrowdClient().fetch_program(slug)
        if platform == "yeswehack":
            creds = self.get_credentials("yeswehack", with_secrets=True)
            return YesWeHackClient(token=creds.get("token", "")).fetch_program(slug)
        if platform == "intigriti":
            creds = self.get_credentials("intigriti", with_secrets=True)
            if not creds.get("token"):
                raise RuntimeError(
                    "Intigriti credentials not configured — add your researcher API "
                    "token (https://app.intigriti.com/profile/api)")
            return IntigritiClient(token=creds["token"]).fetch_program(slug)
        if platform == "immunefi":
            return ImmunefiClient().fetch_program(slug)
        raise ValueError(f"Unsupported platform '{platform}' — use {sorted(self.PLATFORMS)}")

    def sync_program(self, platform: str, slug: str, refresh: bool = True) -> dict:
        key = self._key(platform, slug)
        cache = self._load_cache()
        if not refresh and key in cache.get("programs", {}):
            return cache["programs"][key]
        prog = self._fetch(platform, slug)
        cache.setdefault("programs", {})[key] = prog
        cache.setdefault("last_sync", {})[key] = _utcnow()
        self._save_cache()
        return prog

    def get_program(self, platform: str, slug: str, refresh: bool = False) -> Optional[dict]:
        return self.sync_program(platform, slug, refresh=refresh)

    def list_programs(self, platform: str = "", search: str = "") -> List[dict]:
        cache = self._load_cache()
        results = []
        q = search.lower().strip()
        for key, prog in cache.get("programs", {}).items():
            if platform and not key.startswith(f"{platform}:"):
                continue
            if q and not (q in prog.get("name", "").lower()
                          or q in prog.get("slug", "").lower()
                          or q in prog.get("url", "").lower()):
                continue
            results.append(prog)
        results.sort(key=lambda p: p.get("name", "").lower())
        return results

    def discover(self, platform: str = "hackerone") -> List[dict]:
        """List public programs from the platform API (scope where the API
        provides it), caching minimal entries for programs not already cached."""
        if platform == "hackerone":
            creds = self.get_credentials("hackerone", with_secrets=True)
            if not creds.get("identifier") or not creds.get("token"):
                raise RuntimeError("HackerOne credentials not configured")
            found = HackerOneClient(creds["identifier"], creds["token"]).list_programs()
        elif platform == "yeswehack":
            found = []
            page = 1
            while True:
                batch = YesWeHackClient().list_programs(page=page, results_per_page=100)
                found.extend(batch)
                if len(batch) < 100:
                    break
                page += 1
        elif platform == "immunefi":
            found = ImmunefiClient().list_programs()
        elif platform == "intigriti":
            creds = self.get_credentials("intigriti", with_secrets=True)
            if not creds.get("token"):
                raise RuntimeError("Intigriti credentials not configured")
            found = IntigritiClient(token=creds["token"]).list_programs()
        elif platform == "bugcrowd":
            found = BugcrowdClient().list_programs()
        else:
            raise ValueError(f"Unsupported platform '{platform}' — use {sorted(self.PLATFORMS)}")
        cache = self._load_cache()
        for p in found:
            key = self._key(p["platform"], p["slug"])
            if key not in cache.get("programs", {}):
                cache.setdefault("programs", {})[key] = p
        self._save_cache()
        return found

    def sync_all(self, platform: str = "", limit: int = 0, refresh: bool = True,
                 max_age_hours: float = 24.0) -> dict:
        """Refresh cached programs. If limit > 0, also discover new public
        programs across the discoverable platforms and sync up to `limit` of them.

        With refresh=True, programs synced less than `max_age_hours` ago are
        skipped so a routine update sweep stays fast (set max_age_hours=0 to
        force a full refresh of every cached program).
        """
        cache = self._load_cache()
        slugs = [(k.split(":", 1)[0], k.split(":", 1)[1])
                 for k in cache.get("programs", {})
                 if (not platform or k.startswith(f"{platform}:"))]
        now = datetime.now(timezone.utc)
        stale = []
        for plat, slug in slugs:
            if refresh and max_age_hours:
                key = self._key(plat, slug)
                ls = cache.get("last_sync", {}).get(key)
                if not ls:
                    prog = cache.get("programs", {}).get(key) or {}
                    ls = prog.get("last_refreshed")
                if ls:
                    try:
                        ts = datetime.strptime(
                            ls, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                        if (now - ts).total_seconds() < max_age_hours * 3600:
                            continue
                    except ValueError:
                        pass
            stale.append((plat, slug))
        synced, failed = [], []
        for plat, slug in stale:
            try:
                self.sync_program(plat, slug, refresh=refresh)
                synced.append(f"{plat}:{slug}")
            except Exception as e:
                failed.append({"program": f"{plat}:{slug}", "error": str(e)})
        new_count = 0
        if limit:
            if platform in self.PLATFORMS:
                discoverable = [platform]
            else:
                discoverable = ["hackerone", "yeswehack", "immunefi"]
                if self.get_credentials("intigriti").get("token_enc"):
                    discoverable.append("intigriti")
            for plat in discoverable:
                try:
                    found = self.discover(plat)
                    cache = self._load_cache()
                    existing = {f"{p}:{s}" for p, s in slugs}
                    candidates = [p for p in found
                                  if self._key(plat, p["slug"]) in cache.get("programs", {})
                                  and self._key(plat, p["slug"]) not in existing]
                    for p in candidates[:limit]:
                        try:
                            self.sync_program(plat, p["slug"], refresh=True)
                            synced.append(f"{plat}:{p['slug']}")
                            new_count += 1
                        except Exception as e:
                            failed.append({"program": f"{plat}:{p['slug']}", "error": str(e)})
                except Exception as e:
                    failed.append({"program": f"{plat}:discover", "error": str(e)})
        return {"synced": synced, "failed": failed, "new_discovered": new_count,
                "skipped_fresh": len(slugs) - len(stale)}

    # ---- case + asset import ----

    def import_case(self, platform: str, slug: str, case_id: str = "",
                    client: str = "", customer_id: str = "",
                    include_assets: bool = True) -> dict:
        prog = self.sync_program(platform, slug)
        cid = case_id or re.sub(r"[^a-zA-Z0-9_-]", "-", f"{platform}-{slug}").strip("-")
        in_scope = prog.get("in_scope", [])
        out_scope = prog.get("out_of_scope", [])
        cm = CaseManager()
        try:
            cm.create(
                cid,
                client=client or prog.get("name", ""),
                case_type="pentest_external",
                description=f"{prog.get('name', '')} bug bounty program ({platform}) — "
                            f"{prog.get('url', '')}",
                targets=[e["identifier"] for e in in_scope][:200],
                goals=[f"Test in-scope assets of {prog.get('name', '')} ({platform})"],
            )
        except FileExistsError:
            pass
        for e in in_scope:
            cm.scope_add(cid, e["identifier"], in_scope=True)
        for e in out_scope:
            cm.scope_add(cid, e["identifier"], in_scope=False)

        created = 0
        if include_assets:
            at = AssetTracker()
            existing = {a["address"] for a in at.list_assets()}
            tag = f"bb:{platform}:{slug}"
            for e in in_scope:
                ident = e["identifier"]
                kind = self._asset_kind(e.get("asset_type", ""), ident)
                addr = self._clean_address(ident, kind)
                if not addr or addr in existing:
                    continue
                at.create_asset(
                    customer_id=customer_id, kind=kind, address=addr,
                    label=prog.get("name", ""), tags=[tag],
                    source="bugbounty", case_id=cid,
                    notes=f"In scope for {prog.get('url', '')} ({platform} bounty)")
                existing.add(addr)
                created += 1

        return {"case_id": cid, "program": prog.get("name", slug), "url": prog.get("url", ""),
                "in_scope": len(in_scope), "out_of_scope": len(out_scope),
                "assets_created": created}

    def get_reports(self, platform: str = "hackerone", limit: int = 20,
                    program_slugs: Optional[List[str]] = None) -> List[dict]:
        if platform == "hackerone":
            creds = self.get_credentials("hackerone", with_secrets=True)
            if not creds.get("identifier") or not creds.get("token"):
                raise RuntimeError("HackerOne credentials not configured")
            return HackerOneClient(creds["identifier"], creds["token"]).get_reports(limit=limit)
        if platform == "yeswehack":
            creds = self.get_credentials("yeswehack", with_secrets=True)
            if not creds.get("token"):
                raise RuntimeError(
                    "YesWeHack credentials not configured — add your Personal "
                    "Access Token via `cc bb creds set yeswehack --token <pat>`. "
                    "Note: PATs are only available to Business Unit Owner/Manager "
                    "and Program Manager roles — researchers can't create them.")
            return YesWeHackClient(token=creds["token"]).get_reports(
                limit=limit, program_slugs=program_slugs)
        if platform == "bugcrowd":
            raise ValueError(
                "Bugcrowd has no researcher-facing reports API — its API is "
                "customer-only (OAuth2) and researchers can't generate tokens")
        raise ValueError(
            f"Report lookup is unavailable for {platform} — only hackerone and "
            "yeswehack expose the hunter's report list via their APIs "
            "(intigriti/immunefi do not)")

    # ---- helpers ----

    @staticmethod
    def _asset_kind(asset_type: str, identifier: str) -> str:
        at = (asset_type or "").upper()
        i = (identifier or "").strip().lower()
        if at in ("URL", "WEB", "WEBSITE") or i.startswith(("http://", "https://")):
            return "url"
        if at == "CIDR" or re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$", i):
            return "cidr"
        if at == "IP" or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", i):
            return "host"
        if at in ("WILDCARD", "WILDCARD_PATTERN", "DOMAIN", "DNS") or "*." in i:
            return "domain"
        return "domain"

    @staticmethod
    def _clean_address(identifier: str, kind: str) -> str:
        i = (identifier or "").strip()
        i = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", i)
        i = i.rstrip("/")
        if kind == "domain":
            i = i.removeprefix("*.").removeprefix("www.")
            i = i.split("/")[0]
        if kind == "host":
            i = i.split(":")[0]
        return i


# ── Display helpers (used by MCP tools + CLI) ──────────────────────────────

def format_program(prog: dict, show_scope: bool = True) -> str:
    lines = [f"{prog.get('name', prog.get('slug', '?'))}  [{prog.get('platform', '?')}]"]
    lines.append(f"  URL:        {prog.get('url', '')}")
    lines.append(f"  Slug:       {prog.get('slug', '')}")
    lines.append(f"  State:      {prog.get('state', 'unknown')} "
                 f"(submissions: {prog.get('submission_state', 'unknown')})")
    b = prog.get("offers_bounties")
    lines.append(f"  Bounties:   {'yes' if b else 'no' if b is not None else 'unknown'}"
                 f"{'  (' + prog.get('currency', '') + ')' if prog.get('currency') else ''}")
    rewards = prog.get("rewards")
    if rewards:
        lines.append("  Rewards:    " + ", ".join(f"{r['name']}={r['value']}" for r in rewards))
    lines.append(f"  Refreshed:  {prog.get('last_refreshed', 'never')}")
    if show_scope:
        in_scope = prog.get("in_scope", [])
        out_scope = prog.get("out_of_scope", [])
        lines.append(f"  In scope ({len(in_scope)}):")
        for e in in_scope[:60]:
            flag = "" if e.get("eligible_for_bounty") else " [no bounty]"
            sev = f"  max={e.get('max_severity')}" if e.get("max_severity") else ""
            lines.append(f"    - {e.get('asset_type', 'OTHER'):<10} {e.get('identifier', '')}{flag}{sev}")
        if len(in_scope) > 60:
            lines.append(f"    ... {len(in_scope) - 60} more")
        lines.append(f"  Out of scope ({len(out_scope)}):")
        for e in out_scope[:30]:
            lines.append(f"    - {e.get('asset_type', 'OTHER'):<10} {e.get('identifier', '')}")
        if len(out_scope) > 30:
            lines.append(f"    ... {len(out_scope) - 30} more")
    return "\n".join(lines)


def format_programs(programs: List[dict]) -> str:
    if not programs:
        return "No programs in cache. Run `bb sync <platform> <slug>` or `bb discover` first."
    lines = [f"Bug bounty programs ({len(programs)}):"]
    for p in programs:
        in_n = len(p.get("in_scope", []))
        lines.append(f"  [{p.get('platform','?'):<9}] {p.get('slug','?'):<28} "
                     f"{p.get('name',''):<40} in_scope={in_n:<4} "
                     f"{p.get('state','')}/{p.get('submission_state','')}")
    return "\n".join(lines)
