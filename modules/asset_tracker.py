"""Asset inventory with encrypted credential store.

Hierarchy: Customer → Asset → Credential
Data stored in asset_db.json. Secrets encrypted with Fernet (CC_VAULT_KEY env var).
"""
import json
import os
import re
import threading
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Callable, List, Optional

from cryptography.fernet import Fernet, InvalidToken

from .config import CC_DIR

ASSET_DB_PATH = CC_DIR / "asset_db.json"
VAULT_KEY_ENV = "CC_VAULT_KEY"


# ── Fernet helpers ──────────────────────────────────────────────────────────

def _get_vault_key() -> bytes:
    key = os.environ.get(VAULT_KEY_ENV)
    if key:
        return key.encode() if isinstance(key, str) else key
    cfg_file = CC_DIR / ".vault_key"
    if cfg_file.exists():
        return cfg_file.read_bytes()
    key = Fernet.generate_key()
    cfg_file.write_bytes(key)
    os.chmod(cfg_file, 0o600)
    return key


def _fernet() -> Fernet:
    return Fernet(_get_vault_key())


def _encrypt(plaintext: str) -> str:
    if not plaintext:
        return ""
    return _fernet().encrypt(plaintext.encode()).decode()


def _decrypt(token: str) -> str:
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken:
        return "[invalid key]"


# ── DB I/O ──────────────────────────────────────────────────────────────────

_EMPTY_DB = {"customers": {}, "assets": {}, "credentials": {}}
_db_lock = threading.Lock()


def _load_db() -> dict:
    if not ASSET_DB_PATH.exists():
        return dict(_EMPTY_DB)
    return json.loads(ASSET_DB_PATH.read_text())


def _save_db(db: dict):
    ASSET_DB_PATH.write_text(json.dumps(db, indent=2, default=str))


def _update_db(updater: Callable[[dict], Any]) -> Any:
    """Atomically read, modify, and write the asset DB."""
    with _db_lock:
        db = _load_db()
        result = updater(db)
        tmp = ASSET_DB_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(db, indent=2, default=str))
        tmp.replace(ASSET_DB_PATH)
        return result


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


# ── Main class ──────────────────────────────────────────────────────────────

class AssetTracker:

    # ── Customers ───────────────────────────────────────────────────────

    def list_customers(self) -> List[dict]:
        return list(_load_db().get("customers", {}).values())

    def get_customer(self, customer_id: str) -> Optional[dict]:
        return _load_db().get("customers", {}).get(customer_id)

    def create_customer(self, name: str, notes: str = "") -> dict:
        cid = re.sub(r"[^a-zA-Z0-9_-]", "-", name.lower()).strip("-") or _new_id()
        def _up(db):
            if cid in db["customers"]:
                raise ValueError(f"Customer '{cid}' already exists")
            db["customers"][cid] = {
                "id": cid,
                "name": name,
                "notes": notes,
                "created": _utcnow(),
                "modified": _utcnow(),
            }
            return db["customers"][cid]
        return _update_db(_up)

    def delete_customer(self, customer_id: str):
        def _up(db):
            if customer_id not in db["customers"]:
                raise FileNotFoundError(f"Customer '{customer_id}' not found")
            del db["customers"][customer_id]
            db["assets"] = {k: v for k, v in db["assets"].items()
                            if v.get("customer_id") != customer_id}
        _update_db(_up)

    # ── Assets ──────────────────────────────────────────────────────────

    def list_assets(self, customer_id: str = "", kind: str = "",
                    tag: str = "", search: str = "") -> List[dict]:
        db = _load_db()
        results = []
        for a in db["assets"].values():
            if customer_id and a.get("customer_id") != customer_id:
                continue
            if kind and a.get("kind") != kind:
                continue
            if tag and tag not in a.get("tags", []):
                continue
            if search:
                q = search.lower()
                if not (q in a.get("address", "").lower()
                        or q in a.get("label", "").lower()
                        or q in a.get("fqdn", "").lower()
                        or q in a.get("os", "").lower()
                        or q in a.get("notes", "").lower()):
                    continue
            results.append(self._without_secrets(a))
        return results

    def get_asset(self, asset_id: str) -> Optional[dict]:
        db = _load_db()
        a = db["assets"].get(asset_id)
        return self._without_secrets(a) if a else None

    def create_asset(self, customer_id: str, kind: str, address: str,
                     label: str = "", fqdn: str = "", os: str = "",
                     ports: list = None, tags: list = None,
                     source: str = "manual", case_id: str = "",
                     notes: str = "") -> dict:
        aid = _new_id()
        now = _utcnow()
        def _up(db):
            if customer_id and customer_id not in db["customers"]:
                raise ValueError(f"Customer '{customer_id}' not found — create it first")
            asset = {
                "id": aid,
                "customer_id": customer_id,
                "kind": kind,
                "address": address,
                "label": label or address,
                "fqdn": fqdn,
                "os": os,
                "ports": ports or [],
                "tags": tags or [],
                "source": source,
                "case_ids": [case_id] if case_id else [],
                "first_seen": now,
                "last_seen": now,
                "notes": notes,
                "created": now,
            }
            db["assets"][aid] = asset
            return self._without_secrets(asset)
        return _update_db(_up)

    def update_asset(self, asset_id: str, **kwargs) -> Optional[dict]:
        def _up(db):
            a = db["assets"].get(asset_id)
            if not a:
                return None
            allowed = {"label", "fqdn", "os", "ports", "tags", "notes", "customer_id", "address", "kind"}
            changed = False
            for k, v in kwargs.items():
                if k in allowed and v is not None:
                    a[k] = v
                    changed = True
            if case_ids := kwargs.get("case_ids"):
                existing = set(a.get("case_ids", []))
                new_cases = set(case_ids) if isinstance(case_ids, list) else {case_ids}
                if new_cases - existing:
                    a["case_ids"] = list(existing | new_cases)
                    changed = True
            if changed:
                a["last_seen"] = _utcnow()
                a["modified"] = _utcnow()
            return self._without_secrets(a)
        return _update_db(_up)

    def delete_asset(self, asset_id: str):
        def _up(db):
            if asset_id not in db["assets"]:
                raise FileNotFoundError(f"Asset '{asset_id}' not found")
            del db["assets"][asset_id]
            db["credentials"] = {k: v for k, v in db["credentials"].items()
                                 if v.get("asset_id") != asset_id}
        _update_db(_up)

    def search_assets(self, query: str) -> List[dict]:
        return self.list_assets(search=query)

    # ── Import helpers ──────────────────────────────────────────────────

    def import_nmap_xml(self, xml_content: str, customer_id: str = "",
                        case_id: str = "") -> dict:
        """Parse Nmap XML and create/update assets. Returns summary."""
        created = 0
        updated = 0
        root = ET.fromstring(xml_content)
        results = []
        for host in root.iter("host"):
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue
            addr_el = host.find("address")
            if addr_el is None:
                continue
            address = addr_el.get("addr", "")
            vendor = addr_el.get("vendor", "")
            hostnames = host.find("hostnames")
            fqdn = ""
            if hostnames is not None:
                for hn in hostnames.iter("hostname"):
                    fqdn = hn.get("name", "")
                    break

            os_el = host.find("os")
            os_name = ""
            if os_el is not None:
                for osmatch in os_el.iter("osmatch"):
                    os_name = osmatch.get("name", "")
                    break

            ports = []
            for port_el in host.iter("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                svc_el = port_el.find("service")
                ports.append({
                    "port": int(port_el.get("portid", 0)),
                    "protocol": port_el.get("protocol", "tcp"),
                    "service": svc_el.get("name", "") if svc_el is not None else "",
                    "product": svc_el.get("product", "") if svc_el is not None else "",
                    "version": svc_el.get("version", "") if svc_el is not None else "",
                    "banner": "",
                    "state": "open",
                })

            label = fqdn.split(".")[0].upper() if fqdn else address
            tags = []
            if vendor:
                tags.append(vendor.lower().replace(" ", "-"))
            existing = self._find_by_address(address)
            if existing:
                self.update_asset(
                    existing["id"], ports=ports, os=os_name, fqdn=fqdn or existing.get("fqdn", ""),
                    tags=list(set(existing.get("tags", []) + tags)),
                    case_ids=[case_id] if case_id else [],
                )
                updated += 1
                results.append({"action": "updated", "asset": existing["id"]})
            else:
                a = self.create_asset(
                    customer_id=customer_id, kind="host", address=address,
                    label=label, fqdn=fqdn, os=os_name,
                    ports=ports, tags=tags, source="nmap",
                    case_id=case_id,
                )
                created += 1
                results.append({"action": "created", "asset": a["id"]})

        return {"created": created, "updated": updated, "results": results}

    def extract_from_findings(self, findings: List[dict],
                              customer_id: str = "", case_id: str = "") -> dict:
        """Scan finding descriptions/remediation for IPs/domains and create assets."""
        ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        domain_pattern = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
        extracted_ips = set()
        extracted_domains = set()
        for f in findings:
            text = " ".join(str(v) for v in [
                f.get("description", ""), f.get("remediation", ""),
                f.get("title", ""), f.get("impact", ""),
            ])
            extracted_ips.update(ip_pattern.findall(text))
            extracted_domains.update(d for d in domain_pattern.findall(text)
                                     if not d.startswith(("http", "www")))

        created = 0
        updated = 0
        for ip in sorted(extracted_ips):
            if not self._find_by_address(ip):
                self.create_asset(customer_id, "host", ip, source="finding", case_id=case_id)
                created += 1
            else:
                updated += 1
        for domain in sorted(extracted_domains):
            if not self._find_by_address(domain):
                self.create_asset(customer_id, "domain", domain, source="finding", case_id=case_id)
                created += 1
            else:
                updated += 1

        return {"ips_found": len(extracted_ips), "domains_found": len(extracted_domains),
                "created": created, "updated": updated}

    def _find_by_address(self, address: str) -> Optional[dict]:
        db = _load_db()
        for a in db["assets"].values():
            if a.get("address") == address:
                return a
        return None

    # ── Credentials ─────────────────────────────────────────────────────

    def list_credentials(self, asset_id: str = "") -> List[dict]:
        db = _load_db()
        results = []
        for c in db["credentials"].values():
            if asset_id and c.get("asset_id") != asset_id:
                continue
            entry = dict(c)
            if entry.get("secret_encrypted"):
                entry["secret_encrypted"] = "🔒"
            results.append(entry)
        return results

    def get_credential(self, cred_id: str, decrypt: bool = False) -> Optional[dict]:
        db = _load_db()
        c = db["credentials"].get(cred_id)
        if not c:
            return None
        entry = dict(c)
        if decrypt and entry.get("secret_encrypted"):
            entry["secret"] = _decrypt(entry["secret_encrypted"])
        entry.pop("secret_encrypted", None)
        return entry

    def add_credential(self, asset_id: str, kind: str, username: str,
                       secret: str, service: str = "", url: str = "",
                       notes: str = "") -> dict:
        cid = _new_id()
        def _up(db):
            if asset_id not in db["assets"]:
                raise ValueError(f"Asset '{asset_id}' not found")
            cred = {
                "id": cid,
                "asset_id": asset_id,
                "kind": kind,
                "service": service,
                "url": url,
                "username": username,
                "secret_encrypted": _encrypt(secret),
                "notes": notes,
                "created": _utcnow(),
            }
            db["credentials"][cid] = cred
            return {k: v for k, v in cred.items() if k != "secret_encrypted"}
        return _update_db(_up)

    def update_credential(self, cred_id: str, **kwargs) -> Optional[dict]:
        def _up(db):
            c = db["credentials"].get(cred_id)
            if not c:
                return None
            allowed = {"kind", "service", "url", "username", "notes"}
            for k, v in kwargs.items():
                if k == "secret" and v:
                    c["secret_encrypted"] = _encrypt(v)
                elif k in allowed and v is not None:
                    c[k] = v
            return {k: v for k, v in c.items() if k != "secret_encrypted"}
        return _update_db(_up)

    def delete_credential(self, cred_id: str):
        def _up(db):
            if cred_id not in db["credentials"]:
                raise FileNotFoundError(f"Credential '{cred_id}' not found")
            del db["credentials"][cred_id]
        _update_db(_up)

    # ── Stats ───────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        db = _load_db()
        assets = db["assets"].values()
        by_kind = {}
        by_tag = {}
        for a in assets:
            k = a.get("kind", "unknown")
            by_kind[k] = by_kind.get(k, 0) + 1
            for t in a.get("tags", []):
                by_tag[t] = by_tag.get(t, 0) + 1
        return {
            "customers": len(db["customers"]),
            "assets": len(db["assets"]),
            "credentials": len(db["credentials"]),
            "by_kind": by_kind,
            "by_tag": dict(sorted(by_tag.items(), key=lambda x: -x[1])[:20]),
        }

    # ── Internal ────────────────────────────────────────────────────────

    @staticmethod
    def _without_secrets(a: dict) -> dict:
        if a:
            a = {k: v for k, v in a.items() if k != "secret_encrypted"}
        return a
