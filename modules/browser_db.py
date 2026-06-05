import logging
"""Browser database examiner — LevelDB + IndexedDB analysis with content classification.

Reads LevelDB stores (Chrome/Chromium profiles) and IndexedDB databases,
extracts key-value pairs, and classifies data by type (tokens, credentials,
URLs, session data, JWTs, etc.).

Supports live Chromium profiles or exported .ldb/.log directories.
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pattern-based data classifiers
# ---------------------------------------------------------------------------

_URL_RE = re.compile(
    r"https?://[^\s\"'<>]+\.[^\s\"'<>]{2,}[^\s\"'<>]*"
)
_JWT_RE = re.compile(
    r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"
)
_BEARER_RE = re.compile(r"(?i)(bearer|token|api[_-]?key|secret)\s*[:=]\s*(\S+)")
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_CRED_RE = re.compile(r"(?i)(password|passwd|pwd|login|username|user)\s*[:=]\s*(\S+)")
_SESSION_RE = re.compile(r"(?i)(session|sid|auth|csrf|x?srft?oken)[=:]\s*(\S+)")
_BASE64_PADDED = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")
_BASE64_URL_PADDED = re.compile(r"^[A-Za-z0-9_-]{20,}$")
_HEX_RE = re.compile(r"^[0-9a-f]{32,}$", re.I)
_PROTO_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]{4,}")


def _classify_value(key: str, value: bytes) -> Dict[str, any]:
    """Classify a key-value pair into data categories."""
    result = {"key": key, "size": len(value), "categories": [], "decoded": None}

    # Try text decodings
    text = None
    for enc in ("utf-8", "utf-16-le", "latin-1"):
        try:
            decoded = value.decode(enc)
            if decoded and decoded.strip():
                text = decoded
                break
        except (UnicodeDecodeError, UnicodeError):
            continue

    if text:
        # JSON
        cleaned = text.strip()
        if cleaned.startswith("{") or cleaned.startswith("["):
            try:
                result["decoded"] = json.loads(cleaned)
                result["categories"].append("json")
            except json.JSONDecodeError:
                pass

        # URLs
        urls = _URL_RE.findall(text)
        if urls:
            result["categories"].append("url")
            result["urls"] = urls[:5]

        # JWTs
        if "eyJ" in text:
            jwts = _JWT_RE.findall(text)
            if jwts:
                result["categories"].append("jwt")
                result["decoded"] = {"jwt_count": len(jwts), "first": jwts[0][:80]}

        # Emails
        emails = _EMAIL_RE.findall(text)
        if emails:
            result["categories"].append("email")
            result["emails"] = emails[:5]

        # Credentials
        if _CRED_RE.search(text) or _CRED_RE.search(key):
            result["categories"].append("credential")
            result["decoded"] = text[:200]

        # Bearer tokens / API keys
        if _BEARER_RE.search(text):
            result["categories"].append("api_key")
            result["decoded"] = text[:200]

        # Session tokens
        if _SESSION_RE.search(text):
            result["categories"].append("session")
            result["decoded"] = text[:200]

        # Base64-ish blobs (potential binary data in text)
        lines = text.strip().splitlines()
        if len(text) > 50 and any(_BASE64_PADDED.match(l) for l in lines):
            result["categories"].append("base64_blob")

        # Fallback text
        if not result["categories"] and len(text) < 500:
            result["decoded"] = text[:200]

    # Binary heuristics
    if not text or len(value) > 500:
        if _HEX_RE.match(value.hex()[:64]):
            result["categories"].append("hex_hash")

    if _PROTO_RE.search(value):
        result["categories"].append("protobuf")

    # Key-based classification
    kl = key.lower()
    if "token" in kl or "credential" in kl:
        result["categories"].append("auth")
    if "url" in kl or "href" in kl or "origin" in kl:
        result["categories"].append("url_ref")

    return result


# ---------------------------------------------------------------------------
# LevelDB .ldb / .log parser
# ---------------------------------------------------------------------------

def _read_varint(data: bytes, offset: int) -> Tuple[int, int]:
    """Read a LevelDB varint32 at offset, return (value, new_offset)."""
    value = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return value, offset
        shift += 7
    return value, offset


def _parse_ldb_block(block: bytes) -> List[Tuple[str, bytes, str]]:
    """Parse a single LevelDB data block into (key_hex, value_bytes, classification)."""
    entries = []
    offset = 0
    shared_base = b""

    while offset + 4 <= len(block):
        shared, offset = _read_varint(block, offset)
        unshared, offset = _read_varint(block, offset)
        vlen, offset = _read_varint(block, offset)
        if offset + unshared + vlen > len(block):
            break

        key_bytes = shared_base[:shared] + block[offset:offset + unshared]
        offset += unshared
        value = block[offset:offset + vlen]
        offset += vlen

        shared_base = key_bytes
        key_hex = key_bytes.hex()
        cls = _classify_value(key_hex, value)
        entries.append((key_hex, value, cls))
        # Limit to prevent memory issues
        if len(entries) >= 10000:
            break

    return entries


def _parse_ldb_file(path: Path) -> List[Tuple[str, bytes, Dict]]:
    """Parse a single .ldb or .log file, extracting key-value pairs."""
    data = path.read_bytes()
    entries = []

    if path.suffix == ".log":
        # Write-ahead log — records start at block boundaries (32KB blocks)
        block_size = 32768
        for start in range(0, len(data), block_size):
            block = data[start:start + block_size]
            if len(block) < 12:
                break
            entries.extend(_parse_ldb_block(block[7:]))  # skip 7-byte header
    else:
        # .ldb files — footer has meta index handle, but we scan blocks
        block_size = 32768
        for start in range(0, len(data) - 48, block_size):
            block = data[start:start + block_size - 48]  # leave room for footer
            if len(block) < 12:
                break
            # Snappy-compressed blocks have a 1-byte flag after checksum
            # Try parsing as-is first
            entries.extend(_parse_ldb_block(block[5:]))  # skip 5-byte header

    return entries


# ---------------------------------------------------------------------------
# IndexedDB parser (Chrome's internal LevelDB-based schema)
# ---------------------------------------------------------------------------

_KNOWN_OBJECT_STORE_NAMES: Dict[int, str] = {}


def _classify_keyedb_key(key_hex: str) -> Optional[Dict]:
    """Try to interpret a LevelDB key as IndexedDB internal key."""
    try:
        key_bytes = bytes.fromhex(key_hex)
    except ValueError:
        return None

    # Chrome IndexedDB key format:
    #   database_id (varint) + object_store_id (varint) + index_id (varint) + user_key
    # We try to decode the varint prefix
    offset = 0
    parts = []
    for _ in range(4):
        if offset >= len(key_bytes):
            break
        val, offset = _read_varint(key_bytes, offset)
        parts.append(val)

    if len(parts) >= 2:
        return {
            "database_id": parts[0] if len(parts) > 0 else None,
            "object_store_id": parts[1] if len(parts) > 1 else None,
            "index_id": parts[2] if len(parts) > 2 else None,
            "raw_key_suffix": key_bytes[offset:].hex() if offset < len(key_bytes) else "",
        }
    return None


def analyze_leveldb(path: str) -> Dict:
    """Analyze a LevelDB directory and return classified key-value pairs.

    Args:
        path: Path to a LevelDB directory (containing .ldb, .log, MANIFEST files)
              or a single .ldb/.log file.

    Returns:
        dict with keys: summary, entries_by_category, raw_entry_count
    """
    p = Path(path)
    if not p.exists():
        return {"error": f"Path not found: {path}"}

    all_entries = []
    files_scanned = 0

    targets = [p] if p.is_file() and p.suffix in (".ldb", ".log") else list(p.rglob("*"))
    for f in targets:
        if f.suffix in (".ldb", ".log") and f.is_file():
            try:
                entries = _parse_ldb_file(f)
                all_entries.extend(entries)
                files_scanned += 1
            except e:

                logger.debug("e in browser_db.py", exc_info=True)

    if not all_entries:
        return {
            "error": f"No parseable entries found in {p.name}",
            "files_scanned": files_scanned,
            "entries": [],
        }

    # Group by category
    classified = {
        "jwt": [],
        "credential": [],
        "api_key": [],
        "session": [],
        "url": [],
        "email": [],
        "json": [],
        "hex_hash": [],
        "protobuf": [],
        "base64_blob": [],
        "auth": [],
        "url_ref": [],
        "uncategorized": [],
    }

    for key_hex, value, cls in all_entries:
        cats = cls.get("categories", [])
        entry = {
            "key": key_hex,
            "size": len(value),
            "decoded": cls.get("decoded"),
            "urls": cls.get("urls"),
            "emails": cls.get("emails"),
        }
        # Also try IndexedDB key classification
        idb = _classify_keyedb_key(key_hex)
        if idb:
            entry["indexeddb_key"] = idb

        if cats:
            for c in cats:
                if c in classified:
                    classified[c].append(entry)
        else:
            classified["uncategorized"].append(entry)

    # Summary stats per category
    summary = {}
    for cat, entries_list in classified.items():
        summary[cat] = len(entries_list)

    # Try to detect what this store contains
    detection = _detect_store_type(all_entries)

    return {
        "path": str(p),
        "files_scanned": files_scanned,
        "total_entries": len(all_entries),
        "summary": summary,
        "categories": {k: v[:50] for k, v in classified.items() if v},
        "store_detection": detection,
    }


def _detect_store_type(entries: List[Tuple[str, bytes, Dict]]) -> str:
    """Heuristically determine what browser data this LevelDB contains."""
    keys_set = {e[0][:16] for e in entries[:200]}  # key hex prefixes
    all_text = " ".join(
        _safe_decode(e[1])[:200] for e in entries[:100] if _safe_decode(e[1])
    ).lower()

    # Detection heuristics
    heuristics = {
        "IndexedDB": lambda: any(e[2].get("categories", []) for e in entries[:10]),
        "localStorage": lambda: any("url" in e[2].get("categories", []) for e in entries[:50]),
        "ServiceWorker Cache": lambda: "sw" in all_text or "serviceworker" in all_text or "cachestorage" in all_text,
        "Site Characteristics": lambda: "site_characteristics" in all_text,
        "Extension Storage": lambda: "chrome-extension" in all_text,
        "Login Data (credentials)": lambda: bool(sum(1 for e in entries[:200]
                                                       if "credential" in e[2].get("categories", []))),
    }

    for name, check in heuristics.items():
        try:
            if check():
                return name
        except Exception:
            continue

    return "Unknown browser storage"


def _safe_decode(data: bytes) -> str:
    for enc in ("utf-8", "utf-16-le", "latin-1"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, UnicodeError):
            continue
    return ""


def extract_sensitive(path: str, output_dir: Optional[str] = None) -> Dict:
    """Extract all sensitive data (credentials, tokens, JWTs, sessions) to JSON."""
    result = analyze_leveldb(path)
    if result.get("error"):
        return result

    sensitive = []
    for cat in ("jwt", "credential", "api_key", "session", "auth"):
        for entry in result.get("categories", {}).get(cat, []):
            sensitive.append({**entry, "category": cat})

    out_dir = Path(output_dir or Path.cwd() / "browser_forensics")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"sensitive_data_{Path(path).stem}.json"
    out_file.write_text(json.dumps(sensitive, indent=2, default=str))

    return {
        "sensitive_found": len(sensitive),
        "output_file": str(out_file),
        "by_category": {
            cat: len([e for e in sensitive if e["category"] == cat])
            for cat in ("jwt", "credential", "api_key", "session", "auth")
        },
    }


def analyze_chrome_profile(profile_path: str) -> Dict:
    """Analyze a full Chrome/Chromium profile directory for all LevelDB stores.

    Scans:
      - Default/Local Storage/*.ldb  (localStorage)
      - Default/IndexedDB/*/        (IndexedDB databases)
      - Default/Session Storage/*.ldb  (sessionStorage)
      - Default/Service Worker/CacheStorage/*/
      - Default/Extensions/*/
      - Default/Login Data           (SQLite — noted, not parsed here)

    Returns per-store analysis.
    """
    profile = Path(profile_path)
    if not profile.exists():
        return {"error": f"Profile not found: {profile_path}"}

    stores = {
        "local_storage": profile / "Local Storage" / "leveldb",
        "session_storage": profile / "Session Storage",
        "indexeddb_root": profile / "IndexedDB",
    }

    results = {}
    for name, sp in stores.items():
        if sp.exists():
            analysis = analyze_leveldb(str(sp))
            if not analysis.get("error"):
                results[name] = analysis

    # IndexedDB has per-origin subdirectories
    idb_root = profile / "IndexedDB"
    if idb_root.exists():
        for child in idb_root.iterdir():
            if child.is_dir():
                for db_dir in child.iterdir():
                    if db_dir.is_dir() and any(
                        f.suffix in (".ldb", ".log") for f in db_dir.iterdir()
                    ):
                        origin = child.name.replace(".indexeddb.leveldb", "")
                        lbd_analysis = analyze_leveldb(str(db_dir))
                        if not lbd_analysis.get("error"):
                            results[f"indexeddb_{origin}"] = lbd_analysis

    return {
        "profile": str(profile),
        "stores_analyzed": len(results),
        "stores": results,
        "total_entries": sum(
            s.get("total_entries", 0) for s in results.values()
        ),
        "sensitive_summary": {
            store: s.get("summary", {})
            for store, s in results.items()
        },
    }