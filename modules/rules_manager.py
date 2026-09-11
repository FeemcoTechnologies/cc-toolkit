"""Unified rule management across Semgrep, Sigma, YARA, Suricata, and Nuclei formats."""

import datetime
import io
import json
import re
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional

from .config import CC_DIR

SCRIPTS_DIR = CC_DIR.parent  # Scripts/ root — parent of all rule dirs

# Known rule directory roots relative to SCRIPTS_DIR
RULE_ROOTS = {
    "semgrep":   SCRIPTS_DIR / "Semgrep-Crypto-Backdoors" / "rules",
    "sigma":     SCRIPTS_DIR / "aislop" / "rules" / "sigma",
    "yara":      SCRIPTS_DIR / "aislop" / "rules" / "yara",
    "suricata":  SCRIPTS_DIR / "aislop" / "rules" / "suricata",
    "nuclei":    SCRIPTS_DIR / "nuclei",
    "codeql":    SCRIPTS_DIR / "ai-combined-tools" / "rules" / "codeql",
}

# Additional flat directories for rules that don't fit the aislop layout
FLAT_ROOTS = {
    "yara":   SCRIPTS_DIR / "SpecialYaraRules",
    "sigma":  SCRIPTS_DIR / "sigma rules",
}

# Curated rule dirs maintained next to this repo (ai-combined-tools/rules/<fmt>).
# These complement RULE_ROOTS — discovery and batch scans merge them in.
CURATED_ROOTS = {
    "semgrep":  SCRIPTS_DIR / "ai-combined-tools" / "rules" / "semgrep",
    "sigma":    SCRIPTS_DIR / "ai-combined-tools" / "rules" / "sigma",
    "yara":     SCRIPTS_DIR / "ai-combined-tools" / "rules" / "yara",
    "suricata": SCRIPTS_DIR / "ai-combined-tools" / "rules" / "suricata",
    "nuclei":   SCRIPTS_DIR / "ai-combined-tools" / "rules" / "nuclei",
}

# Bump when the discovery layout changes so stale .rules_cache.json is ignored.
_CACHE_VERSION = 4


def get_scan_roots(fmt: str) -> List[Path]:
    """All existing rule directories for a format (rule + flat + curated).

    Used by batch scan entry points so curated rules are included alongside
    the primary roots. Excludes roots that don't exist on disk.
    """
    roots: List[Path] = []
    for table in (RULE_ROOTS, FLAT_ROOTS, CURATED_ROOTS):
        p = table.get(fmt)
        if p and p.exists():
            roots.append(p)
    return roots

SEMGREP_LANGUAGE_MAP = {
    "c": "C", "go": "Go", "node": "JavaScript/Node",
    "python": "Python", "rust": "Rust", "java": "Java",
}

SEVERITY_SEMGREP = {"INFO": "info", "WARNING": "medium", "ERROR": "high", "CRITICAL": "critical"}
SEVERITY_SIGMA  = {"informational": "info", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}


def _parse_severity_severity(value: str) -> str:
    """Normalise a severity-like field from any format to low/medium/high/critical."""
    v = (value or "").strip().lower()
    return {"info": "info", "informational": "info", "low": "low",
            "medium": "medium", "high": "high", "critical": "critical",
            "warning": "medium", "error": "high", "critical": "critical"}.get(v, "info")


_SEVERITY_KEYWORDS = {
    "critical": [
        "ransomware", "zerologon", "zeroday", "eternalblue", "credential dumping",
        "kerberoast", "as-rep", "golden ticket", "silver ticket", "dcsync",
        "code execution", "remote code", "rce", "sql injection", "sqli",
        "command injection", "xxe", "ssti", "deserialization", "buffer overflow",
        "shellcode", "meterpreter", "cobaltstrike", "mimikatz", "wannacry",
        "notpetya", "lsass", "secretsdump", "pass-the-hash",
        "privilege escalation", "backdoor", "trojan", "infostealer", "keylogger",
        "lateral movement", "token theft",
    ],
    "high": [
        "persistence", "defense evasion", "uac bypass", "process injection",
        "dll injection", "suspicious", "malicious", "malware", "exploit",
        "cve-", "data exfiltration", "webshell", "mirai", "botnet", "dropper",
        "downloader", "phishing", "spoofing", "dga", "obfuscation",
        "psexec", "wmiexec", "brute force", "password spray",
    ],
    "medium": [
        "reconnaissance", "discovery", "enumeration", "scanning",
        "information disclosure", "path traversal", "lfi", "open redirect",
        "csrf", "xss", "cross-site", "mitm", "session hijacking",
        "misconfiguration", "directory listing", "default credentials",
    ],
}


def _heuristic_severity(text: str) -> str:
    """Infer severity from text keywords when no explicit field exists."""
    if not text:
        return "info"
    lower = text.lower()
    for sev, keywords in _SEVERITY_KEYWORDS.items():
        for kw in keywords:
            if kw in lower:
                return sev
    return "info"


def _safe_filename(name: str, default: str, suffix: str) -> str:
    """Sanitize a rule-derived filename component to prevent traversal or odd names.

    Strips any directory components and illegal characters so a rule id like
    ``../../evil`` or ``foo/bar`` can never escape its target directory.
    """
    name = (name or "").replace("\\", "/").split("/")[-1].strip()
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]", "_", name).strip("._")
    if not cleaned or cleaned in (".", "..") or cleaned.startswith(".."):
        cleaned = default
    return cleaned + suffix


# ---------------------------------------------------------------------------
# Rule discovery helpers
# ---------------------------------------------------------------------------

def _discover_files(directory: Path, extensions: set) -> List[Path]:
    if not directory.exists():
        return []
    if not directory.is_dir():
        return []
    return sorted(
        p for p in directory.rglob("*") if p.is_file() and p.suffix.lower() in extensions
    )


def _discover_rule_files() -> Dict[str, List[dict]]:
    """Discover all rule files organised by format."""
    result = {}

    # --- Semgrep (.yml under language/category tree + curated flat dir) ---
    sem_files = []
    sem_root = RULE_ROOTS.get("semgrep")
    if sem_root and sem_root.exists():
        for lang_dir in sorted(sem_root.iterdir()):
            if not lang_dir.is_dir():
                continue
            language = SEMGREP_LANGUAGE_MAP.get(lang_dir.name, lang_dir.name)
            for cat_dir in sorted(lang_dir.iterdir()):
                if not cat_dir.is_dir():
                    continue
                for f in sorted(cat_dir.glob("*.yml")):
                    sem_files.append({
                        "path": f,
                        "language": language,
                        "category": cat_dir.name,
                    })
    for f in sorted((CURATED_ROOTS.get("semgrep") or Path()).glob("*.yml")):
        sem_files.append({"path": f, "language": "", "category": "curated"})
    for f in sorted((CURATED_ROOTS.get("semgrep") or Path()).glob("*.yaml")):
        sem_files.append({"path": f, "language": "", "category": "curated"})
    result["semgrep"] = sem_files

    # --- Sigma (.yml under family tree + root + flat roots) ---
    sigma_files = []
    sigma_root = RULE_ROOTS.get("sigma")
    if sigma_root and sigma_root.exists():
        for f in sorted(sigma_root.glob("*.yml")):
            sigma_files.append({"path": f, "family": ""})
        for family_dir in sorted(sigma_root.iterdir()):
            if not family_dir.is_dir():
                continue
            for f in sorted(family_dir.glob("*.yml")):
                sigma_files.append({"path": f, "family": family_dir.name})
    for flat_root in (FLAT_ROOTS.get("sigma"),):
        if flat_root and flat_root.exists():
            for f in sorted(flat_root.glob("*.yml")):
                sigma_files.append({"path": f, "family": ""})
    for f in sorted((CURATED_ROOTS.get("sigma") or Path()).glob("*.yml")):
        sigma_files.append({"path": f, "family": ""})
    for f in sorted((CURATED_ROOTS.get("sigma") or Path()).glob("*.yaml")):
        sigma_files.append({"path": f, "family": ""})
    result["sigma"] = sigma_files

    # --- YARA (.yar / .yara under family tree + root + flat roots) ---
    yara_files = []
    yara_root = RULE_ROOTS.get("yara")
    if yara_root and yara_root.exists():
        for f in sorted(yara_root.glob("*")):
            if f.suffix.lower() in (".yar", ".yara") and f.is_file():
                yara_files.append({"path": f, "family": ""})
        for family_dir in sorted(yara_root.iterdir()):
            if not family_dir.is_dir():
                continue
            for f in sorted(family_dir.glob("*")):
                if f.suffix.lower() in (".yar", ".yara") and f.is_file():
                    yara_files.append({"path": f, "family": family_dir.name})
    for flat_root in (FLAT_ROOTS.get("yara"),):
        if flat_root and flat_root.exists():
            for f in sorted(flat_root.glob("*")):
                if f.suffix.lower() in (".yar", ".yara") and f.is_file():
                    yara_files.append({"path": f, "family": ""})
    for f in sorted((CURATED_ROOTS.get("yara") or Path()).glob("*")):
        if f.suffix.lower() in (".yar", ".yara") and f.is_file():
            yara_files.append({"path": f, "family": ""})
    result["yara"] = yara_files

    # --- Suricata (.rules under family tree + root) ---
    suri_files = []
    suri_root = RULE_ROOTS.get("suricata")
    if suri_root and suri_root.exists():
        for f in sorted(suri_root.glob("*.rules")):
            suri_files.append({"path": f, "family": ""})
        for family_dir in sorted(suri_root.iterdir()):
            if not family_dir.is_dir():
                continue
            for f in sorted(family_dir.glob("*.rules")):
                suri_files.append({"path": f, "family": family_dir.name})
    for f in sorted((CURATED_ROOTS.get("suricata") or Path()).glob("*.rules")):
        suri_files.append({"path": f, "family": ""})
    result["suricata"] = suri_files

    # --- Nuclei (.yaml flat) ---
    nuclei_files = []
    nuclei_root = RULE_ROOTS.get("nuclei")
    if nuclei_root and nuclei_root.exists():
        for f in sorted(nuclei_root.rglob("*")):
            if f.suffix.lower() in (".yaml", ".yml") and f.is_file():
                nuclei_files.append({"path": f, "family": ""})
    for f in sorted((CURATED_ROOTS.get("nuclei") or Path()).glob("*.yaml")):
        nuclei_files.append({"path": f, "family": ""})
    result["nuclei"] = nuclei_files

    # --- CodeQL (.ql under language subdirs) ---
    codeql_files = []
    codeql_root = RULE_ROOTS.get("codeql")
    if codeql_root and codeql_root.exists():
        for f in sorted(codeql_root.rglob("*.ql")):
            if f.is_file():
                lang_dir = f.relative_to(codeql_root).parts[0] if len(f.relative_to(codeql_root).parts) > 1 else ""
                codeql_files.append({"path": f, "family": lang_dir})
    result["codeql"] = codeql_files

    return result


# ---------------------------------------------------------------------------
# Per-format metadata extractors
# ---------------------------------------------------------------------------

def _extract_semgrep(path: Path) -> Optional[dict]:
    try:
        import yaml
        data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
        if not data or "rules" not in data:
            return None
        first = data["rules"][0] if isinstance(data["rules"], list) and data["rules"] else {}
        return {
            "rule_id": first.get("id", path.stem),
            "title": first.get("id", path.stem),
            "description": first.get("message", ""),
            "severity": SEVERITY_SEMGREP.get(first.get("severity", "").upper(), "info"),
            "author": "",
            "languages": first.get("languages", []),
            "rule_count": len(data["rules"]) if isinstance(data["rules"], list) else 1,
        }
    except Exception:
        return {
            "rule_id": path.stem,
            "title": path.stem,
            "description": "",
            "severity": "info",
            "author": "",
            "languages": [],
            "rule_count": 0,
        }


def _extract_sigma(path: Path) -> Optional[dict]:
    try:
        import yaml
        data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
        if not data:
            return None
        explicit = data.get("level", data.get("severity", ""))
        title = data.get("title", path.stem)
        desc = data.get("description", "")
        family = path.parent.name if path.parent else ""
        heuristic_text = f"{family} {title} {desc}"
        severity = _parse_severity_severity(explicit) if explicit else _heuristic_severity(heuristic_text)
        return {
            "rule_id": data.get("id", title),
            "title": title,
            "description": desc,
            "severity": severity,
            "author": data.get("author", ""),
            "status": data.get("status", ""),
            "logsource": data.get("logsource", {}),
        }
    except Exception:
        return {
            "rule_id": path.stem,
            "title": path.stem,
            "description": "",
            "severity": "info",
            "author": "",
        }


def _extract_yara(path: Path) -> Optional[dict]:
    text = path.read_text(encoding="utf-8", errors="replace")
    name_match = re.search(r"rule\s+(\S+)", text)
    rule_name = name_match.group(1) if name_match else path.stem
    meta = {}
    for m in re.finditer(r'^\s+(\w+)\s*=\s*"([^"]*)"', text, re.MULTILINE):
        meta[m.group(1)] = m.group(2)
    threat = meta.get("threat_score", "0")
    try:
        ts = int(threat)
        severity = "critical" if ts >= 90 else "high" if ts >= 70 else "medium" if ts >= 40 else "low"
    except ValueError:
        severity = "medium"
    return {
        "rule_id": rule_name,
        "title": rule_name,
        "description": meta.get("description", meta.get("DESCRIPTION", "")),
        "severity": severity,
        "author": meta.get("author", ""),
        "family": meta.get("family", ""),
        "meta": meta,
        "string_count": len(re.findall(r"^\s+\$", text, re.MULTILINE)),
    }


def _extract_suricata(path: Path) -> Optional[dict]:
    text = path.read_text(encoding="utf-8", errors="replace")
    rules = [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
    first_rule = rules[0] if rules else ""
    msg_match = re.search(r'msg:"([^"]*)"', first_rule)
    sid_match = re.search(r"sid:(\d+)", first_rule)
    msg = msg_match.group(1) if msg_match else path.stem
    family = path.parent.name if path.parent else ""
    heuristic_text = f"{family} {msg}"
    return {
        "rule_id": f"sid:{sid_match.group(1)}" if sid_match else path.stem,
        "title": msg,
        "description": msg,
        "severity": _heuristic_severity(heuristic_text),
        "author": "",
        "rule_count": len(rules),
    }


def _extract_nuclei(path: Path) -> Optional[dict]:
    try:
        import yaml
        data = yaml.safe_load(path.read_text())
        if not data:
            return None
        info = data.get("info", {})
        protocols = [k for k in ("http", "dns", "tcp", "network", "javascript", "file")
                     if k in data]
        return {
            "rule_id": data.get("id", path.stem),
            "title": info.get("name", data.get("id", path.stem)),
            "description": info.get("description", ""),
            "severity": _parse_severity_severity(info.get("severity", "")),
            "author": info.get("author", ""),
            "protocols": protocols,
        }
    except Exception:
        return {
            "rule_id": path.stem,
            "title": path.stem,
            "description": "",
            "severity": "info",
            "author": "",
        }


def _extract_codeql(path: Path) -> Optional[dict]:
    """Extract metadata from a CodeQL .ql query file.

    Parses the JSDoc-style metadata block at the top:
      /**
       * @name Query Name
       * @description What it detects
       * @kind problem
       * @problem.severity error
       * @id lang/query-id
       * @tags security
       */
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    meta = {"name": path.stem, "description": "", "severity": "info",
            "kind": "", "id": path.stem, "tags": ""}

    # Extract JSDoc comment block at the top
    m = re.match(r'/\*\*([^*]|\*[^/])*\*/', text, re.DOTALL)
    if m:
        block = m.group(0)
        for line in block.splitlines():
            line = line.strip().lstrip("*").strip()
            if line.startswith("@name"):
                meta["name"] = line.split(maxsplit=1)[1] if " " in line else path.stem
            elif line.startswith("@description"):
                meta["description"] = line.split(maxsplit=1)[1] if " " in line else ""
            elif line.startswith("@problem.severity"):
                raw = line.split(maxsplit=1)[1] if " " in line else ""
                sev_map = {"error": "high", "warning": "medium", "recommendation": "low"}
                meta["severity"] = sev_map.get(raw.lower(), raw.lower())
            elif line.startswith("@kind"):
                meta["kind"] = line.split(maxsplit=1)[1] if " " in line else ""
            elif line.startswith("@id"):
                meta["id"] = line.split(maxsplit=1)[1] if " " in line else path.stem
            elif line.startswith("@tags"):
                meta["tags"] = line.split(maxsplit=1)[1] if " " in line else ""

    return {
        "rule_id": meta["id"],
        "title": meta["name"],
        "description": meta["description"],
        "severity": meta["severity"],
        "author": "",
        "kind": meta["kind"],
        "tags": meta["tags"],
    }


EXTRACTORS = {
    "semgrep":  _extract_semgrep,
    "sigma":    _extract_sigma,
    "yara":     _extract_yara,
    "suricata": _extract_suricata,
    "nuclei":   _extract_nuclei,
    "codeql":   _extract_codeql,
}

FORMAT_META = {
    "semgrep":  {"label": "Semgrep", "icon": "shield", "extensions": ".yml",
                 "description": "Semgrep SAST rules"},
    "sigma":    {"label": "Sigma", "icon": "file-text", "extensions": ".yml",
                 "description": "Sigma generic log detection rules"},
    "yara":     {"label": "YARA", "icon": "fingerprint", "extensions": ".yar/.yara",
                 "description": "YARA malware identification rules"},
    "suricata": {"label": "Suricata", "icon": "activity", "extensions": ".rules",
                 "description": "Suricata IDS/IPS signatures"},
    "nuclei":   {"label": "Nuclei", "icon": "zap", "extensions": ".yaml",
                 "description": "Nuclei vulnerability templates"},
    "codeql":   {"label": "CodeQL", "icon": "code", "extensions": ".ql",
                 "description": "CodeQL security queries"},
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class RuleManager:
    """Unified rule manager — discover, read, write rules across all formats."""

    def __init__(self):
        self._fp = None
        self._fp_ts = 0.0
        self._fp_interval = 10.0
        self._build_lock = threading.Lock()
        self._disk_cache = Path(CC_DIR) / ".rules_cache.json"
        self._all_cache = None
        self._all_cache_key = None
        self._sig = self._roots_signature()
        self._sig_ts = time.monotonic()
        self._sig_interval = 5.0
        dirs = self._load_disk_dirs()
        if dirs is None:
            dirs = _discover_rule_files()
        self._dirs_by_format = dirs
        self._format_meta = FORMAT_META
        self._extractors = EXTRACTORS

    def _refresh(self):
        """Re-discover rule files (call after create/delete) and rescan."""
        self._dirs_by_format = _discover_rule_files()
        self._all_cache = None
        self._all_cache_key = None
        self._fp = None
        self._fp_ts = 0.0
        self._sig = self._roots_signature()
        self._sig_ts = time.monotonic()

    def _sig_changed(self) -> bool:
        """True if any scan root gained/lost files or subdirs since last check.

        The recursive directory walk is throttled to _sig_interval so the common
        no-change case only re-walks directories every few seconds.
        """
        now = time.monotonic()
        if now - self._sig_ts < self._sig_interval:
            return False
        self._sig_ts = now
        try:
            return self._roots_signature() != self._sig
        except OSError:
            return False

    def _maybe_refresh(self):
        """Re-discover if the scan roots changed since we last looked.

        The root signature keys on directory mtimes, so adding or removing rule
        files invalidates the in-memory file list shortly after the change
        (previously it only refreshed at construction). In-place content edits
        are caught by the per-file fingerprint bounded by _fp_interval.
        """
        if self._sig_changed():
            self._refresh()

    @staticmethod
    def _rel(p: Path) -> str:
        try:
            return p.relative_to(SCRIPTS_DIR).as_posix()
        except ValueError:
            return p.as_posix()

    @staticmethod
    def _abs(rel: str) -> Path:
        p = Path(rel)
        return p if p.is_absolute() else SCRIPTS_DIR / p

    @staticmethod
    def _roots_signature() -> list:
        """Signature of the scan-root directory trees.

        Captures every directory's mtime (recursively, relative to each root).
        Adding/removing a rule file changes its parent directory's mtime, so a
        file gained or lost anywhere under a root invalidates the disk cache —
        not just changes at depth 1. Recomputes are throttled by _sig_interval in
        _sig_changed so repeated requests don't re-walk the tree on every call.
        """
        seen = set()
        sig = []
        for table in (RULE_ROOTS, FLAT_ROOTS, CURATED_ROOTS):
            for p in table.values():
                key = str(p)
                if key in seen or not p.is_dir():
                    continue
                seen.add(key)
                dirs = []
                try:
                    dirs.append(("", p.stat().st_mtime_ns))
                    for d in p.rglob("*"):
                        if d.is_dir():
                            try:
                                dirs.append((d.relative_to(p).as_posix(),
                                             d.stat().st_mtime_ns))
                            except OSError:
                                pass
                except OSError:
                    continue
                dirs.sort()
                sig.append([RuleManager._rel(p), dirs])
        sig.sort(key=lambda s: s[0])
        return sig

    def _fingerprint(self):
        """Fingerprint of discovered rule files (mtime+size) for invalidation.

        Uses paths relative to SCRIPTS_DIR so the disk cache is portable across
        machines that share the same tree (SMB mount). Recomputed at most once
        per _fp_interval so repeated requests avoid stat()-ing every rule file.
        """
        now = time.monotonic()
        if self._fp is not None and (now - self._fp_ts) < self._fp_interval:
            return self._fp
        fp = []
        for entries in self._dirs_by_format.values():
            for e in entries:
                try:
                    st = e["path"].stat()
                    fp.append((self._rel(e["path"]), st.st_mtime_ns, st.st_size))
                except OSError:
                    pass
        self._fp = tuple(fp)
        self._fp_ts = now
        return self._fp

    def _load_disk_dirs(self):
        """Try to restore the discovered file list from the disk cache (skips slow rglob)."""
        try:
            data = json.loads(self._disk_cache.read_text())
        except Exception:
            return None
        if data.get("v") != _CACHE_VERSION:
            return None
        if data.get("roots") != self._roots_signature():
            return None
        raw = data.get("dirs")
        if not isinstance(raw, dict):
            return None
        dirs = {}
        for fmt, entries in raw.items():
            if not isinstance(entries, list):
                return None
            converted = []
            for e in entries:
                if not isinstance(e, dict) or "path" not in e:
                    return None
                p = Path(e["path"])
                if p.is_absolute():
                    try:
                        p = p.relative_to(SCRIPTS_DIR)
                    except ValueError:
                        return None
                item = {k: v for k, v in e.items()}
                item["path"] = SCRIPTS_DIR / p
                converted.append(item)
            dirs[fmt] = converted
        return dirs

    def _load_disk_cache(self, fp):
        try:
            data = json.loads(self._disk_cache.read_text())
            if data.get("v") != _CACHE_VERSION:
                return None
            if [tuple(t) for t in data.get("fp", [])] == list(fp):
                items = data.get("items") or []
                return [dict(it, filepath=str(self._abs(it["filepath"])))
                        if isinstance(it, dict) and it.get("filepath") else it
                        for it in items]
        except Exception:
            pass
        return None

    def _save_disk_cache(self, fp, items):
        try:
            payload = {
                "v": _CACHE_VERSION,
                "roots": self._roots_signature(),
                "fp": list(fp),
                "items": [dict(it, filepath=self._rel(Path(it["filepath"])))
                          if isinstance(it, dict) and it.get("filepath") else it
                          for it in items],
                "dirs": {fmt: [{k: (self._rel(v) if k == "path" else v) for k, v in e.items()}
                               for e in entries]
                         for fmt, entries in self._dirs_by_format.items()},
            }
            tmp = self._disk_cache.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, default=str))
            tmp.replace(self._disk_cache)
        except Exception:
            pass

    @staticmethod
    def _build_item(fmt, entry, extract) -> Optional[dict]:
        path = entry["path"]
        meta = extract(path)
        if not meta:
            return None
        item = {
            "id": meta.get("rule_id", path.stem),
            "title": meta.get("title", path.stem),
            "description": meta.get("description", ""),
            "severity": meta.get("severity", "info"),
            "format": fmt,
            "filepath": str(path),
            "filename": path.name,
            "relpath": path.relative_to(SCRIPTS_DIR).as_posix()
            if SCRIPTS_DIR in path.parents else path.as_posix(),
            "author": meta.get("author", ""),
            **meta,
        }
        # Add format-specific metadata from the discovery entry
        for k, v in entry.items():
            if k != "path":
                item.setdefault(k, v)
        return item

    def _all_rules(self) -> List[dict]:
        """Extract metadata for every discovered rule, cached until files change."""
        self._maybe_refresh()
        fp = self._fingerprint()
        if self._all_cache is not None and self._all_cache_key == fp:
            return self._all_cache
        with self._build_lock:
            if self._all_cache is not None and self._all_cache_key == fp:
                return self._all_cache
            disk = self._load_disk_cache(fp)
            if disk is not None:
                self._all_cache = disk
                self._all_cache_key = fp
                self._save_disk_cache(fp, disk)
                return disk
            pairs = []
            for fmt, entries in self._dirs_by_format.items():
                extract = self._extractors.get(fmt)
                if not extract:
                    continue
                for entry in entries:
                    pairs.append((fmt, entry, extract))
            if not pairs:
                results = []
            else:
                with ThreadPoolExecutor(max_workers=12) as ex:
                    results = [r for r in ex.map(self._build_item, *(zip(*pairs))) if r is not None]
            self._all_cache = results
            self._all_cache_key = fp
            self._save_disk_cache(fp, results)
            return results

    def list_rules(self, rule_format: str = "", severity: str = "",
                   search: str = "", category: str = "") -> List[dict]:
        """List all rules with optional filters."""
        results = list(self._all_rules())
        if rule_format:
            results = [r for r in results if r.get("format") == rule_format]
        if severity:
            sev_list = [s.strip() for s in severity.split(",")]
            results = [r for r in results if r.get("severity", "info") in sev_list]
        if search:
            q = search.lower()
            results = [r for r in results if
                       q in r.get("title", "").lower()
                       or q in r.get("description", "").lower()
                       or q in r.get("id", "").lower()
                       or q in r.get("rule_id", "").lower()]
        if category:
            q = category.lower()
            results = [r for r in results if
                       q in str(r.get("family", "")).lower()
                       or q in str(r.get("language", "")).lower()
                       or q in str(r.get("category", "")).lower()]

        return results

    def _find_rule_paths(self, rule_format: str, rule_id: str) -> List[Path]:
        """All rule files whose extracted id (or stem, as fallback) equals rule_id.

        Exact-id matches take precedence; the filename-stem fallback only applies
        when no file carries the exact id, so a shared stem can't shadow a real
        id match or cause the wrong file to be picked on collisions.
        """
        extract = self._extractors.get(rule_format)
        if not extract:
            return []
        entries = self._dirs_by_format.get(rule_format, [])
        by_id = []
        for entry in entries:
            path = entry["path"]
            meta = extract(path)
            rid = meta.get("rule_id", path.stem) if meta else path.stem
            if rid == rule_id:
                by_id.append(path)
        if by_id:
            return by_id
        return [entry["path"] for entry in entries if entry["path"].stem == rule_id]

    def get_rule(self, rule_format: str, rule_id: str) -> Optional[dict]:
        """Get a single rule by format and ID."""
        self._maybe_refresh()
        extract = self._extractors.get(rule_format)
        if not extract:
            return None
        for path in self._find_rule_paths(rule_format, rule_id):
            meta = extract(path)
            if not meta:
                continue
            rid = meta.get("rule_id", path.stem)
            raw = path.read_text(encoding="utf-8", errors="replace")
            return {
                "id": rid,
                "title": meta.get("title", path.stem),
                "description": meta.get("description", ""),
                "severity": meta.get("severity", "info"),
                "format": rule_format,
                "filepath": str(path),
                "filename": path.name,
                "relpath": path.relative_to(SCRIPTS_DIR).as_posix()
                if SCRIPTS_DIR in path.parents else path.as_posix(),
                "raw": raw,
                "parsed": meta,
                "format_meta": self._format_meta.get(rule_format, {}),
            }
        return None

    def save_rule(self, rule_format: str, rule_id: str, content: str) -> dict:
        """Save updated content to a rule file. Validates before writing."""
        self._maybe_refresh()
        extract = self._extractors.get(rule_format)
        if not extract:
            raise ValueError(f"Unknown format: {rule_format}")
        paths = self._find_rule_paths(rule_format, rule_id)
        if not paths:
            raise FileNotFoundError(f"Rule {rule_format}/{rule_id} not found")
        if len(paths) > 1:
            raise ValueError(
                f"Rule id {rule_format}/{rule_id} is ambiguous "
                f"({len(paths)} files match); refine the id or edit the file "
                f"directly: " + ", ".join(str(p) for p in paths))
        path = paths[0]
        # Validate: try parsing the new content
        if rule_format in ("semgrep", "sigma", "nuclei"):
            import yaml
            try:
                yaml.safe_load(content)
            except Exception as e:
                raise ValueError(f"Invalid YAML: {e}")
        elif rule_format == "yara":
            if not re.search(r"rule\s+\S+\s*{", content):
                raise ValueError("Invalid YARA rule — missing 'rule name {' block")
        elif rule_format == "suricata":
            if not re.search(r"sid:\d+", content):
                raise ValueError("Invalid Suricata rule — missing sid")
        elif rule_format == "codeql":
            if not re.search(r"select\s", content, re.IGNORECASE):
                raise ValueError("Invalid CodeQL query — missing 'select' clause")
        path.write_text(content, encoding="utf-8")
        self._refresh()
        return {"status": "saved", "filepath": str(path)}

    def create_rule(self, rule_format: str, content: str,
                    target_dir: str = "") -> dict:
        """Create a new rule file within the appropriate directory."""
        root = RULE_ROOTS.get(rule_format) or FLAT_ROOTS.get(rule_format)
        if not root:
            raise ValueError(f"No root directory known for format: {rule_format}")
        root.mkdir(parents=True, exist_ok=True)
        if target_dir:
            dest = root / target_dir
        else:
            dest = root
        dest.mkdir(parents=True, exist_ok=True)

        # Derive filename from content where possible
        if rule_format in ("semgrep", "sigma", "nuclei"):
            import yaml
            try:
                data = yaml.safe_load(content) or {}
                if rule_format == "semgrep":
                    rules_list = data.get("rules", [])
                    first = rules_list[0] if rules_list else {}
                    fname = _safe_filename(first.get("id", "new-rule"), "new-rule", ".yml")
                elif rule_format == "sigma":
                    fname = _safe_filename(
                        data.get("id", data.get("title", "new-rule")) or "new-rule",
                        "new-rule", ".yml")
                elif rule_format == "nuclei":
                    fname = _safe_filename(data.get("id", "new-template") or "new-template",
                                           "new-template", ".yaml")
            except Exception:
                fname = "new-rule.yml" if rule_format != "nuclei" else "new-template.yaml"
        elif rule_format == "yara":
            m = re.search(r"rule\s+(\S+)", content)
            fname = _safe_filename(m.group(1) if m else "new_rule", "new_rule", ".yar")
        elif rule_format == "suricata":
            m = re.search(r"sid:(\d+)", content)
            fname = _safe_filename(f"rule_{m.group(1) if m else 'new'}", "rule_new", ".rules")
        elif rule_format == "codeql":
            # Extract @id from metadata block, or use first @name
            id_m = re.search(r'@id\s+(\S+)', content)
            name_m = re.search(r'@name\s+(.+)', content)
            if id_m:
                fname = _safe_filename(id_m.group(1), "new_query", ".ql")
            elif name_m:
                fname = _safe_filename(name_m.group(1), "new_query", ".ql")
            else:
                fname = "new_query.ql"
        else:
            fname = "new-rule.txt"

        filepath = dest / fname
        if filepath.exists():
            base = filepath.stem
            filepath = dest / f"{base}_{datetime.datetime.now(datetime.timezone.utc):%Y%m%d_%H%M%S}{filepath.suffix}"
        filepath.write_text(content, encoding="utf-8")
        self._refresh()
        return {"status": "created", "filepath": str(filepath), "filename": filepath.name}

    def delete_rule(self, rule_format: str, rule_id: str) -> dict:
        """Delete a rule file."""
        self._maybe_refresh()
        extract = self._extractors.get(rule_format)
        if not extract:
            raise ValueError(f"Unknown format: {rule_format}")
        paths = self._find_rule_paths(rule_format, rule_id)
        if not paths:
            raise FileNotFoundError(f"Rule {rule_format}/{rule_id} not found")
        if len(paths) > 1:
            raise ValueError(
                f"Rule id {rule_format}/{rule_id} is ambiguous "
                f"({len(paths)} files match); refine the id or remove the file "
                f"directly: " + ", ".join(str(p) for p in paths))
        path = paths[0]
        path.unlink()
        self._refresh()
        return {"status": "deleted", "filepath": str(path)}

    def get_format_template(self, rule_format: str) -> str:
        """Return a starter template for creating a new rule in a given format."""
        templates = {
            "semgrep": """rules:\n  - id: my-custom-rule\n    message: "Description of what this rule detects"\n    severity: WARNING\n    languages: [python]\n    patterns:\n      - pattern: |\n          dangerous_function(...)\n""",
            "sigma": """title: My Detection Rule\nstatus: experimental\ndescription: Detects something interesting\nlogsource:\n  product: windows\n  service: sysmon\ndetection:\n  selection:\n    - EventID: 1\n  condition: selection\n""",
            "yara": """rule my_rule {\n    meta:\n        description = "Describe what this detects"\n        author = ""\n        severity = "medium"\n    strings:\n        $s1 = "malicious_string" ascii nocase\n    condition:\n        $s1\n}\n""",
            "suricata": """alert tcp any any -> any any (\n    msg:"My Alert - suspicious activity";\n    content:"bad stuff";\n    sid:1000001;\n    rev:1;\n)\n""",
            "nuclei": """id: my-template\ninfo:\n  name: My Template Name\n  author: you\n  severity: medium\n  description: Detects something\nrequests:\n  - method: GET\n    path:\n      - "{{BaseURL}}"\n    matchers:\n      - type: word\n        words:\n          - "vulnerable"\n""",
            "codeql": """/**\n * @name My Security Query\n * @description Detects a potential security vulnerability\n * @kind problem\n * @problem.severity error\n * @id my/security-query\n * @tags security\n */\n\nimport python\n\nfrom ...\nwhere ...\nselect ...\n""",
        }
        return templates.get(rule_format, "# New rule\n")

    def export_rules(self, rule_format: str, rule_ids: Optional[List[str]] = None) -> bytes:
        """Export rules as a ZIP archive in memory.

        If rule_ids is None or empty, exports all rules for the format.
        Returns raw ZIP bytes.
        """
        self._maybe_refresh()
        extract = self._extractors.get(rule_format)
        if not extract:
            raise ValueError(f"Unknown format: {rule_format}")

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for entry in self._dirs_by_format.get(rule_format, []):
                path = entry["path"]
                meta = extract(path)
                rid = meta.get("rule_id", path.stem) if meta else path.stem
                if rule_ids and rid not in rule_ids and path.stem not in rule_ids:
                    continue
                rel = str(path.relative_to(SCRIPTS_DIR)) if SCRIPTS_DIR in path.parents else path.name
                zf.writestr(rel.replace("\\", "/"), path.read_bytes())
        return buf.getvalue()

    def import_rules(self, rule_format: str, content: str,
                     target_dir: str = "") -> dict:
        """Bulk-import rules from a single blob of text.

        Splits on obvious rule boundaries (YAML doc markers, blank-line
        separators) and creates individual rule files via create_rule.
        Returns summary dict with created count and per-file results.
        """
        if not content.strip():
            raise ValueError("Content is empty")

        # Try splitting on --- YAML doc separators (common for multi-rule bundles)
        parts = re.split(r"\n---\n", content)
        if len(parts) < 2:
            # Fallback: try splitting on double-newline between YAML docs or
            # between Suricata rules (blank-line separated)
            parts = [p.strip() for p in re.split(r"\n\n+", content) if p.strip()]
            if len(parts) < 2:
                parts = [content.strip()]

        results = []
        errors = []
        for part in parts:
            part = part.strip()
            if not part:
                continue
            try:
                r = self.create_rule(rule_format, part, target_dir=target_dir)
                results.append(r)
            except (ValueError, Exception) as e:
                errors.append(str(e))

        return {
            "total": len(results) + len(errors),
            "created": len(results),
            "errors": len(errors),
            "results": results,
            "error_details": errors,
        }

    def import_rules_from_zip(self, rule_format: str, zip_bytes: bytes,
                              target_dir: str = "") -> dict:
        """Bulk-import rules from a ZIP archive.

        Extracts all files matching the format's extension and creates
        individual rule files.
        """
        results = []
        errors = []

        ext_map = {
            "semgrep": ".yml", "sigma": ".yml", "yara": ".yar",
            "suricata": ".rules", "nuclei": ".yaml", "codeql": ".ql",
        }
        allowed = ext_map.get(rule_format, ".txt")

        with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if not info.filename.lower().endswith(allowed.lower()):
                    continue
                try:
                    content = zf.read(info.filename).decode("utf-8", errors="replace")
                    r = self.create_rule(rule_format, content, target_dir=target_dir)
                    results.append(r)
                except Exception as e:
                    errors.append(f"{info.filename}: {e}")

        return {
            "total": len(results) + len(errors),
            "created": len(results),
            "errors": len(errors),
            "results": results,
            "error_details": errors,
        }

    def bulk_delete(self, rule_format: str, rule_ids: List[str]) -> dict:
        """Delete multiple rules by ID. Returns summary."""
        deleted = []
        errors = []
        for rid in rule_ids:
            try:
                self.delete_rule(rule_format, rid)
                deleted.append(rid)
            except (FileNotFoundError, Exception) as e:
                errors.append({"rule_id": rid, "error": str(e)})
        if deleted:
            self._refresh()
        return {"deleted": len(deleted), "errors": len(errors),
                "deleted_ids": deleted, "error_details": errors}

    def get_format_stats(self) -> dict:
        """Return counts and summary stats per format."""
        stats = {}
        rules = self._all_rules()
        for fmt, name in [("semgrep", "Semgrep"), ("sigma", "Sigma"),
                          ("yara", "YARA"), ("suricata", "Suricata"),
                          ("nuclei", "Nuclei"), ("codeql", "CodeQL")]:
            by_sev = {}
            total = 0
            for r in rules:
                if r.get("format") != fmt:
                    continue
                total += 1
                s = r.get("severity", "info")
                by_sev[s] = by_sev.get(s, 0) + 1
            stats[fmt] = {
                "label": name,
                "total": total,
                "by_severity": by_sev,
                "roots": [str(p) for p in get_scan_roots(fmt)],
                "meta": self._format_meta.get(fmt, {}),
            }
        return stats
