"""Compiled-binary CLI-surface scanner.

Walks a directory of compiled binaries (ELF/PE/Mach-O) and maps the command
line surface each one exposes: subcommands, option switches, usage strings,
embedded help, interesting strings (URLs, keypaths), and any CVE-ish hints in
embedded version strings. Uses binutils (``file``, ``strings``, ``nm``,
``objdump``, ``readelf``) when available and degrades to pure-Python ELF/PE
parsing otherwise.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Set

from .config import DEFAULT_EXCLUDE_DIRS

MAGIC_MAP = [
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE"),
    (b"\xfe\xed\xfa\xce", "Mach-O (32-bit BE)"),
    (b"\xce\xfa\xed\xfe", "Mach-O (32-bit LE)"),
    (b"\xfe\xed\xfa\xcf", "Mach-O (64-bit BE)"),
    (b"\xcf\xfa\xed\xfe", "Mach-O (64-bit LE)"),
    (b"\xca\xfe\xba\xbe", "Mach-O fat"),
]

OPT_RE = re.compile(r"(\s|^)(--?[a-zA-Z][a-zA-Z0-9-]{1,24})([\s=]|$)")
SUBCMD_RE = re.compile(r"^\s{2,8}([a-z][a-z0-9-]{1,32})\s{2,}", re.MULTILINE)
URL_RE = re.compile(r"https?://[\w./?=&%+-]{6,200}", re.IGNORECASE)
CVE_RE = re.compile(r"(?i)(CVE-\d{4}-\d{3,7})|([vV]ersion\s+([0-9]+\.){2}[0-9]+)")
PATH_RE = re.compile(r"(/[\w.-]+){2,}")


def _run(cmd: list, timeout: int = 60) -> tuple:
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return r.stdout.decode("utf-8", "replace"), r.returncode
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return "", -1


def detect_type(path: Path) -> str:
    try:
        head = path.open("rb").read(4)
    except OSError:
        return "unknown"
    for magic, label in MAGIC_MAP:
        if head.startswith(magic):
            return label
    return "unknown"


def is_executable(path: Path) -> bool:
    if not path.is_file():
        return False
    if path.stat().st_size == 0:
        return False
    try:
        if path.stat().st_mode & 0o111:
            return True
    except OSError:
        pass
    # Also accept PE/ELF regardless of exec bit (common on mounted shares).
    return detect_type(path) in ("ELF", "PE")


def _file_label(path: Path) -> str:
    """Use `file` for a richer description when available."""
    if shutil.which("file"):
        out, _ = _run(["file", "-b", str(path)])
        return out.strip()
    return detect_type(path)


def _elf_arch(path: Path) -> str:
    if shutil.which("readelf"):
        out, _ = _run(["readelf", "-h", str(path)])
        m = re.search(r"Machine:\s+([\w-]+)", out)
        return m.group(1) if m else "unknown"
    return "unknown"


def _string_surface(path: Path, min_len: int = 6) -> Dict:
    """Extract strings + binutils-derived info."""
    s = {"strings": [], "nm": [], "symbols": 0}
    if shutil.which("strings"):
        out, _ = _run(["strings", "-n", str(min_len), str(path)], timeout=120)
        s["strings"] = [ln for ln in out.splitlines() if ln.strip()]
    else:
        # Pure-Python fallback (works on Windows / minimal hosts).
        s["strings"] = _py_strings(path, min_len)
    if shutil.which("nm"):
        out, _ = _run(["nm", "-C", "--defined-only", str(path)], timeout=120)
        s["nm"] = [ln.strip() for ln in out.splitlines() if ln.strip()][:500]
        s["symbols"] = len(out.splitlines())
    return s


def _py_strings(path: Path, min_len: int = 6, max_len: int = 1024) -> list:
    """Minimal GNU-strings equivalent for binaries (ASCII + UTF-16LE runs)."""
    out = []
    try:
        data = path.open("rb").read()
    except OSError:
        return out
    cur, start = [], None
    for i, b in enumerate(data):
        if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D):
            if start is None:
                start = i
            cur.append(b)
        else:
            if start is not None and len(cur) >= min_len:
                out.append(bytes(cur).decode("ascii", "replace"))
            cur, start = [], None
    if start is not None and len(cur) >= min_len:
        out.append(bytes(cur).decode("ascii", "replace"))
    # UTF-16LE pass (scan aligned words).
    if len(data) > 2:
        s = "".join(chr(data[i] | (data[i + 1] << 8))
                    for i in range(0, len(data) - 1, 2))
        for m in re.finditer(r"[\x20-\x7e]{%d,}" % min_len, s):
            out.append(m.group(0)[:max_len])
    return out


def _pe_version_info(path: Path) -> Dict:
    """Best-effort PE version metadata (needs pefile; falls back to `exiftool`)."""
    out = {}
    try:
        import pefile  # type: ignore
        pe = pefile.PE(str(path), fast_load=True)
        try:
            for finfo in pe.FileInfo:
                for entry in finfo:
                    if getattr(entry, "Key", None) == b"StringFileInfo":
                        for st in entry.StringTable:
                            for k, v in st.entries.items():
                                out[k.decode(errors="replace")] = v.decode(errors="replace")
        except Exception:
            pass
        pe.close()
    except Exception:
        pass
    if not out and shutil.which("exiftool"):
        raw, _ = _run(["exiftool", "-ProductName", "-ProductVersion", "-FileVersion",
                       "-CompanyName", str(path)], timeout=60)
        for ln in raw.splitlines():
            if ":" in ln:
                k, _, v = ln.partition(":")
                out[k.strip()] = v.strip()
    return out


def scan_binary(path: Path, with_strings: bool = True) -> Dict:
    """Analyze a single binary for its CLI surface."""
    info: Dict = {
        "file": str(path),
        "name": path.name,
        "type": detect_type(path),
        "size": path.stat().st_size,
        "arch": "",
        "version_info": {},
        "options": [],
        "subcommands": [],
        "usage_hints": [],
        "urls": [],
        "cve_hints": [],
        "paths": [],
        "symbol_count": 0,
    }
    if info["type"] == "ELF":
        info["arch"] = _elf_arch(path)
    if info["type"] == "PE":
        info["version_info"] = _pe_version_info(path)

    if with_strings:
        ss = _string_surface(path)
        strs = ss["strings"]
        info["symbol_count"] = ss["symbols"]

        # Option switches (filter out common false positives).
        opts = []
        for ln in strs:
            for m in OPT_RE.finditer(ln):
                o = m.group(2)
                if len(o) <= 24 and o not in ("--", "--help", "--version"):
                    opts.append(o)
        info["options"] = sorted(set(opts))[:80]

        # Help/usage lines.
        info["usage_hints"] = [ln[:160] for ln in strs
                               if re.search(r"Usage:|usage:|SYNOPSIS|COMMANDS|Options:", ln)][:20]

        # Subcommands from `COMMANDS:`/`Usage:` blocks.
        subcmds = set()
        for ln in strs:
            if re.search(r"^\s*(Usage|COMMANDS|SUBCOMMANDS|Commands)", ln):
                for m in SUBCMD_RE.finditer(ln):
                    subcmds.add(m.group(1))
            m = re.search(r"\b(?:Usage:)\s+\S+\s+(\[\w+\]|\w+)?\s*(<command>|\{cmd\}|\[command\])", ln)
            if m:
                pass
        info["subcommands"] = sorted(subcmds)[:80]

        # Interesting strings.
        info["urls"] = sorted(set(URL_RE.findall("\n".join(strs))))[:20]
        info["cve_hints"] = list(dict.fromkeys(CVE_RE.findall("\n".join(strs))))[:20]
        info["cve_hints"] = [h[0] or h[1] for h in info["cve_hints"] if h]
        info["paths"] = sorted(set(PATH_RE.findall("\n".join(strs))))[:20]
    return info


def scan_directory(root: Path, max_depth: int = 3, with_strings: bool = True,
                   include_types: Optional[List[str]] = None,
                   exclude_dirs: Optional[Set[str]] = None) -> Dict:
    """Scan a directory tree for compiled binaries and summarize their surface.

    exclude_dirs: directory names to skip during the walk (defaults to
    DEFAULT_EXCLUDE_DIRS — includes `cases`, which holds engagement artifacts).
    """
    include_types = include_types or ["ELF", "PE"]
    ex = set(exclude_dirs) if exclude_dirs is not None else set(DEFAULT_EXCLUDE_DIRS)
    files: List[Path] = []
    root = Path(root)
    try:
        entries = _rglob_depth(root, max_depth, ex) if max_depth > 0 else \
            _rglob_depth(root, 10 ** 9, ex)
    except OSError as e:
        return {"error": str(e)}
    for p in entries:
        if not is_executable(p):
            continue
        t = detect_type(p)
        if t in include_types:
            files.append(p)
    results = []
    errors = []
    for p in files[:500]:
        try:
            results.append(scan_binary(p, with_strings=with_strings))
        except Exception as e:  # noqa: BLE001
            errors.append({"file": str(p), "error": str(e)})
    return {"target": str(root), "scanned": len(files), "results": results,
            "errors": errors, "found": len(results)}


def _rglob_depth(root: Path, max_depth: int, exclude: Set[str]) -> List[Path]:
    out = []
    stack = [(root, 0)]
    while stack:
        d, depth = stack.pop()
        if depth > max_depth:
            continue
        try:
            for p in d.iterdir():
                if p.is_dir():
                    if p.name not in exclude:
                        stack.append((p, depth + 1))
                else:
                    out.append(p)
        except OSError:
            continue
    return out


def format_report(r: Dict) -> str:
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    lines = [f"Binary CLI-surface scan of {r.get('target')}: {r.get('found')} binary(s) "
             f"({r.get('scanned')} scanned)"]
    for b in r.get("results", []):
        lines.append("")
        lines.append(f"== {b['name']} ({b['type']}{'/' + b['arch'] if b.get('arch') else ''}, {b['size']} B)")
        if b.get("version_info"):
            vi = ", ".join(f"{k}={v}" for k, v in list(b["version_info"].items())[:5])
            lines.append(f"  version: {vi}")
        if b.get("subcommands"):
            lines.append(f"  subcommands: {', '.join(b['subcommands'][:25])}")
        if b.get("options"):
            lines.append(f"  options: {', '.join(b['options'][:30])}")
        if b.get("usage_hints"):
            lines.append(f"  usage: {b['usage_hints'][0]}")
        if b.get("urls"):
            lines.append(f"  urls: {', '.join(b['urls'][:8])}")
        if b.get("cve_hints"):
            lines.append(f"  cve/version hints: {', '.join(b['cve_hints'][:8])}")
        if b.get("paths"):
            lines.append(f"  paths: {', '.join(b['paths'][:8])}")
        if b.get("symbol_count"):
            lines.append(f"  symbols: {b['symbol_count']}")
    for e in r.get("errors", [])[:5]:
        lines.append(f"  ERR {e['file']}: {e['error']}")
    return "\n".join(lines)
