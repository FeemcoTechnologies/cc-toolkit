"""Language detection for native binaries + fast symbol indexing.

Serves the "surface triage" model: before any deep analysis we work out what
kind of binary we have (Go / Rust / C-C++ / C# / unknown), where its real
entry points are, and how to cheaply enumerate symbols.  Everything here is
bounded (readelf/nm/go tool nm, never r2 `aaa`), so it is safe even on
hundreds-of-MB blobs and truncated ELFs.
"""

import os
import re
import shutil
import struct
import subprocess

from . import r2util


_GO_FILE_MARKERS = {
    ".gopclntab": "has Go pclntab section",
    ".go.buildinfo": "Go build info section",
    ".note.go.buildid": "has Go build-ID note",
}
_RUST_FILE_MARKERS = {
    ".rustc": "rustc metadata section",
    "rust_eh_personality": "Rust EH personality symbol",
}
_GO_PREFIX_RE = re.compile(r"^(?:net|http|runtime|fmt|io|encoding|syscall|bufio|os|main)(?:/|\.|\s)")
_RUST_MANGLE_RE = re.compile(r"^_ZN(4core|3std|4main|3tokio|3mio)\b")
_GO_PREFIX_PROBE = re.compile(rb"(gopclntab|Go build ID|runtime\.main|buildVersion)")


def detect_language(path: str, symbols: list[dict] | None = None) -> dict:
    """Best-effort language detection.

    Returns language (go|rust|cs|cc|unknown), confidence, evidence list,
    entry candidates, and a symbol-index capability report.
    """
    result: dict = {"path": path, "language": "unknown", "confidence": "low", "evidence": []}
    if not os.path.isfile(path):
        return result

    low = ""
    try:
        finfo = subprocess.check_output(["file", path], text=True, timeout=5).strip()
        low = finfo.lower()
    except Exception:
        finfo = ""
    result["file_info"] = finfo[:160]

    if "elf" not in low and "mach-o" not in low and "pe32" not in low and "pe64" not in low and "ms-dos" not in low:
        result["note"] = "not a native executable; language detection skipped"
        return result

    # --- section-header based markers (fast, reliable when headers exist) ---
    sections = _readelf_section_names(path)
    for marker, desc in _GO_FILE_MARKERS.items():
        if marker in sections:
            result["evidence"].append(desc)
    for marker, desc in _RUST_FILE_MARKERS.items():
        if marker in sections:
            result["evidence"].append(desc)

    no_sections = "missing section headers" in low or not sections

    # --- prefix probe for truncated ELFs / huge blobs (bounded 5s, 4MB) ---
    if no_sections and not any(True for e in result["evidence"] if "pclntab" in e or "build" in e):
        try:
            with open(path, "rb") as f:
                head = f.read(4 * 1024 * 1024)
            if _GO_PREFIX_PROBE.search(head):
                result["evidence"].append("Go runtime markers in file header")
        except Exception:
            pass

    # --- symbol-based markers ---
    funcs, imports = (symbols or ([], [])) if isinstance(symbols, tuple) else ([], [])
    if not funcs and symbols is None:
        funcs, imports = _readelf_symbols(path)
    names = {f.get("name", "") for f in funcs}
    names.update({i.get("name", "") for i in imports})

    go_hits = [n for n in names if _GO_PREFIX_RE.search(n) and "." in n]
    rust_mangled = [n for n in names if _RUST_MANGLE_RE.search(n)]
    rust_eh = any(n == "rust_eh_personality" for n in names)

    if go_hits or any("pclntab" in e or "build" in e for e in result["evidence"]):
        result["language"] = "go"
        result["confidence"] = "high" if (go_hits or "pclntab" in " ".join(result["evidence"])) else "medium"
        result["evidence"].append(f"{len(go_hits)} Go-style symbols (e.g. {sorted(go_hits)[:3]})")
    elif rust_mangled or rust_eh:
        result["language"] = "rust"
        result["confidence"] = "high" if rust_mangled else "medium"
        result["evidence"].append(f"{len(rust_mangled)} Rust mangled symbols")
        result["evidence"].append(f"{len([f for f in funcs if not f['addr']])} rust symbols @0 listed (no addr)")
    elif any(e.startswith("Go") for e in result["evidence"]):
        result["language"] = "go"
    elif "mscoree" in " ".join(names) or "mscorlib" in " ".join(names) or "clr" in " ".join(names).lower():
        result["language"] = "cs"
        result["confidence"] = "medium"
        result["evidence"].append("CLR/.NET imports present (native dotnet image likely)")

    if result["language"] == "unknown" and funcs and any(n == "main" for n in names):
        result["language"] = "cc"
        result["confidence"] = "medium"
        result["evidence"].append("has a `main` symbol (C/C++ typical)")
    elif result["language"] == "unknown" and (funcs or imports):
        result["language"] = "cc"
        result["confidence"] = "low"
        result["evidence"].append("ELF with symbols; no Go/Rust markers (default cc)")

    # --- entry candidates ---
    entries = _entry_candidates(path, result["language"], funcs, imports, finfo)
    result["entry_candidates"] = entries[:8]
    if not entries:
        result["entry_candidates"] = [{"entry": _elf_entry(path), "who": "ELF entry point"}]

    # Go: surface the real seams even when readelf is useless (stripped).
    if result["language"] == "go":
        have = {e.get("name") for e in result["entry_candidates"]}
        if not any(n == "main.main" or n == "runtime.main" for n in have):
            pc, _ = go_pclntab_names(path, cap=1500)
            pc_names = {f["name"] for f in pc}
            for seam in ("main.main", "runtime.main"):
                if seam in pc_names and seam not in have:
                    result["entry_candidates"].append(
                        {"name": seam, "addr": None, "kind": "pclntab"})
                    have.add(seam)
            if any(e.get("kind") == "pclntab" for e in result["entry_candidates"]):
                result["evidence"].append("entry seams recovered from .gopclntab (stripped Go)")

    # --- symbol index capability ---
    result["symbol_index"] = {
        "funcs_found": len(funcs),
        "imports_found": len(imports),
        "local_missing": no_sections,
        "enrichment": _enrichment_available(path, result["language"]),
        "could_go_nm": result["language"] == "go" and shutil.which("go") is not None,
    }

    if result["language"] != "unknown" and not result["evidence"]:
        result["evidence"].append("section/symbol heuristics")
    return result


def _enrichment_available(path: str, language: str) -> str:
    """What extra symbol source exists beyond readelf (gopclntab etc.)."""
    if language == "go":
        try:
            sect = subprocess.check_output(
                ["readelf", "-S", path], text=True, timeout=8, stderr=subprocess.DEVNULL
            )
            if ".gopclntab" in sect:
                return "gopclntab name table (recover function names even when stripped)"
        except Exception:
            pass
    return "none"


def _readelf_sections(path: str, timeout: int = 8) -> dict[str, dict]:
    """Map section name -> {offset, size} (bytes in file), via readelf -S -W."""
    sections: dict[str, dict] = {}
    try:
        out = subprocess.check_output(
            ["readelf", "-S", "-W", path], text=True,
            timeout=timeout, stderr=subprocess.DEVNULL,
        )
    except Exception:
        return sections
    for line in out.splitlines():
        # "[ 8] .gopclntab PROGBITS 0000000000578628 00178628 001081a8 ..."
        m = re.match(
            r"\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)",
            line,
        )
        if not m:
            continue
        sections[m.group(1)] = {
            "offset": int(m.group(2), 16),
            "size": int(m.group(3), 16),
        }
    return sections


_GO_FUNC_NAME_RE = re.compile(
    r"^[A-Za-z0-9_./:*-]+(?:\([^()]*\)[A-Za-z0-9_.()/:*-]*)?$"
)


def _section_vaddr(path: str, name: str, timeout: int = 8) -> int:
    """Virtual address of a section via readelf -S -W (split-based, robust)."""
    try:
        out = subprocess.check_output(
            ["readelf", "-S", "-W", path], text=True,
            timeout=timeout, stderr=subprocess.DEVNULL,
        )
    except Exception:
        return 0
    for line in out.splitlines():
        parts = line.split()
        # [ 1] .text PROGBITS 0000000000401000 001000 b4f0d1 ...
        if len(parts) >= 5 and parts[0] == "[" and parts[2] == name:
            try:
                return int(parts[4], 16)
            except ValueError:
                return 0
    return 0


_GO_PCLN_MAGICS = {
    0xfffffff0: (118, "Go 1.18-1.19 pclntab"),
    0xfffffff1: (120, "Go 1.20+ pclntab"),
}


def go_pclntab_symbols(path: str, max_bytes: int = 128 * 1024 * 1024) -> tuple[list[dict], str]:
    """Recover Go function names *and* entry addresses from .gopclntab.

    Faithful port of debug/gosym's ver118/ver120 parser (Go 1.18+), which is
    what the runtime itself uses:

        header (72 bytes for ptrsize=8): magic u32; byte4/5 pad; byte6 minLC;
        byte7 ptrSize; then 8 uintptr words at 8+i*ptrSize:
            w0 = nfunctab, w1 = nfiletab, w2 = textStart,
            w3 = funcnameOffset, w4 = cuOffset, w5 = filetabOffset,
            w6 = pctabOffset, w7 = functab/funcdata base offset.
        functab (at base w7): nfunc*2+1 uint32 fields:
            [2i]   = entry offset into text (add textStart)
            [2i+1] = _func metadata offset from the funcdata base
        _func metadata: entryoff u32 @0, nameoff i32 @4, ...
        funcnametab (at w3): name = funcnameOffset + nameoff, NUL-terminated.

    Magic values: 0xfffffff0 = Go 1.18-1.19, 0xfffffff1 = Go 1.20+.
    Tries both magics/endiannesses, scores by number of structurally valid
    funcs.  Falls back to the name-only scanner on total parse failure.

    Returns ([{name, addr, type, bind}], note).  addr is a hex string.
    """
    try:
        meta = _readelf_sections(path).get(".gopclntab")
        if not meta:
            return [], "no .gopclntab section"
        with open(path, "rb") as f:
            f.seek(meta["offset"])
            raw = f.read(min(meta["size"], max_bytes))
    except Exception as e:
        return [], f"gopclntab read failed: {str(e)[:120]}"
    if len(raw) < 72:
        return [], "gopclntab too small for header"

    text_sec = _readelf_sections(path).get(".text")
    text_vaddr = _section_vaddr(path, ".text")
    text_size = text_sec["size"] if text_sec else 0
    text_lo, text_hi = text_vaddr, (text_vaddr + text_size) if text_size else 0

    def try_version(magic_target, order, note):
        """Parse one (magic, endianness) candidate; return (funcs, err)."""
        order = "<" if order == "<" else ">"
        magic = struct.unpack_from(order + "I", raw, 0)[0]
        ver, vname = _GO_PCLN_MAGICS.get(magic, (None, None))
        if not ver:
            return [], f"unrecognized pclntab magic 0x{magic:08x}"
        if raw[4] != 0 or raw[5] != 0 or raw[6] not in (1, 2, 4) or raw[7] not in (4, 8):
            return [], "bad quantum/ptrSize header bytes"
        ptr = raw[7]
        if len(raw) < 8 + 8 * ptr:
            return [], "pclntab truncated for word table"
        words = [struct.unpack_from(order + ("Q" if ptr == 8 else "I"), raw, 8 + i * ptr)[0]
                 for i in range(8)]
        nfunc, nfiletab, text_start = words[0], words[1], words[2]
        fnm_off, funcdata_off = words[3], words[7]
        if nfunc == 0 or nfunc > (len(raw) // 4):
            return [], f"implausible nfunc {nfunc}"
        if fnm_off >= len(raw) or funcdata_off >= len(raw):
            return [], f"table offsets out of range ({fnm_off}, {funcdata_off})"
        if not text_start:
            text_start = text_vaddr
        ft_w = 4 if ptr == 8 else ptr  # functab field width (ver118+ = 4)
        ftab_base = funcdata_off
        ft_size = (int(nfunc) * 2 + 1) * ft_w
        if ftab_base + ft_size > len(raw):
            ft_size = len(raw) - ftab_base
        out: list[dict] = []
        seen: set[tuple] = set()
        for i in range(nfunc):
            if i * 2 * ft_w + ft_w > ft_size:
                break
            func_off = struct.unpack_from(
                order + ("I" if ft_w == 4 else ("Q" if ft_w == 8 else "I")),
                raw, ftab_base + (2 * i + 1) * ft_w)[0]
            fpos = funcdata_off + func_off
            if fpos + 8 > len(raw):
                continue
            entry_off = struct.unpack_from(order + "I", raw, fpos)[0]
            name_off = struct.unpack_from(order + "i", raw, fpos + 4)[0]
            addr = text_start + entry_off
            if text_hi and not (text_lo <= addr < text_hi):
                continue
            npos = fnm_off + name_off
            if not (0 <= npos < len(raw)):
                continue
            end = raw.find(b"\x00", npos)
            if end < 0 or end - npos > 512:
                continue
            nm = raw[npos:end].decode(errors="ignore")
            if not _GO_FUNC_NAME_RE.fullmatch(nm):
                continue
            if nm.startswith(("$f32.", "$f64.", "$f.", "$g.", "gofunc", ".")):
                continue
            key = (nm, addr)
            if key in seen:
                continue
            seen.add(key)
            out.append({"name": nm, "addr": hex(addr), "type": "FUNC", "bind": "PC"})
        if not out:
            return [], "0 valid funcs"
        return out, f"{vname} ({nfunc} entries in functab{'-wide' if ft_w == 8 else ''})"

    funcs, note = [], ""
    for order in ("<", ">"):
        f, n = try_version(raw[0], order, "")
        if len(f) > len(funcs):
            funcs, note = f, n
        if len(funcs) >= 1000:
            break
    if len(funcs) < 1000:
        funcs, note = go_pclntab_names(path)
        return funcs, f"pclntab parse too weak; fell back to name scan: {note}"
    note = (f"{len(funcs)} Go funcs + addresses via pclntab "
            f"({note}, text {hex(text_vaddr)}..{hex(text_hi)})")
    return funcs, note


def go_pclntab_names(path: str, cap: int = 3000, max_bytes: int = 24 * 1024 * 1024) -> tuple[list[dict], str]:
    """Recover Go function names from .gopclntab on binaries without .symtab.

    Works on stripped Go binaries (go tool nm needs .symtab). Returns function
    records with addr=None (no addresses in the name table alone).
    """
    try:
        meta = _readelf_sections(path).get(".gopclntab")
        if not meta:
            return [], "no .gopclntab section"
        off, size = meta["offset"], meta["size"]
        with open(path, "rb") as f:
            f.seek(off)
            raw = f.read(min(size, max_bytes))
        note = f"{size} byte .gopclntab"
        if size > max_bytes:
            note += f" (read capped at {max_bytes} bytes)"
    except Exception as e:
        return [], f"gopclntab read failed: {str(e)[:120]}"

    names: set[str] = set()
    for s in re.findall(rb"[\x20-\x7e]{4,}", raw):
        n = s.decode(errors="ignore")
        if not _GO_FUNC_NAME_RE.fullmatch(n):
            continue
        if n.startswith(("$f32", "$f64", "$f", "$g", "gofunc", "\x00", ".")):
            continue
        if n.lstrip("0123456789abcdef") == "":
            continue  # pure hex constant
        if n.count("(") != n.count(")"):
            continue
        names.add(n)

    # package order can bury attack-relevant names (net./http./main./json.)
    # behind huge stdlib prefix blocks, so protect them from the cap.
    _PRIORITY = re.compile(r"(net\.|main\.|http\.|tls\.|json\.|xml\.|gob\.|proto|archive/|compress/|encoding|grpc|\.Accept\.|Listen|Serve|os\.|flag\.|pflag\.)")
    priority = sorted((n for n in names if _PRIORITY.search(n)), key=len)
    rest = [n for n in names if not _PRIORITY.search(n)]
    ordered = priority + rest
    funcs = [{"name": n, "type": "FUNC", "addr": None, "bind": "PCLNTAB"} for n in ordered[:cap]]
    return funcs, f"{len(funcs)} Go func names via .gopclntab ({note} of {len(names)} candidates)"


def go_nm(path: str, cap: int = 4000, timeout: int = 20) -> tuple[list[dict], str]:
    """Symbols via `go tool nm` (works only when .symtab survived)."""
    go = shutil.which("go")
    if not go:
        return [], "go toolchain not installed"
    try:
        out = subprocess.check_output(
            [go, "tool", "nm", path], text=True, timeout=timeout, stderr=subprocess.DEVNULL
        )
    except Exception as e:
        return [], f"go tool nm failed: {str(e)[:120]}"
    funcs = []
    for line in out.splitlines()[:cap]:
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            addr = int(parts[0], 16)
        except ValueError:
            continue
        typ, name = parts[1], " ".join(parts[2:])
        if typ in ("T", "t", "B", "b", "D", "d", "R", "r", "Z", "z") and addr:
            funcs.append({"name": name, "type": "FUNC", "addr": addr, "bind": "GO_NM"})
    return funcs, f"{len(funcs)} Go funcs via go tool nm"


def _readelf_symbols(path: str, timeout: int = 12) -> tuple[list[dict], list[dict]]:
    """Return (defined funcs, undefined imports) parsed from readelf -Ws."""
    funcs, imports = [], []
    try:
        out = subprocess.check_output(
            ["readelf", "-Ws", path], text=True,
            timeout=timeout, stderr=subprocess.DEVNULL,
        )
    except Exception:
        return funcs, imports
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 8:
            continue
        name = parts[-1]
        try:
            typ, bind, ndx = parts[3], parts[4], parts[6]
            addr = int(parts[1], 16)
        except Exception:
            continue
        if typ not in ("FUNC", "OBJECT"):
            continue
        if ndx == "UND":
            imports.append({"name": name, "type": typ})
        elif addr:
            funcs.append({"name": name, "type": typ, "addr": addr, "bind": bind})
    return funcs, imports


def _readelf_section_names(path: str, timeout: int = 8) -> list[str]:
    try:
        out = subprocess.check_output(
            ["readelf", "-S", path], text=True, timeout=timeout, stderr=subprocess.DEVNULL
        )
        return re.findall(r"\[\s*\d+\]\s+([A-Za-z0-9_.]+)", out)
    except Exception:
        return []


def _elf_entry(path: str) -> str:
    try:
        return r2util.fast_elf_info(path).get("entry", "0x0")
    except Exception:
        return "?"


def _entry_candidates(path: str, lang: str, funcs: list[dict], imports: list[dict], finfo: str) -> list[dict]:
    """Project the language-appropriate entry seams (what an input reaches)."""
    cands: list[dict] = []
    if lang == "go":
        for want in ("runtime.main", "runtime.rt0_go", "main.main",
                     "runtime.wbBufFlush", "runtime.syscall"):
            for f in funcs:
                if f["name"] == want:
                    cands.append({"name": want, "addr": hex(f["addr"]), "kind": "go-entry"})
                    break
    elif lang == "rust":
        for f in funcs:
            n = f["name"]
            if "lang_start" in n or n == "main" or "::main" in _demangle(n):
                cands.append({"name": n, "addr": hex(f["addr"]), "kind": "rust-entry"})
            if len(cands) >= 4:
                break
    else:  # cc or unknown
        for want in ("main", "_start"):
            for f in funcs:
                if f["name"] == want:
                    cands.append({"name": f["name"], "addr": hex(f["addr"]), "kind": "entry"})
                    break
            if cands:
                break
    if not cands and funcs:
        cands.append({"name": funcs[0]["name"], "addr": hex(funcs[0]["addr"]), "kind": "sym"})
    if not cands:
        cands.append({"name": "(none in symtab)", "addr": _elf_entry(path), "kind": "entry"})
    return cands


def _demangle(name: str) -> str:
    """Demangle Rust/Itanium names via c++filt (hash suffix stripped first)."""
    cand = re.sub(r"\.\d+$", "", name)  # .llvm.<n> suffixes
    try:
        out = subprocess.check_output(
            ["c++filt"], input=cand.encode("utf-8"), text=True, timeout=3
        ).strip()
        return out
    except Exception:
        return name


# convenience wrapper so remote_surface/tools share one symbol source
def index_symbols(path: str, timeout: int = 12) -> dict:
    funcs, imports = _readelf_symbols(path, timeout)
    lang = detect_language(path, (funcs, imports))
    return {
        "path": path,
        "language": lang.get("language"),
        "funcs": funcs,
        "imports": imports,
        "entry_candidates": lang.get("entry_candidates", []),
        "evidence": lang.get("evidence", []),
    }