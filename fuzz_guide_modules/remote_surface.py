"""Remote-attack-surface scanner.

Implements the "work inward from the sink" model: instead of analyzing a whole
binary, we (1) cheaply index symbols, (2) classify symbols into sink
categories (network / parsing / archive / serialization / crypto), (3) walk
callers upward from the most interesting sinks (bounded, region-scoped), and
(4) emit ranked fuzz-entry candidates + a remote-fuzzability verdict.

Safe on huge binaries: symbol indexing is readelf/nm based and the caller
walk is capped per sink; truncated ELFs short-circuit quickly.
"""

import os
import re
import subprocess

from . import language_profile, r2util


_SINK_MARKERS: dict[str, list[str]] = {
    # category -> substring fragments (matched against lowercased symbol
    # name; for Rust also against the demangled name)
    "network": [
        "accept", "recv", "recvfrom", "recvmsg", "wsarecv", "_read(",
        "read@plt", "socket", "listen", "connect", "getaddrinfo", "select",
        "epoll_wait", "poll(", "recvmmsg", "readv", "implrecv",
        # Go / Rust style
        "net.", ".listen", ".accept", ".read", "http.", "tcpstream",
        "tcplistener", "std::net", "tokio", "mio::", "syscall.read",
    ],
    "parsing": [
        "sscanf", "fscanf", "scanf", "strtol", "strtod", "atoi", "parse",
        "decode", "json", "xml", "yaml", "toml", "protobuf", "msgpack",
        "unmarshal", "deserialize", "regexec", "regex::", "nom::", "simdjson",
    ],
    "archive": [
        "inflate", "deflate", "uncompress", "gzip", "zlib", "bz2", "lz4",
        "zstd", "libarchive", "archive/", "unzip", "zip", "tar", "7z",
    ],
    "serialization": [
        "sprintf", "vsnprintf", "strcpy", "strncpy", "memcpy", "wcstombs",
        "wsprintf", "format::", "fmt.fprint", "append",
    ],
    "crypto": [
        "md5", "sha1", "sha256", "sha512", "aes", "rsa", "chacha", "blake",
        "openssl", "crypto/", "hash", "hmac", "bcrypt",
    ],
}
_CAT_WEIGHT = {"network": 3, "parsing": 2, "archive": 2, "serialization": 2, "crypto": 1}
_RUST_PRECHEK = re.compile(r"^_(?:ZN[34](?:std|core|tokio|mio)|ZN.*(?:net|json|tokio|socket))", re.I)
_GO_PRECHEK = re.compile(r"(net|http|json|xml|archive|compress|encoding)/?[\./]")

# Go: grade on receiver/package semantics instead of raw substring fragments,
# so `bufio.(*Reader).Read` / `internal/runtime/cgroup` / cgo stubs aren't
# miscategorized as network entry points.
_GO_PKG_NET = ("net.", "http.", "grpc", "tcp", "socket", "tls.", "websocket", "ftp.", "ssh.")
_GO_PKG_NET_VERB = ("accept", "listen", "dial", "read", "recv", "connect", "handshake",
                    "addr", "conn", "request", "header", "serve")
_GO_PKG_PARSE = ("json.", "xml.", "gob.", "yaml.", "toml.", "proto", "msgpack", "csv.",
                 "html", "template.", "scanner", "lexer", "parser", "form.", "url.", "query.")
_GO_PKG_ARCH = ("archive/", "gzip", "zip.", "tar.", "compress/", "flate", "zlib", "zstd",
                "brotli", "lz4", "snappy", "png", "jpeg", "gif", "webp")
_GO_PKG_CRYPTO = ("crypto/", "sha", "md5", "aes", "rsa", "hmac", "x509", "ecdsa", "chacha",
                  "blake", "pbkdf", "bcrypt", "argon2")
_GO_PKG_SER = ("bytes.", "strings.", "encoding/binary.")


def _go_category(name: str) -> list[str]:
    """Package/verb-aware Go sink classification."""
    low = name.lower()
    if low.startswith(("_cgo_", "go:", "runtime.", "internal/")):
        return []
    seg = low.split("/")[-1]
    pkg = seg.split("(")[0]          # "net.(*TCPListener).Accept" -> "net."
    verb = seg.split(")")[-1] if ")" in seg else seg  # verb after the receiver
    hits = []
    if any(s in pkg for s in _GO_PKG_NET) and any(v in verb for v in _GO_PKG_NET_VERB):
        hits.append("network")
    if any(s in pkg for s in _GO_PKG_PARSE):
        hits.append("parsing")
    if any(s in pkg for s in _GO_PKG_ARCH):
        hits.append("archive")
    if any(s in pkg for s in _GO_PKG_CRYPTO):
        hits.append("crypto")
    if any(s in pkg for s in _GO_PKG_SER):
        hits.append("serialization")
    return hits


def _go_bonus(name: str) -> int:
    """User-code (main**) bumps above stdlib plumbing in the ranking."""
    return 1 if "main." in name.lower().replace("/", ".main.") else 0


def _go_net_bonus(name: str) -> int:
    """Prefer inbound listener seams (Accept/Listen/Serve) over outbound dialing."""
    seg = name.lower().split("/")[-1]
    verb = seg.split(")")[-1] if ")" in seg else seg
    for v in ("accept", "listen", "handleconn", "readrequest"):
        if v in verb:
            return 2
    if re.search(r"(?<![a-z])serve(?![a-z])", verb) is not None:
        return 2
    if any(v in verb for v in ("dial", "read", "recv", "connect", "write")):
        return 1
    return 0


def analyze_remote_surface(path: str, max_sinks: int = 16) -> dict:
    """Rank remote fuzz entry candidates for *path*."""
    if not r2util.is_huge(path) and not _truncated(path):
        funcs, imports = language_profile._readelf_symbols(path)
    else:
        funcs, imports = [], []

    lang = language_profile.detect_language(path, (funcs, imports))

    # --- Go enrichment ---
    # readelf -Ws on modern Go binaries only surfaces cgo/asm stubs; the
    # .gopclntab name table is the real source of truth. Union it with any
    # address-bearing readelf symbols so both names and xref-capable addrs exist.
    symbols_source = "readelf -Ws"
    if lang.get("language") == "go":
        pc_funcs, pc_note = language_profile.go_pclntab_names(path)
        if pc_funcs:
            have = {f["name"] for f in funcs}
            funcs = funcs + [f for f in pc_funcs if f["name"] not in have]
            symbols_source = f"readelf -Ws + {pc_note}"
        else:
            symbols_source = symbols_source + f" (pclntab: {pc_note})"

    classified_defs, classified_imports = _classify(funcs, imports, lang.get("language", "cc"))
    has_net_import = any(c["category"] == "network" and not c["defined"] for c in classified_imports)

    candidate_meta = _best_candidates(classified_defs, max_sinks)
    callers = {}
    if funcs and _can_xref(path, funcs, lang.get("language", "cc")):
        r2, ok = _open_r2_cached(path, budget_s=12)
        if ok:
            try:
                for addr, name, cat in candidate_meta[:12]:
                    try:
                        x = r2.cmd(f"axt @ {addr}")
                        found = [
                            {"caller": ln.strip().split()[0], "at": ln.strip()}
                            for ln in x.splitlines() if ln.strip() and "axt" not in ln
                        ]
                        callers[addr] = found[:6]
                    except Exception:
                        callers[addr] = []
            finally:
                try:
                    r2.quit()
                except Exception:
                    pass

    ranked = _rank(candidate_meta, callers, lang.get("language", "cc"))
    # name-only candidates (stripped Go: pclntab has no addresses) still rank
    name_only = _rank_name_only(classified_defs, max_sinks)
    if name_only:
        have = {r["name"] for r in ranked}
        ranked = ranked + [e for e in name_only if e["name"] not in have]
    ranked.sort(key=lambda x: (-x["score"], x["name"] or "", x["addr"] or ""))

    # C-style: network sinks are imports (channels), consumers live around the
    # entry/main seam.  Surface that so the AI knows where to point fuzz_detail.
    if has_net_import and not any(c["category"] == "network" for c in ranked):
        for ec in lang.get("entry_candidates", []):
            if ec.get("addr") and not ec["addr"].startswith("0x0") and ec["addr"] not in {"?", "0x0"}:
                ranked.append({
                    "addr": ec["addr"],
                    "name": f"{ec.get('name', 'main')}  (network imports present)",
                    "category": "network_channel",
                    "score": 2,
                    "callers": 0,
                    "caller_names": [],
                })
                break

    verdict = _verdict(ranked, lang, len(imports), has_net_import)
    net_defs = [c for c in ranked if c["category"] == "network" or c["category"] == "network_channel"]
    no_callers = (not callers) and funcs
    return {
        "path": path,
        "language": lang.get("language", "unknown"),
        "confidence": lang.get("confidence", "low"),
        "symbols_indexed": {"funcs": len(funcs), "imports": len(imports)},
        "symbols_source": symbols_source,
        "verdict": verdict["label"],
        "remote_fuzzable": verdict["remote"],
        "rationale": verdict["rationale"],
        "ranked_candidates": ranked[:12],
        "top_network": net_defs[:6],
        "entry_candidates": lang.get("entry_candidates", [])[:6],
        "recommended_harness": "net_basic" if net_defs else ("file" if verdict["label"] == "local_parser" else "stdin"),
        "note": None if callers else ("callers unresolved (name-only symbols / stripped Go)" if no_callers else
                                      "no caller xref (no addressable defined symbols)"),
    }


# ----------------------------------------------------------------------
# internals
# ----------------------------------------------------------------------

def _truncated(path: str) -> bool:
    try:
        out = subprocess.check_output(["file", path], text=True, timeout=5)
        return "missing section headers" in out.lower()
    except Exception:
        return False


def _can_xref(path: str, funcs: list[dict], language: str = "cc") -> bool:
    """r2 axt callers are affordable only on small addressable-symbol binaries."""
    if r2util.is_huge(path) or _truncated(path):
        return False
    defined = [f for f in funcs if f.get("addr")]
    if not (1 <= len(defined) <= 1200):
        return False
    if language == "go" and len(defined) < 200:
        return False  # stripped-go: the few addr symbols are cgo stubs, not seams
    try:
        if os.path.getsize(path) > 6 * 1024 * 1024:
            return False
    except Exception:
        return False
    return True


def _open_r2_cached(path: str, budget_s: int = 12):
    try:
        r2 = r2util.open_r2(path, budget_s=budget_s)
        out = r2.cmd("aaa")
        if isinstance(out, str) and "budget exceeded" in out:
            try:
                r2.quit()
            except Exception:
                pass
            return None, False
        return r2, True
    except Exception:
        return None, False


def _classify(funcs: list[dict], imports: list[dict], language: str) -> tuple[list[dict], list[dict]]:
    def _mk(entries, is_def):
        out = []
        for e in entries:
            name = e.get("name", "")
            cats = _match_categories(name, language)
            if cats:
                out.append({
                    "name": name,
                    "addr": e.get("addr", 0),
                    "addr_hex": hex(e.get("addr", 0)) if e.get("addr") else None,
                    "category": cats[0],
                    "defined": is_def,
                })
        return out

    return _mk(funcs, True), _mk(imports, False)


def _match_categories(name: str, language: str) -> list[str]:
    if language == "go":
        return _go_category(name)
    low = name.lower()
    hits = []
    demangled = ""
    if language == "rust" and _RUST_PRECHEK.search(name):
        demangled = language_profile._demangle(name).lower()
    for cat, markers in _SINK_MARKERS.items():
        for m in markers:
            if _marker_hit(m, low) or (demangled and _marker_hit(m, demangled)):
                hits.append(cat)
                break
    return hits


def _marker_hit(m: str, low: str) -> bool:
    """Short markers need token boundaries so 'tar' doesn't match 'start'."""
    if len(m) < 4:
        return re.search(r"(?<![a-z0-9])" + re.escape(m) + r"(?![a-z0-9])", low) is not None
    return m in low


def _best_candidates(classified: list[dict], max_sinks: int) -> list[tuple[int, str, str]]:
    """Dedup names, keep highest-weight category per symbol, sort by weight.
    Returns [(addr, name, category)] for defined symbols only (needed for xrefs)."""
    seen: dict[str, tuple[int, str, str]] = {}
    for c in classified:
        if not c["defined"] or not c["addr"]:
            continue
        key = c["name"]
        w = _CAT_WEIGHT.get(c["category"], 1)
        if key not in seen or w > _CAT_WEIGHT.get(seen[key][2], 1):
            seen[key] = (c["addr"], c["name"], c["category"])
    best = sorted(seen.values(), key=lambda t: (-_CAT_WEIGHT.get(t[2], 1), t[0]))
    return best[:max_sinks]


def _rank_name_only(classified: list[dict], max_sinks: int) -> list[dict]:
    """Rank address-less (e.g. .gopclntab) sink names; no caller edges available."""
    seen: dict[str, tuple[int, str]] = {}
    for c in classified:
        if c["addr"]:
            continue
        w = _CAT_WEIGHT.get(c["category"], 1) + _go_bonus(c["name"]) + _go_net_bonus(c["name"])
        if c["name"] not in seen or w > seen[c["name"]][0]:
            seen[c["name"]] = (w, c["category"])
    out = [{
        "addr": None,
        "name": n,
        "category": cat,
        "score": w,
        "callers": 0,
        "caller_names": [],
        "source": "name table (no addresses)",
    } for n, (w, cat) in seen.items()]
    out.sort(key=lambda x: (-x["score"], x["name"]))
    return out[:max_sinks]


def _rank(candidates: list[tuple[int, str, str]], callers: dict[int, list[dict]], language: str) -> list[dict]:
    ranked = []
    for addr, name, cat in candidates:
        rank = _CAT_WEIGHT.get(cat, 1) + _go_bonus(name) + _go_net_bonus(name)
        c = callers.get(addr, [])
        rank += min(3, len(c) // 2)
        ranked.append({
            "addr": hex(addr),
            "name": name,
            "category": cat,
            "score": rank,
            "callers": len(c),
            "caller_names": [x["caller"] for x in c[:5]],
        })
    ranked.sort(key=lambda x: (-x["score"], x["addr"]))
    return ranked


def _verdict(ranked: list[dict], lang: dict, n_imports: int, has_net_import: bool = False) -> dict:
    network = [c for c in ranked if c["category"] in ("network", "network_channel")]
    parsing = [c for c in ranked if c["category"] in ("parsing", "archive", "serialization")]
    lng = lang.get("language", "unknown")
    if len(ranked) == 0 and not has_net_import:
        return {
            "label": "no_symbols",
            "remote": False,
            "rationale": f"No indexed symbols (stripped/truncated). {n_imports} imports seen; "
                         "use fuzz_function_list/input_surface for a channel-level view.",
        }
    if network:
        if any(c["callers"] for c in network) or lng in ("go", "rust") or has_net_import:
            kind = "imported sockets/channels" if has_net_import else "definition sinks"
            return {
                "label": "remote_fuzzable" if any(c["callers"] for c in network) else "remote_possible",
                "remote": True,
                "rationale": f"{len(network)} network sink(s) ({kind}) with "
                             f"{sum(c['callers'] for c in network)} resolved caller(s). "
                             "Target a net_basic harness at the top candidate.",
            }
        return {
            "label": "remote_possible",
            "remote": True,
            "rationale": "Network sinks found but callers unresolved (stripped/huge). "
                         "Networking is present; harness the listener directly.",
        }
    if parsing:
        return {
            "label": "local_parser",
            "remote": False,
            "rationale": f"Parser/archive sinks ({len(parsing)}) but no network sinks. "
                         "Fuzz via file/stdin (parse the container format), not the wire.",
        }
    return {
        "label": "local_only",
        "remote": False,
        "rationale": "No remote or parser sinks indexed; likely internal compute. Low fuzz priority.",
    }