"""Input-surface detection: how a binary receives external data."""

import json
import os
import re
import subprocess

from . import r2util, language_profile


# Import categories and their risk levels
_IMPORT_CATS = {
    "network": {
        "kw": (
            "recv", "send", "socket", "connect", "bind", "listen", "accept",
            "wsarecv", "wsasend", "wsastartup", "inet_", "gethostby",
            "getaddrinfo", "getpeername", "getsockname", "setsockopt",
            "htons", "htonl", "ntohs", "ntohl", "ioctlsocket",
            "internetopen", "httpopenrequest", "httpsendrequest",
            "urldownload", "winhttpopen", "winhttpconnect",
        ),
        "risk": "high",
    },
    "file_read": {
        "kw": (
            "fopen", "fread", "open", "read", "pread", "mmap", "createfile",
            "readfile", "findfirstfile", "findnextfile", "getfileattributes",
            "mapviewoffile", "createfilemapping", "fgetpos", "fseek",
            "readdir", "opendir",
        ),
        "risk": "medium",
    },
    "file_write": {
        "kw": (
            "fwrite", "write", "pwrite", "createfile", "writefile",
            "setfilepointer", "deletefile", "copyfile", "movefile",
            "createpermanentresource", "regsetvalue",
        ),
        "risk": "medium",
    },
    "stdin": {
        "kw": ("fgets", "gets", "scanf", "fscanf", "sscanf", "getchar", "readline"),
        "risk": "high",
    },
    "env": {
        "kw": ("getenv", "getenvironmentvariable"),
        "risk": "low",
    },
    "process": {
        "kw": (
            "system", "popen", "exec", "spawn", "createprocess",
            "shellexecute", "shell.exec", "eval", "dlopen", "dlsym",
            "loadlibrary", "getprocaddress",
        ),
        "risk": "high",
    },
    "crypto": {
        "kw": (
            "crypt", "aes", "des", "md5", "sha", "hmac", "rsa",
            "certopenstore", "certfindcertificate",
        ),
        "risk": "info",
    },
    "registry": {
        "kw": (
            "regopenkey", "regqueryvalue", "regsetvalue", "regdelete",
            "regcreatekey", "regenumkey", "regenumvalue",
        ),
        "risk": "medium",
    },
    "memory": {
        "kw": (
            "malloc", "calloc", "realloc", "free", "virtualalloc",
            "heapalloc", "globalalloc",
        ),
        "risk": "info",
    },
}


def analyze_input_surface(path: str) -> dict:
    """Analyze imports + strings to determine how a binary receives input.

    Returns methods, risk-ranked imports, interesting strings, and a
    summary of attack surface.
    """
    if r2util.is_huge(path):
        return _fast_surface(path)
    if language_profile.detect_language(path).get("language") == "go":
        return _go_channel_surface(path)
    try:
        if os.path.getsize(path) > 10 * 1024 * 1024:
            return _fast_surface(path)
    except Exception:
        pass

    try:
        r2 = r2util.open_r2(path)
        r2.cmd("aaa")
    except Exception as e:
        return {"path": path, "error": f"r2 open/analysis failed: {e}"}

    result: dict = {"path": path}

    # -- imports --
    try:
        imports = json.loads(r2.cmd("iij"))
        categorized = _categorize_imports(imports)
        result["imports_by_cat"] = {
            cat: {"count": len(items), "risk": info["risk"], "examples": items[:8]}
            for cat, (items, info) in categorized.items()
        }
    except Exception:
        result["imports_by_cat"] = {}

    # -- interesting strings --
    try:
        strings = json.loads(r2.cmd("izj"))
        interesting = _find_input_strings(strings)
        result["interesting_strings"] = interesting[:30]
    except Exception:
        result["interesting_strings"] = []

    try:
        r2.quit()
    except Exception:
        pass
    return _finalize(result, categorized)


def _fast_surface(path: str) -> dict:
    """Non-r2 input-surface estimate for huge binaries (size guard).

    Falls back to readelf (imported symbols) + a capped ``strings`` scan.
    """
    result: dict = {"path": path, "fast_path": True}

    # No symtab?  readelf -Ws will produce nothing useful and burn the
    # budget (e.g. ELF with missing/corrupt section headers).  Detect via
    # ``file`` and skip straight to the strings pass.
    import subprocess as _sp
    finfo = ""
    try:
        finfo = _sp.check_output(["file", path], text=True, timeout=5).strip()
    except Exception:
        pass
    result["file_info"] = finfo
    no_symtab = "missing section headers" in finfo or "no .symtab" in finfo

    imports = []
    if not no_symtab:
        try:
            out = subprocess.check_output(
                ["readelf", "-Ws", path], text=True, timeout=12, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 8 and parts[4] == "UND" and parts[2] in ("FUNC", "OBJECT"):
                    imports.append({"name": parts[-1], "type": parts[2]})
        except Exception:
            imports = []

    categorized = _categorize_imports(imports)
    result["imports_by_cat"] = {
        cat: {"count": len(items), "risk": info["risk"], "examples": items[:8]}
        for cat, (items, info) in categorized.items()
    }

    strings = []
    strings_note = ""
    try:
        out = subprocess.check_output(
            ["strings", "-n", "8", path], text=True, timeout=8,
            stderr=subprocess.DEVNULL)
        strings = [{"string": s, "type": "str", "vaddr": 0}
                   for s in out.splitlines()[:1200]]
        strings_note = "strings scan truncated to 1200 lines"
    except subprocess.TimeoutExpired:
        strings_note = "strings scan exceeded 8s on huge binary; skipped"
    except Exception:
        strings_note = "strings scan failed"

    result["interesting_strings"] = _find_input_strings(strings)[:30]
    result = _finalize(result, categorized)
    result["note"] = "; ".join(
        x for x in [("no .symtab" if no_symtab else None), strings_note] if x)
    return result


def _go_channel_surface(path: str) -> dict:
    """Input-channel map for stripped Go from the .gopclntab name table.

    readelf -Ws on stripped Go yields nothing and r2 ``aaa`` on large Go
    images is memory-hungry, so infer channels from recovered function names.
    """
    result: dict = {"path": path, "fast_path": True, "analysis": "pclntab name channels"}
    funcs, note = language_profile.go_pclntab_names(path, cap=4000)
    names = [f["name"] for f in funcs]

    pats = {
        "network_listener": re.compile(
            r"(\.(Accept|Serve(Deferwraps?|Downgrade)?|ListenAndServe(TLS)?)\b|net\.Listen\b|ListenTCP\b)"),
        "network_client": re.compile(
            r"(\.(Dial|DialContext|DialTLS|DialTimeout|NewRequest|RoundTrip|Do)\b|http\.Client\b|RoundTripper\b)"),
        "stdin": re.compile(
            r"(os\.Stdin\b|bufio\.(NewScanner|NewReader(Size)?|Scanner)|fmt\.(Scan|Scanln|Scanf|ScanfFunc|Fscan|Fscanln))"),
        "file_read": re.compile(
            r"(os\.(Open|OpenFile|ReadFile|ReadDir|Readlink)\b|ioutil\.(ReadFile|ReadAll|ReadDir)\b|io\.ReadAll\b)"),
        "args_env": re.compile(
            r"(^flag\.|os\.Args\b|os\.Getenv\b|os\.LookupEnv\b|os\.Environ\b|pflag\.)"),
        "process": re.compile(
            r"(os/exec\b|os\.StartProcess\b|syscall\.(Exec|ForkExec)\b|os\.Pipe\b)"),
    }
    risks = {
        "network_listener": "high",
        "network_client": "high",
        "stdin": "high",
        "file_read": "medium",
        "args_env": "low",
        "process": "high",
    }
    detected: dict[str, list[str]] = {k: [] for k in pats}
    for n in names:
        for k, p in pats.items():
            if p.search(n):
                detected[k].append(n)
                break

    result["imports_by_cat"] = {
        k: {"count": len(v), "risk": risks[k], "examples": v[:8]}
        for k, v in detected.items() if v
    }
    methods = [k for k, v in detected.items() if v]
    result["input_methods"] = methods
    result["network_capable"] = bool(detected["network_listener"] or detected["network_client"])
    result["file_capable"] = bool(detected["file_read"])
    result["cli_capable"] = bool(detected["stdin"] or detected["args_env"])
    result["fuzzable"] = bool(
        detected["network_listener"] or detected["network_client"]
        or detected["stdin"] or detected["file_read"])
    result["high_risk_imports"] = [
        {"name": v[0], "cat": k}
        for k, v in detected.items() if risks[k] == "high" and v
    ][:8]

    strings = []
    strings_note = ""
    try:
        out = subprocess.check_output(
            ["strings", "-n", "8", path], text=True, timeout=8,
            stderr=subprocess.DEVNULL)
        strings = [{"string": s, "type": "str", "vaddr": 0}
                   for s in out.splitlines()[:1200]]
        strings_note = "strings scan truncated to 1200 lines"
    except subprocess.TimeoutExpired:
        strings_note = "strings scan exceeded 8s; skipped"
    except Exception:
        strings_note = "strings scan failed"
    result["interesting_strings"] = _find_input_strings(strings)[:30]

    result["note"] = f"{note}; " + "; ".join(
        x for x in [strings_note, "r2 aaa skipped for Go (size/perf)"] if x)
    return result


def _finalize(result: dict, categorized: dict) -> dict:
    """Shared summary built from categorized imports."""
    # -- input methods summary --
    methods = []
    cats = result.get("imports_by_cat", {})
    if "network" in cats:
        methods.append("network")
    if "stdin" in cats:
        methods.append("stdin")
    if "file_read" in cats:
        methods.append("file_input")
    if "env" in cats:
        methods.append("env_vars")
    if "registry" in cats:
        methods.append("registry")
    if "process" in cats:
        methods.append("process_spawning")

    result["input_methods"] = methods
    result["network_capable"] = "network" in methods
    result["file_capable"] = "file_input" in methods
    result["cli_capable"] = "stdin" in methods

    # -- high-risk imports (actionable) --
    high_risk = []
    for cat, (items, info) in categorized.items():
        if info["risk"] == "high":
            for item in items[:5]:
                high_risk.append({"name": item, "cat": cat})
    result["high_risk_imports"] = high_risk

    # -- fuzzer-friendliness --
    result["fuzzable"] = bool(
        methods and any(m in methods for m in ("network", "stdin", "file_input"))
    )
    return result


# ------------------------------------------------------------------
# helpers
# ------------------------------------------------------------------

def _categorize_imports(imports: list[dict]) -> dict:
    """Group imports into risk categories."""
    cats: dict = {}
    for imp in imports:
        name = (imp.get("name", "") or "").lower()
        if not name:
            continue
        for cat, info in _IMPORT_CATS.items():
            if any(kw in name for kw in info["kw"]):
                if cat not in cats:
                    cats[cat] = ([], info)
                cats[cat][0].append(imp.get("name", ""))
                break
    return cats


def _find_input_strings(strings: list[dict]) -> list[dict]:
    """Find strings that hint at input handling."""
    patterns = [
        (re.compile(r"https?://", re.I), "url"),
        (re.compile(r"localhost|127\.0\.0\.1|0\.0\.0\.0", re.I), "loopback_addr"),
        (re.compile(r":\d{2,5}"), "port_number"),
        (re.compile(r"Content-Type|User-Agent|HTTP/", re.I), "http_header"),
        (re.compile(r"%s|%d|%x|%n|%[^%]", re.I), "format_string"),
        (re.compile(r"/tmp/|/var/|C:\\|/etc/"), "file_path"),
        (re.compile(r"password|passwd|secret|token|key", re.I), "secret_hint"),
        (re.compile(r"exec|system|popen|shell|eval", re.I), "code_exec_hint"),
        (re.compile(r"<\?php|#!/|<script", re.I), "script_hint"),
    ]
    result = []
    seen = set()
    for s in strings:
        val = s.get("string", "") or ""
        if not val or val in seen:
            continue
        for pat, tag in patterns:
            if pat.search(val):
                result.append({"str": val[:80], "tag": tag})
                seen.add(val)
                break
    return result
