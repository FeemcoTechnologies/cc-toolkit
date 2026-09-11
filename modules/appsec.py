"""AppSec scanning: SBOM (syft/trivy), SCA (grype/trivy), secrets (gitleaks).

Every function returns a dict with an ``error`` key on failure so the MCP/CLI
layers can format consistently. Tools are located on PATH; a missing binary is
reported gracefully instead of raising.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

from .config import DEFAULT_EXCLUDE_DIRS


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


def _run(cmd: list, timeout: int = 900, env: Optional[dict] = None) -> dict:
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env=full_env)
        return {"rc": r.returncode, "stdout": r.stdout, "stderr": r.stderr}
    except FileNotFoundError:
        return {"error": f"binary not found: {cmd[0]}"}
    except subprocess.TimeoutExpired:
        return {"error": f"timed out after {timeout}s: {' '.join(cmd)}"}
    except Exception as e:
        return {"error": str(e)}


# Marker substrings that indicate a scan tool failed for offline/network reasons
# rather than because of a finding. Used to downgrade the failure to a clean
# "offline" warning instead of a hard error.
_OFFLINE_MARKERS = (
    "unable to locate the vulnerability database",
    "no vulnerability database",
    "database does not exist",
    "failed to load vulnerability db",
    "db update skipped",
    "update skipped and no database",
    "no such host",
    "connection refused",
    "temporary failure in name resolution",
    "i/o timeout",
    "failed to download",
    "failed to fetch",
    "tls handshake",
    "network is unreachable",
)


def _offline_reason(stderr: str) -> str:
    for m in _OFFLINE_MARKERS:
        if m in stderr.lower():
            return m
    return ""


def _rc_error(r: dict, tool: str) -> dict:
    """Build a graceful failure dict when a scan tool exits non-zero."""
    err = (r.get("stderr") or "").strip() or (r.get("stdout") or "").strip()
    snippet = (err[-600:]) if len(err) > 600 else err
    out = {"tool": tool, "rc": r.get("rc"), "error": snippet or f"{tool} exited non-zero"}
    offline = _offline_reason(r.get("stderr") or "")
    if offline:
        out["offline"] = True
        out["error"] = (f"{tool} needs its vulnerability database, but the update "
                        f"failed (offline/network): {offline}")
    return out


# ---------------------------------------------------------------------------
# SBOM
# ---------------------------------------------------------------------------
def sbom_generate(target: str, format: str = "cyclonedx-json",
                  tool: str = "syft", output: str = "") -> dict:
    """Generate an SBOM for a directory, image archive, or container image.

    format: cyclonedx-json | spdx-json | syft-json
    tool: syft | trivy
    """
    tgt = str(target).strip()
    if not tgt:
        return {"error": "target required (dir, image name, or image.tar)"}

    out_file = output.strip()
    if not out_file:
        out_file = f"sbom_{Path(tgt).name or 'target'}.{format.split('-')[0]}.json"

    fmt_map = {
        "cyclonedx-json": "cyclonedx-json",
        "spdx-json": "spdx-json",
        "syft-json": "syft-json",
    }
    fmt = fmt_map.get(format.lower(), "cyclonedx-json")

    if tool.lower() == "trivy":
        if not _which("trivy"):
            return {"error": "trivy not installed"}
        # trivy writes SBOM with `trivy fs --format cyclonedx` (sbom subcommand
        # writes native trivy DB format; fs+cyclonedx is the interoperable path)
        cmd = ["trivy", "fs", "--format", "cyclonedx", "--output", out_file,
               "--skip-db-update", "--skip-dirs"] + _skip_dirs() + [tgt]
        r = _run(cmd)
        if r.get("error"):
            return r
        if r.get("rc") != 0:
            return _rc_error(r, "trivy")
        return {
            "tool": "trivy",
            "target": tgt,
            "rc": r["rc"],
            "format": "cyclonedx",
            "output_file": out_file,
            "stdout": r["stdout"][:800],
            "stderr": r["stderr"][:800],
            "note": "SBOM written by trivy fs (cyclonedx). Exit rc=0 means success.",
        }

    if not _which("syft"):
        return {"error": "syft not installed"}
    cmd = (["syft", "-o", f"{fmt}={out_file}"]
           + _exclude_flags("--exclude") + [tgt])
    r = _run(cmd)
    if r.get("error"):
        return r
    summary = _summarize_sbom(out_file)
    return {
        "tool": "syft",
        "target": tgt,
        "rc": r["rc"],
        "format": fmt,
        "output_file": out_file,
        "stdout": r["stdout"][:800],
        "stderr": r["stderr"][:800],
        "summary": summary,
    }


def _summarize_sbom(sbom_file: str) -> dict:
    try:
        data = json.loads(Path(sbom_file).read_text(encoding="utf-8"))
        comps = data.get("components") or []
        count = len(comps)
        by_type: dict = {}
        for c in comps:
            t = c.get("type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1
        licenses = sorted({l.get("license", {}).get("id", "?")
                           for c in comps for l in c.get("licenses", [])})
        return {"components": count, "by_type": by_type,
                "licenses_sample": licenses[:20]}
    except (OSError, json.JSONDecodeError):
        return {}


def _skip_dirs() -> list:
    """Glob patterns for directories excluded from scans (see DEFAULT_EXCLUDE_DIRS)."""
    return [f"**/{name}" for name in DEFAULT_EXCLUDE_DIRS]


def _exclude_flags(flag: str = "--exclude") -> list:
    """Repeatable --exclude/--exclude-paths args for syft/grype-style tools.

    Matches any <name> directory at any depth under the scan root (e.g.
    ``**/cases/**``), mirroring _skip_dirs / _walk_files exclusions so case
    and engagement data never leaks into SBOM/SCA output.
    """
    out = []
    for name in DEFAULT_EXCLUDE_DIRS:
        out += [flag, f"**/{name}/**"]
    return out


# ---------------------------------------------------------------------------
# SCA: grype
# ---------------------------------------------------------------------------
def sca_grype_scan(target: str, output: str = "") -> dict:
    """Vulnerability scan of a dir/image with Grype (uses its own catalog)."""
    tgt = str(target).strip()
    if not tgt:
        return {"error": "target required (dir, image name, or image.tar)"}
    if not _which("grype"):
        return {"error": "grype not installed"}
    cmd = ["grype", tgt, "-o", "json"] + _exclude_flags("--exclude")
    # Never auto-update: keep offline scans deterministic and fast. Auto-update
    # off is required — update-check=false alone still lets grype block on a DB
    # download attempt when the cache is missing/stale.
    env = {
        "GRYPE_DB_UPDATE_CHECK": "false",
        "GRYPE_DB_AUTO_UPDATE": "false",
        "GRYPE_CHECK_FOR_APP_UPDATE": "false",
    }
    r = _run(cmd, timeout=1200, env=env)
    if r.get("error"):
        return r
    if r.get("rc") != 0:
        return _rc_error(r, "grype")
    matches = []
    try:
        data = json.loads(r["stdout"] or "{}")
        matches = data.get("matches") or []
    except json.JSONDecodeError:
        pass

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0}
    top: list = []
    for m in matches:
        v = m.get("vulnerability", {})
        sev = (v.get("severity") or "unknown").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
        top.append({
            "id": v.get("id", "?"),
            "severity": sev,
            "pkg": m.get("artifact", {}).get("name", "?"),
            "version": m.get("artifact", {}).get("version", "?"),
            "fix": (v.get("fix", {}) or {}).get("versions", []),
        })
    top.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["severity"], 4))

    summary = {
        "total": len(matches),
        "by_severity": sev_counts,
        "top_vulns": top[:30],
    }
    return {"tool": "grype", "target": tgt, "rc": r["rc"],
            "summary": summary, "stdout": r["stdout"][:800],
            "stderr": r["stderr"][:800],
            "output_file": output or ""}


# ---------------------------------------------------------------------------
# SCA: trivy
# ---------------------------------------------------------------------------
def sca_trivy_scan(target: str, output: str = "") -> dict:
    """Vulnerability scan of filesystem/image with Trivy."""
    tgt = str(target).strip()
    if not tgt:
        return {"error": "target required (dir or image name)"}
    if not _which("trivy"):
        return {"error": "trivy not installed"}
    # --skip-db-update + --offline-scan: no network, no hang; if the local DB is
    # absent trivy fails fast and _rc_error maps it to a clean offline warning.
    cmd = ["trivy", "fs", "--format", "json", "--quiet",
           "--skip-db-update", "--offline-scan",
           "--skip-dirs"] + _skip_dirs() + [tgt]
    r = _run(cmd, timeout=1200)
    if r.get("error"):
        return r
    if r.get("rc") != 0:
        return _rc_error(r, "trivy")

    vulns = []
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    try:
        data = json.loads(r["stdout"] or "[]")
        # trivy emits a bare JSON array when there are no results
        if isinstance(data, dict):
            results = data.get("Results", [])
        elif isinstance(data, list):
            results = data
        else:
            results = []
        for res in results:
            for v in res.get("Vulnerabilities", []):
                sev = (v.get("Severity") or "unknown").lower()
                if sev in sev_counts:
                    sev_counts[sev] += 1
                vulns.append({
                    "id": v.get("VulnerabilityID", "?"),
                    "severity": sev,
                    "pkg": v.get("PkgName", "?"),
                    "installed": v.get("InstalledVersion", "?"),
                    "fixed": v.get("FixedVersion", ""),
                    "title": (v.get("Title") or "")[:100],
                })
    except json.JSONDecodeError:
        pass

    vulns.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["severity"], 4))
    summary = {"total": len(vulns), "by_severity": sev_counts, "top_vulns": vulns[:30]}
    return {"tool": "trivy", "target": tgt, "rc": r["rc"],
            "summary": summary, "stdout": r["stdout"][:800],
            "stderr": r["stderr"][:800], "output_file": output or ""}


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------
def _gitleaks_config(exclude_dirs=DEFAULT_EXCLUDE_DIRS) -> str:
    """Write a gitleaks config extending the default with an allowlist that
    skips excluded directories (cases/, node_modules/, .git/, ...)."""
    paths = ",\n".join(f"\t'''(^|/){re.escape(name)}(/|$).*'''"
                       for name in exclude_dirs if name)
    toml = (
        "[extend]\n"
        "useDefault = true\n"
        "\n"
        "[allowlist]\n"
        "paths = [\n"
        f"{paths}\n"
        "]\n"
    )
    cfg = Path(tempfile.gettempdir()) / "gitleaks_cc_exclude.toml"
    cfg.write_text(toml, encoding="utf-8")
    return str(cfg)


def secret_scan(path: str, report_file: str = "") -> dict:
    """Scan a directory for secrets/leaks with Gitleaks (gitleaks dir)."""
    p = str(path).strip()
    if not p:
        return {"error": "path required"}
    if not _which("gitleaks"):
        return {"error": "gitleaks not installed"}
    out_file = report_file.strip() or "gitleaks_report.json"
    cmd = ["gitleaks", "dir", p, "--report-format", "json",
           "--report-path", out_file, "--no-banner", "--log-level", "warn",
           "--config", _gitleaks_config()]
    r = _run(cmd, timeout=1200)
    if r.get("error"):
        return r
    # gitleaks exits 1 when leaks were found (not an error)
    leaks = []
    try:
        leaks = json.loads(Path(out_file).read_text(encoding="utf-8"))
        if isinstance(leaks, dict):
            leaks = leaks.get("Leaks", []) or []
    except (OSError, json.JSONDecodeError):
        pass
    summary = {
        "leaks": len(leaks),
        "by_rule": _counts(leaks, "RuleID"),
        "files": sorted({l.get("File", "?") for l in leaks}),
        "sample": [{"file": l.get("File"), "line": l.get("StartLine"),
                    "rule": l.get("RuleID"), "match": (l.get("Match") or "")[:80]}
                   for l in leaks[:20]],
    }
    return {"tool": "gitleaks", "target": p, "rc": r["rc"],
            "summary": summary, "report_file": out_file,
            "stdout": r["stdout"][:800], "stderr": r["stderr"][:800]}


def _counts(items: list, key: str) -> dict:
    out: dict = {}
    for it in items:
        k = it.get(key) or "unknown"
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def _trufflehog_excludes() -> str:
    """Write a regex exclude-file for heavy dirs (node_modules, .git, ...)."""
    paths = list(DEFAULT_EXCLUDE_DIRS) + [
        "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
        ".cache", "site-packages", ".terraform", ".bundle",
    ]
    lines = "\n".join(f"(.*/)?{re.escape(name)}(/.*)?" for name in paths if name)
    f = Path(tempfile.gettempdir()) / "trufflehog_cc_exclude.txt"
    f.write_text(lines, encoding="utf-8")
    return str(f)


def trufflehog_scan(path: str, report_file: str = "") -> dict:
    """Scan a path (filesystem dir or git repo) for secrets with TruffleHog.

    TruffleHog is designed for git histories but also scans a plain directory
    tree; both work through the ``filesystem`` source on a local path.
    """
    p = str(path).strip()
    if not p:
        return {"error": "path required"}
    if not _which("trufflehog"):
        return {"error": "trufflehog not installed"}
    out_file = report_file.strip() or "trufflehog_report.json"
    cmd = ["trufflehog", "filesystem", p, "--json",
           "--no-update", "--no-fail", "--exclude-paths", _trufflehog_excludes()]
    r = _run(cmd, timeout=900)
    leaks = []
    for line in r.get("stdout", "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        src = item.get("SourceMetadata") or {}
        d = src.get("Data") or {}
        leaks.append({
            "file": d.get("file"),
            "line": d.get("line"),
            "rule": item.get("DetectorName"),
            "match": (item.get("Raw") or "")[:80],
        })
    summary = {
        "leaks": len(leaks),
        "by_rule": _counts(leaks, "rule"),
        "files": sorted({l["file"] for l in leaks if l.get("file")}),
        "sample": leaks[:20],
    }
    return {"tool": "trufflehog", "target": p, "rc": r["rc"],
            "summary": summary, "report_file": out_file,
            "stdout": r["stdout"][:800], "stderr": r["stderr"][:800]}


# ---------------------------------------------------------------------------
# SAST: lightweight pattern scanner (no semgrep binary required)
# ---------------------------------------------------------------------------

# Rule set: id, languages, severity, CWE, regex, message.
# Each regex is scanned per source line so file:line findings are cheap.
_SAST_RULES = (
    {
        "id": "eval-exec",
        "langs": ("python",),
        "severity": "high",
        "cwe": "CWE-95",
        "re": r"\b(?:eval|exec|execfile|compile)\s*\(",
        "msg": "Dynamic code execution (eval/exec/compile) — dangerous with untrusted input.",
    },
    {
        "id": "os-command",
        "langs": ("python",),
        "severity": "high",
        "cwe": "CWE-78",
        "re": r"\bos\.(?:system|popen)\s*\(",
        "msg": "OS command execution (os.system/os.popen) — injectable with untrusted input.",
    },
    {
        "id": "subprocess-shell",
        "langs": ("python",),
        "severity": "high",
        "cwe": "CWE-78",
        "re": r"\b(?:subprocess\.)?(?:Popen|call|run|check_output|check_call)\s*\([^)]*\bshell\s*=\s*True",
        "msg": "subprocess with shell=True — command injection risk.",
    },
    {
        "id": "pickle-load",
        "langs": ("python",),
        "severity": "high",
        "cwe": "CWE-502",
        "re": r"\b(?:pickle|cPickle|cloudpickle|dill)\.loads?\s*\(",
        "msg": "Unsafe deserialization (pickle) — RCE on untrusted data.",
    },
    {
        "id": "yaml-unsafe",
        "langs": ("python",),
        "severity": "high",
        "cwe": "CWE-502",
        "re": r"\byaml\.load\s*\(|yaml\.load_all\s*\(",
        "msg": "yaml.load unsafe by default (PyYAML<6) — RCE on untrusted YAML; use safe_load.",
    },
    {
        "id": "sql-string",
        "langs": ("python",),
        "severity": "high",
        "cwe": "CWE-89",
        "re": r"(?:execute|executemany|executescript)\s*\(\s*(?:f|rf|b)?['\"].*\b(?:SELECT|INSERT|UPDATE|DELETE)\b",
        "msg": "SQL executed via string literal — possible SQL injection; prefer parameterized queries.",
    },
    {
        "id": "sql-fstring",
        "langs": ("python",),
        "severity": "high",
        "cwe": "CWE-89",
        "re": r"\b(?:execute|executemany)\s*\(\s*f['\"]",
        "msg": "SQL via f-string — SQL injection risk; use ?/%(name)s parameters.",
    },
    {
        "id": "weak-crypto",
        "langs": ("python",),
        "severity": "medium",
        "cwe": "CWE-327",
        "re": r"\b(?:md5|sha1)\.(?:new|digest|hexdigest)?\s*\(",
        "msg": "Weak hash (MD5/SHA1) — use SHA-256+ or argon2/bcrypt for secrets.",
    },
    {
        "id": "insecure-des",
        "langs": ("python",),
        "severity": "medium",
        "cwe": "CWE-327",
        "re": r"\bDES3?\.new|ECB\b",
        "msg": "Insecure cipher mode (DES/ECB) — use AES-GCM.",
    },
    {
        "id": "http-request",
        "langs": ("python",),
        "severity": "medium",
        "cwe": "CWE-319",
        "re": r"requests\.(?:get|post|put|patch|delete)\s*\(\s*['\"]http://",
        "msg": "Cleartext HTTP request — credentials/tokens sent unencrypted.",
    },
    {
        "id": "js-eval",
        "langs": ("javascript",),
        "severity": "high",
        "cwe": "CWE-95",
        "re": r"\beval\s*\(|\bnew\s+Function\s*\(",
        "msg": "JavaScript eval/new Function — code injection.",
    },
    {
        "id": "js-innerhtml",
        "langs": ("javascript",),
        "severity": "medium",
        "cwe": "CWE-79",
        "re": r"\b(?:innerHTML|outerHTML|insertAdjacentHTML)\s*=",
        "msg": "Assigning raw HTML — DOM-based XSS if content is untrusted.",
    },
    {
        "id": "js-docwrite",
        "langs": ("javascript",),
        "severity": "medium",
        "cwe": "CWE-79",
        "re": r"\bdocument\.write\s*\(",
        "msg": "document.write — DOM-based XSS risk.",
    },
    {
        "id": "js-dangerously-set",
        "langs": ("javascript",),
        "severity": "medium",
        "cwe": "CWE-79",
        "re": r"dangerouslySetInnerHTML",
        "msg": "dangerouslySetInnerHTML — React XSS risk on untrusted content.",
    },
    {
        "id": "js-node-exec",
        "langs": ("javascript",),
        "severity": "high",
        "cwe": "CWE-78",
        "re": r"\bexec(Sync)?\s*\(|child_process",
        "msg": "Child process exec — OS command injection risk.",
    },
    {
        "id": "html-http-src",
        "langs": ("html",),
        "severity": "medium",
        "cwe": "CWE-319",
        "re": r"<(?:script|link|iframe|img)[^>]+src\s*=\s*['\"]http://",
        "msg": "Mixed/insecure content loaded over cleartext HTTP.",
    },
    {
        "id": "html-inline-handler",
        "langs": ("html",),
        "severity": "medium",
        "cwe": "CWE-79",
        "re": r"\bon(?:error|click|load|mouseover)\s*=\s*['\"]?[^'\"<>]{4,}",
        "msg": "Inline event handler — XSS/behavior risk; prefer event binding in JS.",
    },
    {
        "id": "hardcoded-secret",
        "langs": ("python", "javascript"),
        "severity": "high",
        "cwe": "CWE-798",
        "re": r"\b(?:password|passwd|api_key|apikey|secret_key|access_token|auth_token)\s*[:=]\s*['\"][^'\"]{6,}",
        "msg": "Possible hardcoded secret/credential in source.",
    },
)


def _walk_files(root: Path, suffixes: set):
    """Walk ``root`` for files with the given suffixes using os.walk.

    Follows no symlinks and prunes excluded dirs in-place so traversal never
    descends into huge/unwanted trees (cases, node_modules, .git, ...).
    Yields absolute Path objects."""
    skip = set(DEFAULT_EXCLUDE_DIRS)
    for dirpath, dirnames, filenames in os.walk(str(root), followlinks=False):
        kept = []
        for d in dirnames:
            if d not in skip:
                kept.append(d)
        dirnames[:] = kept
        base = Path(dirpath)
        for fn in filenames:
            if Path(fn).suffix.lower() in suffixes:
                yield base / fn


def _iter_source_files(root: Path):
    """Yield (relpath, content) for python/js/html files, skipping excluded dirs."""
    exts = {".py": "python", ".js": "javascript", ".html": "html"}
    for path in _walk_files(root, set(exts)):
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        yield path.relative_to(root), exts[path.suffix.lower()], content


def sast_scan(target: str) -> dict:
    """Run a lightweight pattern-based SAST scan over a directory.

    Pure-python (no semgrep binary required). If the real ``semgrep`` CLI is on
    PATH it is preferred; otherwise the built-in rule set runs.
    """
    tgt = str(target).strip()
    if not tgt:
        return {"error": "target required (dir or image)"}
    root = Path(tgt)
    if not root.exists():
        return {"error": f"path not found: {tgt}"}
    if root.is_file():
        root = root.parent
        scope = Path(tgt)
    else:
        scope = None

    # Prefer real semgrep when available.
    if _which("semgrep"):
        try:
            from .tool_wrappers import semgrep_scan
            r = semgrep_scan([str(p) for p in _rule_dirs()], str(root))
            if isinstance(r, dict) and not r.get("error") and r.get("results_count", 0) > 0:
                return _semgrep_summary(r, str(root))
        except Exception:
            pass

    findings = []
    if scope is not None and scope.is_file():
        lang = {".py": "python", ".js": "javascript", ".html": "html"}.get(scope.suffix.lower())
        if lang:
            try:
                content = scope.read_text(encoding="utf-8", errors="replace")
            except OSError:
                content = ""
            _match_rules(scope.name, lang, content, findings)
    else:
        for rel, lang, content in _iter_source_files(root):
            _match_rules(rel, lang, content, findings)

    return _sast_summary(root, findings)


def _rule_dirs() -> list:
from .config import SEMGREP_RULES_DIR
    roots = [SEMGREP_RULES_DIR]
    return [str(r) for r in roots if Path(r).exists()]


def _match_rules(rel, lang, content, findings) -> None:
    for line_no, line in enumerate(content.splitlines(), start=1):
        for rule in _SAST_RULES:
            if lang not in rule["langs"]:
                continue
            m = re.search(rule["re"], line)
            if m:
                findings.append({
                    "id": rule["id"],
                    "severity": rule["severity"],
                    "cwe": rule["cwe"],
                    "message": rule["msg"],
                    "file": str(rel),
                    "line": line_no,
                    "snippet": line.strip()[:160],
                })


def _sast_summary(root: Path, findings: list) -> dict:
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        k = f.get("severity") or "low"
        if k in sev:
            sev[k] += 1
        else:
            sev["low"] += 1
    by_id: dict = {}
    for f in findings:
        by_id[f["id"]] = by_id.get(f["id"], 0) + 1
    return {
        "tool": "sast",
        "engine": "builtin-patterns",
        "target": str(root),
        "findings": len(findings),
        "by_severity": sev,
        "by_rule": dict(sorted(by_id.items(), key=lambda kv: -kv[1])),
        "sample": findings[:50],
    }


def _semgrep_summary(r: dict, target: str) -> dict:
    out_file = r.get("output_file") or ""
    data = {}
    try:
        data = json.loads(Path(out_file).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        pass
    findings = []
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "error": 0}
    for res in data.get("results", []):
        extra = res.get("extra", {})
        s = (extra.get("severity") or "low").lower()
        sev[s] = sev.get(s, 0) + 1
        loc = res.get("location", {})
        findings.append({
            "id": res.get("check_id", "?") or "?",
            "severity": s,
            "cwe": (extra.get("metadata", {}).get("cwe") or ["CWE-000"])[0] if isinstance(extra.get("metadata", {}).get("cwe"), list) else extra.get("metadata", {}).get("cwe", "CWE-000"),
            "message": extra.get("message", ""),
            "file": loc.get("path", "?"),
            "line": loc.get("start", {}).get("line"),
            "snippet": (loc.get("snippet", "") or "").strip()[:160],
        })
    by_id: dict = {}
    for f in findings:
        by_id[f["id"]] = by_id.get(f["id"], 0) + 1
    return {
        "tool": "sast",
        "engine": "semgrep",
        "target": target,
        "findings": len(findings),
        "by_severity": sev,
        "by_rule": dict(sorted(by_id.items(), key=lambda kv: -kv[1])) if by_id else {"errors": len(data.get("errors", []))},
        "sample": findings[:50],
    }


# ---------------------------------------------------------------------------
# OSV vuln check (live API + offline snapshot fallback)
# ---------------------------------------------------------------------------

def _osv_snapshot_path() -> Path:
    return Path(__file__).resolve().parent / "osv_snapshot.json"


def _load_osv_snapshot() -> dict:
    p = _osv_snapshot_path()
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"generated_at": "", "packages": []}


def _query_osv_batch(pkgs: list) -> list:
    """Query OSV querybatch API for [(ecosystem, name, version), ...].
    Returns list of vuln dicts (id/severity/fixed/summary) per package or [] on
    any network/parse failure so callers can fall back to the snapshot."""
    if not pkgs:
        return []
    queries = [{"package": {"name": n, "ecosystem": e}, "version": v}
               for e, n, v in pkgs]
    body = json.dumps({"queries": queries}).encode("utf-8")
    req = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch", data=body,
        headers={"Content-Type": "application/json", "User-Agent": "cc-toolkit/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError):
        return []
    out = []
    for res in data.get("results", []):
        pkg_vulns = []
        for v in res.get("vulns", []):
            pkg_vulns.append({
                "id": v.get("id", "?"),
                "summary": v.get("summary", ""),
                "severity": (v.get("database_specific") or {}).get("severity", ""),
            })
        out.append(pkg_vulns)
    return out


def _osv_find(pkgs: list, use_live: bool = True) -> dict:
    """Return {pkg_key: [vuln, ...]} for the given package list.

    Tries the live OSV API first (when use_live and network is up), then merges
    the bundled offline snapshot so results are never empty.
    """
    merged: dict = {f"{e}/{n}@{v}": [] for e, n, v in pkgs}
    live = _query_osv_batch(pkgs) if use_live else []
    snapshot = _load_osv_snapshot()
    snap_lookup = {
        (p.get("ecosystem", "").lower(), p.get("name", "").lower()): p.get("vulns", [])
        for p in snapshot.get("packages", [])
    }
    for i, (e, n, v) in enumerate(pkgs):
        key = f"{e}/{n}@{v}"
        if use_live and i < len(live) and live[i]:
            merged[key] = live[i]
            continue
        snap_vulns = snap_lookup.get((e.lower(), n.lower()), [])
        if snap_vulns:
            merged[key] = [{
                "id": sv.get("id", "?"),
                "summary": sv.get("summary", ""),
                "severity": sv.get("severity", ""),
                "fixed": sv.get("fixed", ""),
            } for sv in snap_vulns]
    return merged


def _discover_python_packages(root: Path) -> list:
    """Discover (ecosystem, name, version) tuples from requirements.txt /
    pip freeze style files under the target (excluding scanned-out dirs)."""
    found = []
    seen = set()
    req_files = sorted(_walk_files(root, {".txt"}))
    req_files = [p for p in req_files if p.name.startswith("requirements")]
    for rf in req_files:
        try:
            lines = rf.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line or line.startswith(("#", "-", "[")):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:==|>=|<=|~=)\s*([0-9][0-9.A-Za-z\-+]*)$", line)
            if m:
                key = (m.group(1).lower(), m.group(2))
                if key not in seen:
                    seen.add(key)
                    found.append(("PyPI", m.group(1), m.group(2)))
    return found


def osv_scan(target: str, use_live: bool = True) -> dict:
    """Check Python package versions against the OSV vulnerability database.

    Discovers pinned deps from requirements*.txt under the target, queries the
    OSV querybatch API (when online), and merges the bundled offline snapshot
    (modules/osv_snapshot.json) so results are available even without network.
    """
    tgt = str(target).strip()
    if not tgt:
        return {"error": "target required (dir)"}
    root = Path(tgt)
    if not root.exists():
        return {"error": f"path not found: {tgt}"}
    pkgs = _discover_python_packages(root if root.is_dir() else root.parent)
    if not pkgs:
        return {"tool": "osv", "target": tgt, "checked": 0, "vulns": 0,
                "by_severity": {}, "top_vulns": [],
                "message": "No pinned python deps found (requirements*.txt with == pin)"}
    matches = _osv_find(pkgs, use_live=use_live)
    vulns = []
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for key, vs in matches.items():
        _, _, ver = key.rpartition("@")
        for v in vs:
            s = (v.get("severity") or "unknown").lower()
            if s in sev:
                sev[s] += 1
            vulns.append({
                "id": v.get("id", "?"),
                "severity": s,
                "pkg": key,
                "version": ver,
                "summary": (v.get("summary") or "")[:160],
                "fixed": v.get("fixed", ""),
            })
    vulns.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["severity"], 4))
    return {
        "tool": "osv",
        "source": "live-api+snapshot" if use_live else "snapshot",
        "target": tgt,
        "checked": len(pkgs),
        "vulns": len(vulns),
        "by_severity": sev,
        "top_vulns": vulns[:30],
    }


# ---------------------------------------------------------------------------
# CDN frontend library inventory + advisory check
# ---------------------------------------------------------------------------

# Well-known frontend CVEs keyed by (pkg, version) -> advisory. The OSV npm
# snapshot covers most; this map is for quick manual adds of anything missing.
_CDN_ADVISORIES = {
    ("quill", "2.0.3"): {
        "id": "CVE-2025-15056",
        "severity": "low",
        "summary": "Quill HTML export feature XSS. No patched release (2.0.3 is latest); sanitize exported HTML.",
    },
}

# CDN hosts + URL shapes we can extract @version from.
_CDN_PATTERNS = (
    re.compile(r"cdn\.jsdelivr\.net/npm/([A-Za-z0-9._\-/@]+)@([0-9][0-9.A-Za-z\-+]*)"),
    re.compile(r"unpkg\.com/([A-Za-z0-9._\-/@]+)@([0-9][0-9.A-Za-z\-+]*)"),
    re.compile(r"cdnjs\.cloudflare\.com/ajax/libs/([A-Za-z0-9._\-/]+)/([0-9][0-9.A-Za-z\-+]*)"),
    re.compile(r"cdn\.quilljs\.com/([0-9][0-9.A-Za-z\-+]*)"),
)


def _extract_cdn_refs(content: str) -> list:
    """Return [(pkg, version, url)] found in HTML/JS content."""
    out = []
    for m in _CDN_PATTERNS[0].finditer(content):
        name = m.group(1).split("/")[0]
        out.append((name, m.group(2), m.group(0)))
    for m in _CDN_PATTERNS[1].finditer(content):
        name = m.group(1).split("/")[0]
        out.append((name, m.group(2), m.group(0)))
    for m in _CDN_PATTERNS[2].finditer(content):
        name = m.group(1).split("/")[0]
        out.append((name, m.group(2), m.group(0)))
    for m in _CDN_PATTERNS[3].finditer(content):
        out.append(("quill", m.group(1), m.group(0)))
    return out


def cdn_scan(target: str) -> dict:
    """Inventory CDN frontend libraries referenced in templates/HTML.

    Extracts lib@version from script/link URLs (jsdelivr, unpkg, cdnjs, quilljs),
    reports the inventory, and flags known-vulnerable versions from the advisory
    map + the OSV npm snapshot.
    """
    tgt = str(target).strip()
    if not tgt:
        return {"error": "target required (dir)"}
    root = Path(tgt)
    if not root.exists():
        return {"error": f"path not found: {tgt}"}
    files = [root] if root.is_file() and root.suffix.lower() == ".html" else []
    if not files:
        files = list(_walk_files(root, {".html", ".htm"}))
    inventory: dict = {}
    sources: dict = {}
    snapshot = _load_osv_snapshot()
    snap_lookup = {
        (p.get("name", "").lower()): p.get("vulns", [])
        for p in snapshot.get("packages", []) if (p.get("ecosystem") or "").lower() == "npm"
    }
    for f in files:
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for name, version, url in _extract_cdn_refs(content):
            key = (name, version)
            prev = inventory.get(key, {"files": [], "urls": []})
            prev["files"].append(str(f.relative_to(root)) if root.is_dir() else str(f))
            prev["urls"].append(url)
            inventory[key] = prev
    flagged = []
    for (name, version), info in inventory.items():
        adv = _CDN_ADVISORIES.get((name, version))
        if adv:
            flagged.append({**adv, "pkg": name, "version": version,
                            "files": sorted(set(info["files"]))})
            continue
        for v in snap_lookup.get(name.lower(), []):
            if v.get("fixed") and version == v.get("matched_version", version):
                pass
        # snapshot is keyed by exact version; match id list and annotate
        snap_vulns = snap_lookup.get(name.lower(), [])
        if snap_vulns:
            flagged.append({
                "id": "snapshot",
                "severity": (snap_vulns[0].get("severity") or "unknown"),
                "pkg": name, "version": version,
                "summary": (snap_vulns[0].get("summary") or "")[:160],
                "fixed": snap_vulns[0].get("fixed", ""),
                "files": sorted(set(info["files"])),
            })
    libs = [{"name": n, "version": v, "files": sorted(set(i["files"]))[:5]}
            for (n, v), i in sorted(inventory.items())]
    return {
        "tool": "cdn",
        "target": tgt,
        "libs": len(libs),
        "inventory": libs,
        "flagged": len(flagged),
        "advisories": flagged,
    }


# ---------------------------------------------------------------------------
# Existing SBOM ingestion
# ---------------------------------------------------------------------------

def sbom_existing(target: str) -> dict:
    """Find and summarize pre-built CycloneDX SBOMs under the target.

    Surfaces components + vulnerabilities from existing sbom_*.json files so
    manual/scoped SBOMs (e.g. the ai-combined-tools one) are not lost when the
    dashboard regenerates its own via syft.
    """
    tgt = str(target).strip()
    if not tgt:
        return {"error": "target required (dir)"}
    root = Path(tgt)
    if not root.exists():
        return {"error": f"path not found: {tgt}"}
    if root.is_file():
        files = [root] if "sbom" in root.name and root.suffix == ".json" else []
    else:
        files = [p for p in _walk_files(root, {".json"}) if p.name.startswith("sbom_")]
    found = []
    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        comps = data.get("components") or []
        vulns = data.get("vulnerabilities") or []
        by_type: dict = {}
        for c in comps:
            t = c.get("type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        v_ids = []
        for v in vulns:
            s = (v.get("severity") or "unknown").lower()
            if s in sev:
                sev[s] += 1
            v_ids.append(v.get("id", "?"))
        found.append({
            "file": str(f),
            "format": data.get("bomFormat", "?"),
            "spec": data.get("specVersion", "?"),
            "components": len(comps),
            "by_type": by_type,
            "vulnerabilities": len(vulns),
            "by_severity": sev,
            "vuln_ids": v_ids[:40],
        })
    return {
        "tool": "sbom_existing",
        "target": tgt,
        "sboms_found": len(found),
        "sboms": found,
    }


# ---------------------------------------------------------------------------
# Combined
# ---------------------------------------------------------------------------
def appsec_scan(target: str, do_sbom: bool = True, do_sca: bool = True,
                do_secrets: bool = True, sca_tool: str = "grype",
                do_sast: bool = True, do_osv: bool = True,
                do_cdn: bool = True, do_sbom_existing: bool = True) -> dict:
    """Run a full AppSec audit: SBOM + SCA + secrets + SAST + OSV + CDN +
    existing-SBOM ingestion. Returns per-stage results."""
    tgt = str(target).strip()
    if not tgt:
        return {"error": "target required (dir or image)"}
    results: dict = {"target": tgt, "stages": {}}
    if do_sbom:
        results["stages"]["sbom"] = sbom_generate(tgt)
    if do_sca:
        fn = sca_trivy_scan if sca_tool.lower() == "trivy" else sca_grype_scan
        results["stages"]["sca"] = fn(tgt)
    if do_secrets:
        results["stages"]["secrets"] = secret_scan(tgt)
    if do_sast:
        results["stages"]["sast"] = sast_scan(tgt)
    if do_osv:
        results["stages"]["osv"] = osv_scan(tgt)
    if do_cdn:
        results["stages"]["cdn"] = cdn_scan(tgt)
    if do_sbom_existing:
        results["stages"]["sbom_existing"] = sbom_existing(tgt)
    return results
