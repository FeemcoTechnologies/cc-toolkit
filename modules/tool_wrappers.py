import logging
"""Wrappers for your existing tools: trufflehog, mitm, dns, route, yara, semgrep, sigma, nuclei templates."""

import datetime
import json
import os
import re
import shlex
import shutil
import sqlite3
import tempfile
import subprocess
import sys
import threading
import time
from pathlib import Path
from shutil import which
from typing import Dict, List, Optional

from .config import DEFAULT_EXCLUDE_DIRS, SCRIPTS_DIR
logger = logging.getLogger(__name__)


def _walk_files(root: Path, exclude=None) -> List[Path]:
    """Recursively list files, skipping excluded directory names."""
    ex = set(exclude) if exclude is not None else set(DEFAULT_EXCLUDE_DIRS)
    out: List[Path] = []
    stack = [Path(root)]
    while stack:
        d = stack.pop()
        try:
            for p in d.iterdir():
                if p.is_dir():
                    if p.name not in ex:
                        stack.append(p)
                else:
                    out.append(p)
        except OSError:
            continue
    return out


_out_dir_lock = threading.Lock()
_out_dir_seq = 0


def _safe_stem(stem: str) -> str:
    """Sanitize a string for use as an output filename stem.

    Targets/URLs contain chars that break on some filesystems the shared
    server mounts (e.g. vboxsf errors with 'protocol error' on ':'). Keep
    only [A-Za-z0-9._-] and clamp length.
    """
    safe = "".join(c if (c.isalnum() or c in "._-") else "_" for c in stem)
    return safe[:120] or "out"


def _default_out_dir(name: str, output_dir: Optional[Path] = None) -> Path:
    """Return output_dir if given, else a fresh unique dir under cwd.

    Repeated runs of a tool from the same working directory (e.g. under the
    long-running MCP server) used to all write into one fixed dir like
    ./hashcat_output, colliding on files like cracked.txt / lsass_*.json. A
    timestamped + sequence-numbered subdir keeps each run's artifacts apart
    even for calls made within the same second. An explicit output_dir is
    used verbatim so callers keep full control.
    """
    global _out_dir_seq
    if output_dir:
        d = Path(output_dir)
    else:
        with _out_dir_lock:
            _out_dir_seq += 1
            seq = _out_dir_seq
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        d = Path.cwd() / f"{name}_{stamp}_{seq:04d}"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---------------------------------------------------------------------------
# trufflehog wrapper (from trufflehog-org.sh)
# ---------------------------------------------------------------------------
def trufflehog_org(org: str, output_dir: Optional[Path] = None) -> dict:
    """Scan a GitHub org for secrets via TruffleHog Docker image."""
    out_dir = _default_out_dir("trufflehog_results", output_dir)
    raw_file = out_dir / "raw_output.txt"

    print(f"Scanning GitHub org: {org}")
    cmd = [
        "docker", "run", "--rm",
        "--log-driver=none",
        "-a", "stdin", "-a", "stdout", "-a", "stderr",
        "trufflesecurity/trufflehog:latest",
        "github", "--org", org,
        "--issue-comments", "--pr-comments",
    ]
    result = {}
    try:
        with open(raw_file, "w") as f:
            proc = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT,
                                  text=True, timeout=600)
        result["rc"] = proc.returncode
        result["raw_file"] = str(raw_file)

        # Parse results like trufflehog-org.sh
        raw_text = raw_file.read_text(errors="ignore")

        combos = set()
        users = set()
        passes = set()
        keys = set()
        detectors = set()

        for line in raw_text.splitlines():
            if "Raw result:" in line and "@" in line:
                try:
                    after = line.split("Raw result:")[1]
                    parts = after.split("://")
                    if len(parts) > 1:
                        creds = parts[1].split("@")[0]
                        if ":" in creds:
                            u, p = creds.split(":", 1)
                            combos.add(f"{u}:{p}")
                            users.add(u)
                            passes.add(p)
                except Exception:

                    logger.debug("Exception in tool_wrappers.py", exc_info=True)
            if "SSH private key" in line:
                keys.add(line)

        for match in re.finditer(r"Detector Type:\s+(\S+)", raw_text):
            detectors.add(match.group(1))

        parsed = {
            "combolist": sorted(combos),
            "users": sorted(users),
            "passwords": sorted(passes),
            "ssh_keys": list(keys)[:20],
            "detectors": sorted(detectors),
        }
        result["parsed"] = parsed

        # Write parsed files
        for k, v in parsed.items():
            if v:
                (out_dir / f"{k}.txt").write_text("\n".join(v) + "\n")

    except subprocess.TimeoutExpired:
        result["error"] = "Timed out after 600s"
    except FileNotFoundError:
        result["error"] = "Docker not found. Install Docker or use podman."
    except Exception as e:
        result["error"] = str(e)

    return result


def trufflehog_local(path: str, output_dir: Optional[Path] = None) -> dict:
    """Run TruffleHog on a local directory."""
    out_dir = _default_out_dir("trufflehog_results", output_dir)
    result_path = out_dir / "results.json"

    cmd = [
        "docker", "run", "--rm", "-v", f"{os.path.abspath(path)}:/scan",
        "trufflesecurity/trufflehog:latest",
        "filesystem", "--directory", "/scan",
        "--json",
    ]
    result = {"path": path}
    try:
        with open(result_path, "w") as f:
            proc = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT,
                                  text=True, timeout=300)
        result["rc"] = proc.returncode
        result["results_file"] = str(result_path)
    except Exception as e:
        result["error"] = str(e)
    return result


# ---------------------------------------------------------------------------
# MITM proxy (from example-mitm.py)
# ---------------------------------------------------------------------------
def mitm_start(port: int = 8080, upstream: str = "") -> subprocess.Popen:
    """Start the MITM proxy server."""
    script = SCRIPTS_DIR / "automation-tools" / "example-mitm.py"
    if not script.exists():
        raise FileNotFoundError(f"MITM script not found: {script}")
    env = os.environ.copy()
    cmd = [sys.executable, str(script)]
    print(f"Starting MITM proxy on 0.0.0.0:{port}")
    if upstream:
        env["UPSTREAM_PROXY"] = upstream
    proc = subprocess.Popen(
        cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    return proc


# ---------------------------------------------------------------------------
# DNS monitor (from dns-monitor.py)
# ---------------------------------------------------------------------------
def dns_track(domain: str, interval: int = 300, duration: int = 0) -> Dict[str, list]:
    """Track DNS resolutions for a domain over time.

    Thin wrapper over modules.dns_wrapper (the canonical resolver/monitor
    engine with persistence + change detection) so there is a single
    implementation instead of a duplicate blocking loop here.
    """
    from . import dns_wrapper
    dns_wrapper.start_monitor(domain, types=["A"], interval=interval,
                              duration=duration)
    dns_wrapper.start_background_monitor()
    history: Dict[str, list] = {}
    start = time.time()
    count = 0
    print(f"Tracking DNS for {domain} every {interval}s...")
    try:
        while True:
            if duration and (time.time() - start) > duration:
                break
            try:
                answers = dns_wrapper.get_history(domain, limit=100)
                if answers:
                    ips = sorted({a["value"] for a in answers
                                  if a.get("type") == "A" and a.get("value")})
                    ts = answers[0]["ts"]
                    history.setdefault(domain, []).append({"ts": ts, "ips": ips})
                else:
                    ips = []
                    ts = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
                    history.setdefault(domain, []).append({"ts": ts, "ips": ips})
                count += 1
                print(f"  [{count}] {ts} \u2192 {', '.join(ips)}")
            except Exception as e:
                print(f"  [{count}] Resolve failed: {e}")
            time.sleep(max(interval, 1))
    except KeyboardInterrupt:
        print("\nTracking stopped.")
    return history


# ---------------------------------------------------------------------------
# Route scan / Weird routing test (from Weird-routing-test.py)
# ---------------------------------------------------------------------------
def route_scan(target_range: str = "172.16.0.0/12",
               max_workers: int = 10, arp_only: bool = False) -> List[str]:
    """Trace routes to IPs in a range and report suspicious private IPs in transit."""
    try:
        from scapy.all import traceroute
    except ImportError:
        return ["scapy not installed"]

    import concurrent.futures

    local_routes = set()
    try:
        import netifaces
        for gw in netifaces.gateways().get("default", {}).values():
            local_routes.add(gw[0])
    except Exception:

        logger.debug("Exception in tool_wrappers.py", exc_info=True)

    suspicious: List[str] = []
    import ipaddress
    _hops_lock = threading.Lock()

    def _trace(addr: str):
        ans, _ = traceroute(addr, verbose=0, timeout=2)
        hops = set()
        for pkt in ans:
            try:
                ip = pkt.answer.src
                if ipaddress.ip_address(ip).is_private and ip not in local_routes:
                    with _hops_lock:
                        hops.add(ip)
            except Exception:

                logger.debug("Exception in tool_wrappers.py", exc_info=True)
        return hops

    network = ipaddress.IPv4Network(target_range, strict=False)
    hosts = list(network.hosts())[:50]  # limit to first 50 to avoid DDOS

    print(f"Route scanning {target_range} ({len(hosts)} hosts)...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        fut = {ex.submit(_trace, str(h)): h for h in hosts}
        for f in concurrent.futures.as_completed(fut):
            hops = f.result()
            if hops:
                with _hops_lock:
                    suspicious.extend(hops)
                print(f"  Suspicious: {hops}")

    return list(set(suspicious))


# ---------------------------------------------------------------------------
# YARA scan
# ---------------------------------------------------------------------------
def yara_scan(rule_path: str, target: str) -> Dict[str, list]:
    """Scan a file or directory with YARA rules (batch mode).

    rule_path may be a single rule file/dir or a list of rule files/dirs
    (all compiled and applied to the targets).
    """
    yara_path = which("yara") or which("yara64")
    if not yara_path:
        return {"error": "yara not found in PATH"}
    if isinstance(rule_path, (list, tuple)):
        rule_paths = [str(p) for p in rule_path]
    else:
        rule_paths = [str(rule_path)]
    missing = [p for p in rule_paths if not Path(p).exists()]
    if missing:
        return {"error": f"Rule file not found: {missing[0]}"}

    target_p = Path(target)
    if target_p.is_dir():
        targets = [str(f) for f in _walk_files(target_p)]
    else:
        targets = [target]

    if not targets:
        return {"matches": [], "rule_file": ", ".join(rule_paths), "total": 0}

    # Batch all targets into a single subprocess call
    results = []
    # Split into batches of 500 to avoid command-line length limits
    batch_size = 500
    for i in range(0, len(targets), batch_size):
        batch = targets[i:i + batch_size]
        cmd = [yara_path] + rule_paths + batch
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            for line in r.stdout.strip().splitlines():
                if line.strip():
                    parts = line.split(maxsplit=1)
                    rule_name = parts[0] if parts else "?"
                    matched_file = parts[1] if len(parts) > 1 else "?"
                    results.append({"rule": rule_name, "file": matched_file})
        except subprocess.TimeoutExpired:
            for t in batch:
                results.append({"rule": "TIMEOUT", "file": t})
        except Exception as e:
            for t in batch:
                results.append({"rule": "ERROR", "file": t, "error": str(e)})

    return {"matches": results, "rule_file": ", ".join(rule_paths), "total": len(results)}


# ---------------------------------------------------------------------------
# Semgrep scan
# ---------------------------------------------------------------------------
def semgrep_scan(config, target: str) -> Dict:
    """Run Semgrep with a given config against a target.

    config may be a single path/rule-id or a list of configs (each becomes
    its own --config flag, so multiple rule dirs can be merged).
    """
    sg = which("semgrep")
    if not sg:
        return {"error": "semgrep not found in PATH"}
    if isinstance(config, (list, tuple)):
        configs = [str(c) for c in config]
    else:
        configs = [str(config)]
    out_file = Path.cwd() / f"semgrep_{Path(target).stem}.json"
    cmd = [sg]
    for c in configs:
        cmd += ["--config", c]
    cmd += ["--json", "--output", str(out_file)]
    cmd += [f"--exclude={d}" for d in DEFAULT_EXCLUDE_DIRS]
    cmd += [target]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        results = {"rc": r.returncode, "output_file": str(out_file)}
        if out_file.exists():
            try:
                data = json.loads(out_file.read_text())
                results["results_count"] = len(data.get("results", []))
                results["errors"] = data.get("errors", [])
            except Exception:

                logger.debug("Exception in tool_wrappers.py", exc_info=True)
        return results
    except subprocess.TimeoutExpired:
        return {"error": "Timed out"}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Sigma conversion
# ---------------------------------------------------------------------------
def sigma_convert(input_file: str, target_format: str = "siem",
                  output: str = "") -> Dict:
    """Convert Sigma rules to other formats (splunk, elk, qradar, etc.)."""
    sc = which("sigmac") or which("sigma")
    if not sc:
        return {"error": "sigma/sigmac not found in PATH"}

    inf = Path(input_file)
    if not inf.exists():
        return {"error": f"Input file not found: {input_file}"}

    out_file = output or str(inf.with_suffix(f".{target_format}"))
    cmd = [sc, "--target", target_format, "-o", out_file, str(inf)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return {
            "rc": r.returncode,
            "output": out_file,
            "stderr": r.stderr[:500] if r.stderr else "",
        }
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# CodeQL query scanner
# ---------------------------------------------------------------------------
def codeql_scan(rule_path: str, target: str, language: str = "") -> Dict:
    """Run a CodeQL query against a source code directory.

    Creates a CodeQL database from the target source, then analyzes
    it with the given query. Returns SARIF results or error dict.
    """
    codeql = which("codeql")
    if not codeql:
        return {"error": "codeql not found in PATH"}
    rule_p = Path(rule_path)
    if not rule_p.exists():
        return {"error": f"Query file not found: {rule_path}"}
    target_p = Path(target)
    if not target_p.is_dir():
        return {"error": f"Target must be a source directory: {target}"}

    # Auto-detect language from target files if not provided
    lang_map = {".py": "python", ".js": "javascript", ".ts": "javascript",
                ".java": "java", ".cs": "csharp", ".go": "go",
                ".rb": "ruby", ".rs": "rust", ".cpp": "cpp", ".c": "cpp",
                ".swift": "swift"}
    if not language:
        for f in target_p.rglob("*"):
            if f.suffix in lang_map:
                language = lang_map[f.suffix]
                break
    if not language:
        return {"error": "Could not detect source language. Specify language parameter."}

    try:
        tmp_dir = Path(tempfile.mkdtemp(prefix="codeql_"))
        db_dir = tmp_dir / "db"
        out_file = tmp_dir / "results.sarif"

        # Step 1: create database
        cmd_create = [codeql, "database", "create", str(db_dir),
                      f"--language={language}", f"--source-root={target}"]
        r1 = subprocess.run(cmd_create, capture_output=True, text=True, timeout=600)

        # Step 2: run query
        cmd_analyze = [codeql, "database", "analyze", str(db_dir),
                       str(rule_p), "--format=sarif-latest", f"--output={str(out_file)}"]
        r2 = subprocess.run(cmd_analyze, capture_output=True, text=True, timeout=600)

        results = {
            "rc_create": r1.returncode,
            "rc_analyze": r2.returncode,
            "stderr_create": r1.stderr[:1000] if r1.stderr else "",
            "stderr_analyze": r2.stderr[:1000] if r2.stderr else "",
            "output_file": str(out_file),
            "language": language,
            "query": rule_p.name,
        }
        if out_file.exists():
            try:
                sarif = json.loads(out_file.read_text(encoding="utf-8"))
                results["finding_count"] = sum(
                    len(run.get("results", [])) for run in sarif.get("runs", []))
                results["sarif"] = sarif
            except Exception:
                pass
        return results
    except subprocess.TimeoutExpired:
        return {"error": "CodeQL scan timed out"}
    except Exception as e:
        return {"error": str(e)}
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Nuclei template scanner
# ---------------------------------------------------------------------------
def nuclei_scan(target: str, template: str = "",
                output_dir: Optional[Path] = None,
                templates_dir=None) -> Dict:
    """Run Nuclei with template selection and structured output.

    templates_dir may be a single directory or a list of directories (each
    becomes its own -t/-nt pair so primary + curated templates are scanned).
    """
    n = which("nuclei")
    if not n:
        return {"error": "nuclei not found in PATH"}

    out_dir = Path(output_dir or Path.cwd())
    out_dir.mkdir(parents=True, exist_ok=True)
    json_out = out_dir / f"nuclei_{Path(target).stem}.json"

    cmd = [n, "-u", target, "-json", "-o", str(json_out)]
    if template:
        cmd.extend(["-t", template])
    if templates_dir:
        if isinstance(templates_dir, (list, tuple)):
            for d in templates_dir:
                cmd.extend(["-t", str(d), "-nt"])
        else:
            cmd.extend(["-t", str(templates_dir), "-nt"])

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        result = {"rc": r.returncode, "output_file": str(json_out)}
        if json_out.exists():
            findings = []
            with json_out.open() as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        findings.append(json.loads(line))
                    except Exception:

                        logger.debug("Exception in tool_wrappers.py", exc_info=True)
            result["findings"] = findings
            result["finding_count"] = len(findings)
        return result
    except subprocess.TimeoutExpired:
        return {"error": "Timed out"}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Wireless graph
# ---------------------------------------------------------------------------
def wireless_graph(pcap: str = "", iface: str = "") -> Dict:
    """Parse wireless PCAP or live capture and generate HTML graph."""
    script = SCRIPTS_DIR / "wirelessgraph" / "main.py"
    if not script.exists():
        return {"error": f"wirelessgraph/main.py not found at {script}"}

    cmd = [sys.executable, str(script)]
    if pcap:
        cmd.extend(["--pcap", pcap])
    elif iface:
        cmd.extend(["--iface", iface])
    else:
        return {"error": "Specify --pcap or --iface"}

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return {"rc": r.returncode, "stdout": r.stdout[:1000], "stderr": r.stderr[:500]}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# BloodyAD — Active Directory ACL abuse / privilege escalation
# ---------------------------------------------------------------------------
def bloodyad_exec(server: str, action: str, *,
                  username: str = "", password: str = "",
                  domain: str = "", target_dn: str = "", ldap_filter: str = "",
                  attribute: str = "", value: str = "") -> Dict:
    """Execute a BloodyAD action against an AD server (requires bloodyAD)."""
    ba = which("bloodyAD") or which("bloodyad")
    if not ba:
        return {"error": "bloodyAD not found in PATH"}
    cmd = [ba, "--host", server]
    if username:
        cmd.extend(["-u", username])
    if password:
        cmd.extend(["-p", password])
    if domain:
        cmd.extend(["-d", domain])
    cmd.append(action)
    if target_dn:
        cmd.extend(["--dn", target_dn])
    if ldap_filter:
        cmd.extend(["--filter", ldap_filter])
    if attribute:
        cmd.extend(["--attribute", attribute])
    if value:
        cmd.extend(["--value", value])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return {"rc": r.returncode, "stdout": r.stdout[:2000], "stderr": r.stderr[:500]}
    except subprocess.TimeoutExpired:
        return {"error": "Timed out"}
    except Exception as e:
        return {"error": str(e)}


def bloodyad_dump(server: str, *, username: str = "", password: str = "",
                  domain: str = "", object_class: str = "user") -> Dict:
    """Dump AD objects of a given class (user, computer, group)."""
    ba = which("bloodyAD") or which("bloodyad")
    if not ba:
        return {"error": "bloodyAD not found in PATH"}
    cmd = [ba, "--host", server]
    if username:
        cmd.extend(["-u", username])
    if password:
        cmd.extend(["-p", password])
    if domain:
        cmd.extend(["-d", domain])
    cmd.extend(["get", "object", "--class", object_class])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return {"rc": r.returncode, "stdout": r.stdout[:5000], "stderr": r.stderr[:500]}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Certipy — AD Certificate Services exploitation (ESC1-8)
# ---------------------------------------------------------------------------
def certipy_find(domain: str, target: str, *, username: str = "",
                 password: str = "", ca: str = "",
                 output_dir: Optional[Path] = None) -> Dict:
    """Enumerate AD CS misconfigurations (ESC1-8)."""
    cp = which("certipy")
    if not cp:
        return {"error": "certipy not found in PATH"}
    out_dir = Path(output_dir or Path.cwd())
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [cp, "find", "-dc-ip", target, "-domain", domain,
           "-output", str(out_dir / "certipy_find")]
    if username:
        cmd.extend(["-u", username])
    if password:
        cmd.extend(["-p", password])
    if ca:
        cmd.extend(["-ca", ca])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return {"rc": r.returncode, "stdout": r.stdout[:3000],
                "output_dir": str(out_dir)}
    except subprocess.TimeoutExpired:
        return {"error": "Timed out"}
    except Exception as e:
        return {"error": str(e)}


def certipy_request(domain: str, target: str, template: str, *,
                    username: str = "", password: str = "",
                    upn: str = "", dns: str = "") -> Dict:
    """Request a certificate via Certipy (ESC1/ESC3)."""
    cp = which("certipy")
    if not cp:
        return {"error": "certipy not found in PATH"}
    cmd = [cp, "req", "-dc-ip", target, "-domain", domain,
           "-template", template, "-ca", f"{domain}-CA"]
    if username:
        cmd.extend(["-u", username])
    if password:
        cmd.extend(["-p", password])
    if upn:
        cmd.extend(["-upn", upn])
    if dns:
        cmd.extend(["-dns", dns])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return {"rc": r.returncode, "stdout": r.stdout[:3000]}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# LdapNomNom — anonymous LDAP enumeration
# ---------------------------------------------------------------------------
def ldapnomnom_enum(target: str, *, base_dn: str = "",
                    output_dir: Optional[Path] = None) -> Dict:
    """Enumerate LDAP anonymously using ldapnomnom."""
    ln = which("ldapnomnom")
    if not ln:
        return {"error": "ldapnomnom not found in PATH"}
    out_dir = Path(output_dir or Path.cwd())
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"ldapnomnom_{target}.json"
    cmd = [ln, "-s", target, "--json", str(out_file)]
    if base_dn:
        cmd.extend(["-b", base_dn])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return {"rc": r.returncode, "output_file": str(out_file)}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Kerbrute — Kerberos pre-auth brute-force / user enumeration
# ---------------------------------------------------------------------------
def kerbrute_userenum(domain: str, wordlist: str, *,
                      dc_ip: str = "", output_dir: Optional[Path] = None) -> Dict:
    """Enumerate valid AD usernames via Kerberos pre-auth."""
    kb = which("kerbrute")
    if not kb:
        return {"error": "kerbrute not found in PATH"}
    if not Path(wordlist).exists():
        return {"error": f"Wordlist not found: {wordlist}"}
    out_dir = Path(output_dir or Path.cwd())
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"kerbrute_users_{domain}.txt"
    cmd = [kb, "userenum", "-d", domain, "--dc"]
    if dc_ip:
        cmd.append(dc_ip)
    else:
        cmd.append(domain)
    cmd.extend([wordlist, "--output", str(out_file)])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return {"rc": r.returncode, "output_file": str(out_file),
                "stdout": r.stdout[:2000]}
    except subprocess.TimeoutExpired:
        return {"error": "Timed out"}
    except Exception as e:
        return {"error": str(e)}


def kerbrute_bruteforce(domain: str, user: str, wordlist: str, *,
                        dc_ip: str = "") -> Dict:
    """Brute-force password for a single AD user via Kerberos."""
    kb = which("kerbrute")
    if not kb:
        return {"error": "kerbrute not found in PATH"}
    cmd = [kb, "bruteforce", "-d", domain, "--dc"]
    if dc_ip:
        cmd.append(dc_ip)
    else:
        cmd.append(domain)
    cmd.extend([user, wordlist])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return {"rc": r.returncode, "stdout": r.stdout[:2000]}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# EapHammer — Enterprise WiFi phishing / EAP attacks
# ---------------------------------------------------------------------------
def eaphammer_attack(bssid: str, essid: str, iface: str, *,
                     handshake_dir: Optional[Path] = None,
                     pmkid: bool = False, captive: bool = False,
                     auth_type: str = "WPA2-EAP") -> Dict:
    """Execute EAPHammer attack (PMKID, captive portal, downgrade)."""
    eh = which("eaphammer")
    if not eh:
        return {"error": "eaphammer not found in PATH"}
    out_dir = _default_out_dir("eaphammer_results", handshake_dir)
    cmd = ["sudo", eh, "--bssid", bssid, "--essid", essid,
           "--interface", iface, "--auth-type", auth_type,
           "--output-dir", str(out_dir)]
    if pmkid:
        cmd.append("--capture-pmkid")
    if captive:
        cmd.append("--captive-portal")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return {"rc": r.returncode, "output_dir": str(out_dir),
                "stdout": r.stdout[:2000]}
    except subprocess.TimeoutExpired:
        return {"error": "Timed out"}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# JWT Tool — JSON Web Token attack toolkit
# ---------------------------------------------------------------------------
def jwt_tool_scan(token: str) -> Dict:
    """Analyze and scan a JWT for vulnerabilities."""
    jt = which("jwt_tool")
    if not jt:
        return {"error": "jwt_tool not found in PATH"}
    cmd = [jt, token, "-X"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {"rc": r.returncode, "stdout": r.stdout[:4000]}
    except Exception as e:
        return {"error": str(e)}


def jwt_tool_attack(token: str, attack: str = "none", *,
                    payload_field: str = "", payload_value: str = "",
                    signing_key: str = "") -> Dict:
    """Exploit a JWT with a specific attack (none, kid, alg confusion, etc.)."""
    jt = which("jwt_tool")
    if not jt:
        return {"error": "jwt_tool not found in PATH"}
    cmd = [jt, token, "-X", attack]
    if payload_field and payload_value:
        cmd.extend(["-pc", payload_field, "-pv", payload_value])
    if signing_key:
        cmd.extend(["-k", signing_key])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {"rc": r.returncode, "stdout": r.stdout[:4000]}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# graphw00f — GraphQL endpoint fingerprinting
# ---------------------------------------------------------------------------
def graphw00f_scan(target: str, output_dir: Optional[Path] = None) -> Dict:
    """Fingerprint a GraphQL endpoint using graphw00f."""
    gw = which("graphw00f")
    if not gw:
        return {"error": "graphw00f not found in PATH"}
    out_dir = Path(output_dir or Path.cwd())
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"graphw00f_{Path(target).stem}.json"
    cmd = [gw, "-t", target, "-o", str(out_file)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return {"rc": r.returncode, "output_file": str(out_file),
                "stdout": r.stdout[:2000]}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# WSGIDAV — WebDAV server for file transfer / hosting
# ---------------------------------------------------------------------------
def wsgidav_serve(directory: str, host: str = "0.0.0.0", port: int = 8080,
                  auth: bool = True, username: str = "",
                  password: str = "") -> subprocess.Popen:
    """Start a WebDAV server for file sharing (useful for transferring tools).

    auth defaults to True: without credentials the server refuses to start
    rather than exposing an anonymous read-write share on the network.
    """
    wd = which("wsgidav")
    if not wd:
        raise FileNotFoundError("wsgidav not found in PATH (pip install wsgidav)")
    cmd = [wd, "--host", host, "--port", str(port), "--root", directory]
    if not auth:
        cmd.append("--auth=anonymous")
    else:
        if not username or not password:
            raise ValueError("wsgidav_serve requires username and password when auth=True")
        cmd.extend(["--auth=basic", "--user", f"{username}:{password}"])
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    return proc


# ---------------------------------------------------------------------------
# KAPE — Kroll Artifact Parser & Extractor (Windows forensic collection)
# ---------------------------------------------------------------------------
def kape_collect(target: str, output_dir: Optional[Path] = None,
                 targets: str = "!BasicCollection", module: str = "",
                 binary_path: str = "kape") -> Dict:
    """Run KAPE against a target for Windows forensic artifact collection."""
    kp = which(binary_path)
    if not kp:
        return {"error": "kape not found — ensure binary_path is correct"}
    out_dir = _default_out_dir("kape_output", output_dir)
    cmd = [kp, "--tsource", target, "--tdest", str(out_dir),
           "--target", targets, "--gui", "0"]
    if module:
        cmd.extend(["--module", module])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return {"rc": r.returncode, "output_dir": str(out_dir),
                "stdout": r.stdout[:2000]}
    except subprocess.TimeoutExpired:
        return {"error": "Timed out"}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Swaks — Swiss Army Knife for SMTP (email testing)
# ---------------------------------------------------------------------------
def swaks_send(to: str, server: str, *,
               from_addr: str = "", subject: str = "Test",
               body: str = "", port: int = 25,
               tls: bool = False, auth_user: str = "",
               auth_pass: str = "", attach: str = "",
               header: str = "") -> Dict:
    """Send a test email via SMTP with optional auth/TLS/headers."""
    sk = which("swaks")
    if not sk:
        return {"error": "swaks not found in PATH"}
    cmd = [sk, "--to", to, "--server", server, "--port", str(port)]
    if from_addr:
        cmd.extend(["--from", from_addr])
    if subject:
        cmd.extend(["--header", f"Subject: {subject}"])
    if body:
        cmd.extend(["--body", body])
    if tls:
        cmd.append("--tls")
    if auth_user and auth_pass:
        cmd.extend(["--auth", "LOGIN", "--auth-user", auth_user,
                    "--auth-pass", auth_pass])
    if attach:
        cmd.extend(["--attach", attach])
    if header:
        cmd.extend(["--header", header])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {"rc": r.returncode, "stdout": r.stdout[:2000]}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# NetExec — pre-created computer account check (pre2k)
# ---------------------------------------------------------------------------
def netexec_pre2k(domain: str, dc_ip: str, wordlist: str, *,
                  output_dir: Optional[Path] = None) -> Dict:
    """Check for pre-created computer accounts via NetExec."""
    nx = which("netexec")
    if not nx:
        return {"error": "netexec not found in PATH"}
    if not Path(wordlist).exists():
        return {"error": f"Wordlist not found: {wordlist}"}
    out_dir = Path(output_dir or Path.cwd())
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"netexec_pre2k_{domain}.txt"
    cmd = [nx, "pre2k", "-d", domain, "-dc-ip", dc_ip,
           "-inputfile", wordlist, "-o", str(out_file)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return {"rc": r.returncode, "output_file": str(out_file),
                "stdout": r.stdout[:2000]}
    except subprocess.TimeoutExpired:
        return {"error": "Timed out"}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Responder — LLMNR/NBT-NS/mDNS poisoner + HTTP/SMB rogue server
# ---------------------------------------------------------------------------
def responder_analyze(interface: str = "eth0", *,
                      analyze_mode: bool = False, verbose: bool = False,
                      log_dir: Optional[Path] = None,
                      timeout: int = 60) -> Dict:
    """Start Responder in analyze or poison mode, capture hashes."""
    r = which("responder") or which("Responder")
    if not r:
        return {"error": "responder not found in PATH"}
    out_dir = _default_out_dir("responder_logs", log_dir)
    cmd = [r, "-I", interface]
    if analyze_mode:
        cmd.append("-A")
    if verbose:
        cmd.append("-v")
    # Only wrap in sudo when we are not already root: sudo on a password-less
    # box adds a pointless subprocess, and on a password box it stalls without
    # a tty. We never pass invalid legacy flags (-r, -f on) — current
    # Responder builds reject them outright.
    if os.geteuid() != 0:
        cmd.insert(0, "sudo")
    try:
        import select
        # Binary mode + select() so the capture loop honors `timeout` even
        # when Responder is silent (blocking readline() used to hang the loop
        # far past the requested duration).
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL)
        buf = bytearray()
        output_buf = []
        start = time.time()
        deadline = start + timeout
        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            try:
                rlist, _, _ = select.select([proc.stdout], [], [], min(remaining, 0.5))
            except (OSError, ValueError):
                break
            if not rlist:
                continue
            try:
                chunk = os.read(proc.stdout.fileno(), 4096)
            except OSError:
                break
            if not chunk:
                break
            buf.extend(chunk)
            while b"\n" in buf:
                line, _, buf = buf.partition(b"\n")
                output_buf.append(line.decode("utf-8", "replace").rstrip())
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        return {
            "rc": proc.returncode,
            "mode": "analyze" if analyze_mode else "poison",
            "interface": interface,
            "output_lines": output_buf[-100:],
            "log_dir": str(out_dir),
            "note": "Check log dir for NTLMv2 hashes captured",
        }
    except Exception as e:
        return {"error": str(e)}


def responder_poison(interface: str = "eth0", *,
                     log_dir: Optional[Path] = None,
                     timeout: int = 300) -> Dict:
    """Run Responder in poison mode to capture NTLMv2 hashes."""
    return responder_analyze(interface=interface, analyze_mode=False,
                             log_dir=log_dir, timeout=timeout)


# ---------------------------------------------------------------------------
# Evil-WinRM — WinRM shell for post-exploitation
# ---------------------------------------------------------------------------
def evil_winrm_connect(ip: str, *, username: str = "",
                       password: str = "", hash_value: str = "",
                       certificate: str = "", command: str = "",
                       output_dir: Optional[Path] = None) -> Dict:
    """Connect to a WinRM service with Evil-WinRM for command execution."""
    ew = which("evil-winrm")
    if not ew:
        return {"error": "evil-winrm not found in PATH"}
    out_dir = Path(output_dir or Path.cwd())
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [ew, "-i", ip]
    if username:
        cmd.extend(["-u", username])
    if password:
        cmd.extend(["-p", password])
    if hash_value:
        cmd.extend(["-H", hash_value])
    if certificate:
        cmd.extend(["-c", certificate])
    out_file = out_dir / f"evil_winrm_{ip}_{username or 'anon'}.log"
    if command:
        # evil-winrm: -c runs a PS command and exits; -s is a scripts DIR
        cmd.extend(["-c", command])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        result = {"rc": r.returncode, "ip": ip}
        if command:
            result["output_file"] = str(out_file)
            out_file.write_text(r.stdout)
        else:
            result["stdout"] = r.stdout[:3000]
        return result
    except subprocess.TimeoutExpired:
        return {"error": "Timed out"}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Hydra — brute-force login for multiple protocols
# ---------------------------------------------------------------------------
def hydra_bruteforce(protocol: str, target: str, userlist: str,
                     passlist: str, *, port: int = 0,
                     service: str = "", extra_args: str = "",
                     output_dir: Optional[Path] = None) -> Dict:
    """Run Hydra brute-force against a service with user/pass lists."""
    h = which("hydra")
    if not h:
        return {"error": "hydra not found in PATH"}
    for fn, name in [(userlist, "userlist"), (passlist, "passlist")]:
        if not Path(fn).exists():
            return {"error": f"{name} not found: {fn}"}
    out_dir = Path(output_dir or Path.cwd())
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"hydra_{protocol}_{target}.json"
    cmd = [h, "-L", userlist, "-P", passlist, "-o", str(out_file), "-t", "4"]
    if port:
        cmd.extend(["-s", str(port)])
    if extra_args:
        cmd.extend(shlex.split(extra_args))
    service_target = service or protocol
    cmd.append(f"{service_target}://{target}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        result = {"rc": r.returncode, "command": " ".join(cmd[:8]) + " ...",
                  "output_file": str(out_file)}
        if out_file.exists():
            result["output"] = out_file.read_text()[:2000]
        else:
            result["stdout"] = r.stdout[:2000]
        return result
    except subprocess.TimeoutExpired:
        return {"error": "Timed out"}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# John the Ripper — hash cracking
# ---------------------------------------------------------------------------
def john_crack(hash_file: str, *, wordlist: str = "",
               rules: str = "", format: str = "",
               output_dir: Optional[Path] = None,
               show: bool = False) -> Dict:
    """Crack hashes with John the Ripper using wordlist or rules."""
    j = which("john")
    if not j:
        return {"error": "john not found in PATH"}
    hf = Path(hash_file)
    if not hf.exists():
        return {"error": f"Hash file not found: {hash_file}"}
    out_dir = Path(output_dir or Path.cwd())
    out_dir.mkdir(parents=True, exist_ok=True)
    pot_file = out_dir / "john.pot"
    cmd = [j, f"--pot={pot_file}"]
    if wordlist:
        if not Path(wordlist).exists():
            return {"error": f"Wordlist not found: {wordlist}"}
        cmd.extend([f"--wordlist={wordlist}"])
    if rules:
        cmd.append(f"--rules={rules}")
    if format:
        cmd.append(f"--format={format}")
    cmd.append(str(hf))
    if show:
        cmd.append("--show")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        result = {"rc": r.returncode, "pot_file": str(pot_file)}
        if show:
            result["cracked"] = [l for l in r.stdout.splitlines()
                                 if ":" in l and not l.startswith("(")]
        else:
            result["stdout"] = r.stdout[:2000]
        return result
    except subprocess.TimeoutExpired:
        return {"error": "Timed out"}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Impacket — secretsdump, wmiexec, psexec, smbexec, ticketer
# ---------------------------------------------------------------------------
def impacket_secretsdump(target: str, username: str = "", password: str = "",
                         domain: str = "", hash: str = "",
                         output_dir: Optional[Path] = None,
                         just_dc: bool = False, just_dc_ntlm: bool = False,
                         history: bool = False, user_status: bool = False) -> Dict:
    """Dump SAM/LSA/AD secrets via Impacket secretsdump."""
    imp = which("impacket-secretsdump") or which("secretsdump")
    if not imp:
        imp = which("secretsdump.py")
    if not imp:
        return {"error": "impacket-secretsdump not found in PATH"}
    out_dir = _default_out_dir("impacket_output", output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"secretsdump_{target}.txt"
    target_str = target
    if domain and username:
        target_str = f"{domain}/{username}:{password}@{target}" if password else f"{domain}/{username}@{target}"
    elif username:
        target_str = f"{username}:{password}@{target}" if password else f"{username}@{target}"
    cmd = [imp, target_str]
    if hash:
        cmd.extend(["-hashes", f":{hash}"])
    if just_dc:
        cmd.append("-just-dc")
    if just_dc_ntlm:
        cmd.append("-just-dc-ntlm")
    if history:
        cmd.append("-history")
    if user_status:
        cmd.append("-user-status")
    cmd.extend(["-outputfile", str(out_file.with_suffix(""))])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return {"rc": r.returncode, "output_file": str(out_file),
                "stdout": r.stdout[:3000], "stderr": r.stderr[:500]}
    except subprocess.TimeoutExpired:
        return {"error": "Timed out"}
    except Exception as e:
        return {"error": str(e)}


def impacket_wmiexec(target: str, username: str = "", password: str = "",
                     domain: str = "", hash: str = "",
                     command: str = "whoami") -> Dict:
    """Execute commands via WMI using Impacket wmiexec."""
    imp = which("impacket-wmiexec") or which("wmiexec")
    if not imp:
        return {"error": "impacket-wmiexec not found in PATH"}
    target_str = f"{domain}/{username}:{password}@{target}" if domain else f"{username}:{password}@{target}"
    cmd = [imp, target_str, command]
    if hash:
        cmd = [imp, "-hashes", f":{hash}", target_str, command]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return {"rc": r.returncode, "stdout": r.stdout[:3000]}
    except Exception as e:
        return {"error": str(e)}


def impacket_psexec(target: str, username: str = "", password: str = "",
                    domain: str = "", hash: str = "",
                    command: str = "cmd.exe /c whoami") -> Dict:
    """Execute commands via SMB using Impacket psexec."""
    imp = which("impacket-psexec") or which("psexec")
    if not imp:
        return {"error": "impacket-psexec not found in PATH"}
    target_str = f"{domain}/{username}:{password}@{target}" if domain else f"{username}:{password}@{target}"
    cmd = [imp, target_str, command]
    if hash:
        cmd = [imp, "-hashes", f":{hash}", target_str, command]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return {"rc": r.returncode, "stdout": r.stdout[:3000]}
    except Exception as e:
        return {"error": str(e)}


def impacket_smbexec(target: str, username: str = "", password: str = "",
                     domain: str = "", hash: str = "",
                     command: str = "whoami") -> Dict:
    """Execute commands via SMB using Impacket smbexec (no service creation)."""
    imp = which("impacket-smbexec") or which("smbexec")
    if not imp:
        return {"error": "impacket-smbexec not found in PATH"}
    target_str = f"{domain}/{username}:{password}@{target}" if domain else f"{username}:{password}@{target}"
    cmd = [imp, target_str, command]
    if hash:
        cmd = [imp, "-hashes", f":{hash}", target_str, command]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return {"rc": r.returncode, "stdout": r.stdout[:3000]}
    except Exception as e:
        return {"error": str(e)}


def impacket_ticketer(domain: str, username: str, ntlm_hash: str = "",
                      domain_sid: str = "", krbtgt_hash: str = "",
                      output_dir: Optional[Path] = None,
                      extra_sids: str = "", duration_hours: int = 10,
                      user_id: int = 500) -> Dict:
    """Create a golden/silver Kerberos ticket via Impacket ticketer."""
    imp = which("impacket-ticketer") or which("ticketer")
    if not imp:
        return {"error": "impacket-ticketer not found in PATH"}
    out_dir = _default_out_dir("impacket_output", output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [imp, "-nthash", ntlm_hash, "-domain-sid", domain_sid,
           "-domain", domain, "-duration", str(duration_hours),
           "-user-id", str(user_id), username]
    if krbtgt_hash:
        cmd.extend(["-krbtgt-hash", krbtgt_hash])
    if extra_sids:
        cmd.extend(["-extra-sid", extra_sids])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                           cwd=str(out_dir))
        ticket_file = out_dir / f"{username}.ccache"
        return {"rc": r.returncode, "output_dir": str(out_dir),
                "ticket": str(ticket_file) if ticket_file.exists() else "",
                "stdout": r.stdout[:1000]}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# ffuf / gobuster — web content/parameter fuzzing
# ---------------------------------------------------------------------------
def ffuf_fuzz(url: str, wordlist: str, *, mode: str = "dir",
              extensions: str = "", filter_size: str = "",
              extra_args: str = "", output_dir: Optional[Path] = None,
              timeout: int = 600) -> Dict:
    """Run ffuf for directory/file/parameter fuzzing."""
    ff = which("ffuf")
    if not ff:
        return {"error": "ffuf not found in PATH"}
    if not Path(wordlist).exists():
        return {"error": f"Wordlist not found: {wordlist}"}
    out_dir = _default_out_dir("ffuf_output", output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"ffuf_{Path(url).stem}.json"
    cmd = [ff, "-u", url, "-w", wordlist, "-o", str(out_file), "-of", "json"]
    if mode == "dir":
        cmd.append("-c")
    elif mode == "params":
        cmd.extend(["-mode", "pb"])
    elif mode == "vhost":
        from urllib.parse import urlparse
        host = urlparse(url).netloc or url.strip("/")
        cmd.extend(["-H", f"Host: FUZZ.{host}"])
    if extensions:
        cmd.extend(["-e", extensions])
    if filter_size:
        cmd.extend(["-fs", filter_size])
    if extra_args:
        cmd.extend(shlex.split(extra_args))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        results = {"rc": r.returncode, "output_file": str(out_file)}
        if out_file.exists():
            try:
                data = json.loads(out_file.read_text())
                results["results"] = data.get("results", [])
                results["total"] = len(results["results"])
            except Exception:

                logger.debug("Exception in tool_wrappers.py", exc_info=True)
        results["stdout"] = r.stdout[:1000]
        return results
    except subprocess.TimeoutExpired:
        return {"error": f"Timed out after {timeout}s"}
    except Exception as e:
        return {"error": str(e)}


def gobuster_dir(url: str, wordlist: str, *, extensions: str = "",
                 output_dir: Optional[Path] = None,
                 timeout: int = 600) -> Dict:
    """Run gobuster for directory/file brute-forcing."""
    gb = which("gobuster")
    if not gb:
        return {"error": "gobuster not found in PATH"}
    out_dir = _default_out_dir("gobuster_output", output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"gobuster_{Path(url).stem}.txt"
    cmd = [gb, "dir", "-u", url, "-w", wordlist, "-o", str(out_file)]
    if extensions:
        cmd.extend(["-x", extensions])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        results = {"rc": r.returncode, "output_file": str(out_file)}
        if out_file.exists():
            results["output"] = out_file.read_text()[:3000]
        else:
            results["stdout"] = r.stdout[:2000]
        return results
    except subprocess.TimeoutExpired:
        return {"error": f"Timed out after {timeout}s"}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# hashcat — GPU-accelerated hash cracking
# ---------------------------------------------------------------------------
def hashcat_crack(hash_file: str, wordlist: str = "", mask: str = "",
                  hash_mode: int = 0, rules: str = "",
                  output_dir: Optional[Path] = None,
                  show: bool = False, username: bool = False,
                  extra_args: str = "", device: str = "",
                  timeout: int = 7200) -> Dict:
    """Crack hashes with hashcat (GPU-accelerated).

    Pass `wordlist` for an -a 0 dictionary attack, or `mask` (e.g.
    "?d?d?d?d") for an -a 3 mask attack. One of them is required: silently
    inventing a default 8-char brute-force mask is how expensive surprises
    happen.
    """
    hc = which("hashcat")
    if not hc:
        return {"error": "hashcat not found in PATH"}
    hf = Path(hash_file)
    if not hf.exists():
        return {"error": f"Hash file not found: {hash_file}"}
    if wordlist and mask:
        return {"error": "Provide either wordlist (-a 0) or mask (-a 3), not both"}
    if not wordlist and not mask:
        return {"error": "No attack specified: pass wordlist for -a 0 or mask for -a 3"}
    out_dir = _default_out_dir("hashcat_output", output_dir)
    pot_file = out_dir / "hashcat.potfile"
    out_file = out_dir / "cracked.txt"
    cmd = [hc, "-m", str(hash_mode), "--potfile-path", str(pot_file),
           "-o", str(out_file)]
    if username:
        cmd.append("--username")
    if wordlist:
        cmd.extend(["-a", "0", str(hf), wordlist])
    else:
        cmd.extend(["-a", "3", str(hf), mask])
    if rules:
        cmd.extend(["-r", rules])
    if show:
        cmd.append("--show")
    if device:
        cmd.extend(["-D", device])
    if extra_args:
        cmd.extend(shlex.split(extra_args))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        result = {"rc": r.returncode, "pot_file": str(pot_file)}
        if out_file.exists():
            cracked = out_file.read_text().strip().splitlines()
            result["cracked"] = cracked[:100]
            result["cracked_count"] = len(cracked)
        result["stdout"] = r.stdout[:2000]
        return result
    except subprocess.TimeoutExpired:
        return {"error": f"Timed out after {timeout}s"}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Burp Suite / Caido — import scan results
# ---------------------------------------------------------------------------
def burp_import_xml(xml_file: str, case_id: str = "",
                    output_dir: Optional[Path] = None) -> Dict:
    """Parse Burp Suite XML export into structured findings."""
    xml_p = Path(xml_file)
    if not xml_p.exists():
        return {"error": f"XML file not found: {xml_file}"}
    out_dir = _default_out_dir("burp_imports", output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(xml_p)
        root = tree.getroot()
        findings = []
        for item in root.iter("item"):
            finding = {
                "url": item.findtext("url", ""),
                "path": item.findtext("path", ""),
                "severity": item.findtext("severity", ""),
                "confidence": item.findtext("confidence", ""),
                "name": item.findtext("name", ""),
                "issue_detail": item.findtext("issueDetail", "")[:500],
                "remediation": item.findtext("remediationBackground", "")[:500],
            }
            findings.append(finding)
        out_file = out_dir / f"burp_{xml_p.stem}.json"
        out_file.write_text(json.dumps(findings, indent=2))
        return {"total_findings": len(findings), "output_file": str(out_file),
                "findings": findings}
    except ImportError:
        return {"error": "xml.etree.ElementTree not available"}
    except Exception as e:
        return {"error": str(e)}


def caido_import_json(json_file: str, case_id: str = "",
                      output_dir: Optional[Path] = None) -> Dict:
    """Parse Caido JSON export into structured findings."""
    jp = Path(json_file)
    if not jp.exists():
        return {"error": f"File not found: {json_file}"}
    out_dir = _default_out_dir("caido_imports", output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        data = json.loads(jp.read_text())
        issues = data if isinstance(data, list) else data.get("issues", data.get("results", []))
        findings = []
        for issue in issues:
            finding = {
                "url": issue.get("url", issue.get("host", "")),
                "severity": issue.get("severity", issue.get("risk", "")),
                "name": issue.get("name", issue.get("title", "")),
                "description": issue.get("description", "")[:500],
            }
            findings.append(finding)
        out_file = out_dir / f"caido_{jp.stem}.json"
        out_file.write_text(json.dumps(findings, indent=2))
        return {"total_findings": len(findings), "output_file": str(out_file)}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# linpeas / winpeas — privilege escalation check execution
# ---------------------------------------------------------------------------
def linpeas_run(target_host: str = "", target_user: str = "",
                target_pass: str = "", local_path: str = "") -> Dict:
    """Execute linpeas.sh on a remote target via SSH or locally."""
    lp = Path(local_path) if local_path else which("linpeas.sh")
    if not lp or not Path(lp).exists():
        lp = Path("/usr/share/peas/linpeas.sh")
    if not lp.exists():
        return {"error": "linpeas.sh not found. Provide --local-path or install."}

    out_dir = Path.cwd() / "peas_output"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"linpeas_{target_host or 'local'}.txt"

    if target_host and target_user:
        # Remote via SSH
        import subprocess as sp
        cmd = ["sshpass", "-p", target_pass, "ssh", "-o", "StrictHostKeyChecking=no",
               f"{target_user}@{target_host}", "bash -s"] if target_pass else \
              ["ssh", "-o", "StrictHostKeyChecking=no",
               f"{target_user}@{target_host}", "bash -s"]
        try:
            with open(lp, "rb") as f:
                script_data = f.read()
            r = sp.run(cmd, input=script_data, capture_output=True, text=True, timeout=300)
            out_file.write_text(r.stdout)
            return {"rc": r.returncode, "output_file": str(out_file),
                    "stdout": r.stdout[-2000:]}
        except Exception as e:
            return {"error": str(e)}
    else:
        # Local
        r = subprocess.run(["bash", str(lp)], capture_output=True, text=True, timeout=600)
        out_file.write_text(r.stdout)
        return {"rc": r.returncode, "output_file": str(out_file),
                "stdout": r.stdout[-2000:]}


def winpeas_run(target_host: str = "", target_user: str = "",
                target_pass: str = "", local_path: str = "") -> Dict:
    """Execute winPEAS.exe on a remote target."""
    wp = Path(local_path) if local_path else which("winPEAS.exe")
    if not wp or not wp.exists():
        return {"error": "winPEAS not found. Provide --local-path or install."}
    out_dir = Path.cwd() / "peas_output"
    out_dir.mkdir(parents=True, exist_ok=True)

    if target_host and target_user:
        # Upload via SMB and execute via wmiexec/evil-winrm
        try:
            if target_pass:
                r = subprocess.run(
                    ["smbclient", f"//{target_host}/ADMIN$", "-U",
                     f"{target_user}%{target_pass}", "-c", f"put {wp} winPEAS.exe"],
                    capture_output=True, text=True, timeout=60)
                if r.returncode != 0:
                    return {"error": f"Upload failed: {r.stderr[:500]}"}
            return {"status": "winPEAS uploaded to ADMIN$",
                    "note": "Execute via: evil-winrm -i {target} -u {user} -p {pass} -c 'C:\\Windows\\winPEAS.exe'"}
        except Exception as e:
            return {"error": str(e)}
    return {"error": "Remote target required for winPEAS (--target-host, --target-user)"}


# ---------------------------------------------------------------------------
# chisel / ligolo — tunnel/proxy management
# ---------------------------------------------------------------------------
def chisel_client(server: str, remote_port: int = 8080, local_port: int = 1080,
                  socks: bool = True, reverse: bool = False) -> Dict:
    """Start a chisel client tunnel to a remote server."""
    ch = which("chisel")
    if not ch:
        return {"error": "chisel not found in PATH"}
    if reverse:
        cmd = [ch, "client", server, f"R:{remote_port}:127.0.0.1:{local_port}"]
    elif socks:
        cmd = [ch, "client", server, f"{remote_port}:socks"]
    else:
        cmd = [ch, "client", server, f"{remote_port}:127.0.0.1:{local_port}"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"status": f"Chisel client started -> {server}",
                "pid": proc.pid, "mode": "reverse" if reverse else "forward"}
    except Exception as e:
        return {"error": str(e)}


def chisel_server(port: int = 8080, socks: bool = True) -> Dict:
    """Start a chisel server for incoming tunnel connections."""
    ch = which("chisel")
    if not ch:
        return {"error": "chisel not found in PATH"}
    cmd = [ch, "server", "--port", str(port)]
    if socks:
        cmd.append("--socks5")
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"status": f"Chisel server on :{port}", "pid": proc.pid}
    except Exception as e:
        return {"error": str(e)}


def ligolo_agent(server: str, proxy_port: int = 11601) -> Dict:
    """Start a Ligolo agent that connects back to the proxy."""
    lg = which("ligolo-agent")
    if not lg:
        return {"error": "ligolo-agent not found in PATH"}
    cmd = [lg, "-connect", f"{server}:{proxy_port}", "-ignore-cert"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"status": f"Ligolo agent -> {server}:{proxy_port}", "pid": proc.pid}
    except Exception as e:
        return {"error": str(e)}


def ligolo_proxy(listen_port: int = 11601) -> Dict:
    """Start a Ligolo proxy that listens for agent connections."""
    lg = which("ligolo-proxy")
    if not lg:
        return {"error": "ligolo-proxy not found in PATH"}
    cmd = [lg, "-listen", f"0.0.0.0:{listen_port}", "-self-cert"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"status": f"Ligolo proxy on :{listen_port}", "pid": proc.pid}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# enum4linux-ng — SMB/RPC enumeration with structured output
# ---------------------------------------------------------------------------
def enum4linux_ng(target: str, *, username: str = "", password: str = "",
                  domain: str = "", output_dir: Optional[Path] = None,
                  all_checks: bool = True, timeout: int = 300) -> Dict:
    """Enumerate Windows/Samba hosts via SMB/RPC using enum4linux-ng."""
    e4l = which("enum4linux-ng")
    if not e4l:
        return {"error": "enum4linux-ng not found in PATH"}
    out_dir = _default_out_dir("enum4linux_output", output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"enum4linux_{target}.json"
    cmd = [e4l, "-oA", str(out_file.with_suffix("")), "-t", target]
    if username and password:
        cmd.extend(["-u", username, "-p", password])
    if domain:
        cmd.extend(["-d", domain])
    if all_checks:
        cmd.append("-a")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        result = {"rc": r.returncode, "output_file": str(out_file)}
        # Also read JSON output if it exists
        if out_file.exists():
            try:
                data = json.loads(out_file.read_text())
                result["users"] = data.get("users", [])
                result["shares"] = data.get("shares", [])
                result["os_info"] = data.get("os", "")
            except Exception:

                logger.debug("Exception in tool_wrappers.py", exc_info=True)
        result["stdout"] = r.stdout[-2000:]
        return result
    except subprocess.TimeoutExpired:
        return {"error": "Timed out"}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# ProjectDiscovery recon stack (subfinder / httpx / naabu / dnsx / katana)
# ---------------------------------------------------------------------------
_PDTM_BIN_DIR = Path(os.environ.get("PDTM_BIN_DIR",
                                    str(Path.home() / ".pdtm" / "go" / "bin")))


def _find_pd_bin(name: str) -> Optional[str]:
    """Locate a ProjectDiscovery binary, preferring the pdtm install dir.

    pdtm installs tools into ~/.pdtm/go/bin which is usually NOT on PATH, so
    the plain ``which()`` lookup would miss them. Worse, on this host
    ``/usr/bin/httpx`` is the unrelated ``python3-httpx`` package CLI, so
    checking PATH first would select the WRONG binary for httpx. We therefore
    check the pdtm dir first and only then fall back to PATH.
    """
    candidates = [_PDTM_BIN_DIR / name]
    fp = which(name)
    if fp:
        candidates.append(Path(fp))
    for c in candidates:
        if c.is_file() and os.access(c, os.X_OK):
            return str(c)
    return None


def _load_jsonl(path: Path) -> List[dict]:
    """Read a JSON-lines file into a list of dicts (tolerant of bad lines)."""
    rows = []
    if not path.exists():
        return rows
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except Exception:
                logger.debug("Exception in tool_wrappers.py", exc_info=True)
                continue
            if isinstance(data, dict):
                rows.append(data)
    return rows


def subfinder_enum(domain: str, *, recursive: bool = False,
                   all_sources: bool = False, resolvers: str = "",
                   threads: int = 0, output_dir: Optional[Path] = None,
                   timeout: int = 600) -> Dict:
    """Enumerate subdomains with ProjectDiscovery subfinder.

    Passive subdomain discovery backed by many OSINT sources; add -all to pull
    every source including active brute-force based providers.
    """
    sf = _find_pd_bin("subfinder")
    if not sf:
        return {"error": "subfinder not found (checked PATH and ~/.pdtm/go/bin)"}
    out_dir = _default_out_dir("subfinder_output", output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"subfinder_{_safe_stem(domain)}.json"
    cmd = [sf, "-d", domain, "-silent", "-oJ", "-o", str(out_file)]
    if recursive:
        cmd.append("-recursive")
    if all_sources:
        cmd.append("-all")
    if resolvers:
        cmd.extend(["-r", resolvers])
    if threads > 0:
        cmd.extend(["-t", str(threads)])
    try:
        # stdin must be closed (DEVNULL): subfinder reads stdin and will block
        # forever otherwise when run from a daemon with inherited stdin.
        r = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True,
                           text=True, timeout=timeout)
        rows = _load_jsonl(out_file)
        hosts = sorted({row.get("host", "") for row in rows if row.get("host")})
        result = {"rc": r.returncode, "output_file": str(out_file),
                  "total": len(hosts), "subdomains": hosts}
        if r.stderr.strip():
            result["stderr"] = r.stderr[:1000]
        return result
    except subprocess.TimeoutExpired:
        # subfinder is source-rate-limited and often outlives the timeout while
        # still making progress; return whatever was already written to disk.
        rows = _load_jsonl(out_file)
        hosts = sorted({row.get("host", "") for row in rows if row.get("host")})
        return {"rc": -1, "output_file": str(out_file), "total": len(hosts),
                "subdomains": hosts,
                "stderr": f"Timed out after {timeout}s; returning partial results"}
    except Exception as e:
        return {"error": str(e)}


def httpx_probe(target: str = "", list_file: str = "",
                status_codes: str = "", include_title: bool = True,
                tech_detect: bool = True, follow_redirects: bool = False,
                threads: int = 0, output_dir: Optional[Path] = None,
                timeout: int = 600) -> Dict:
    """Probe hosts/URLs with ProjectDiscovery httpx.

    Take a single URL or a file of hosts and report live ones with status
    code, title, detected tech, and webserver. When neither target nor
    list_file is given, reads hosts from stdin (allows chaining subfinder).
    """
    hx = _find_pd_bin("httpx")
    if not hx:
        return {"error": "httpx not found (checked PATH and ~/.pdtm/go/bin)"}
    if not target and not list_file:
        return {"error": "Provide target (URL/host) or list_file of hosts"}
    out_dir = _default_out_dir("httpx_output", output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = Path(list_file).stem if list_file else (target or "probe").replace("/", "_")
    out_file = out_dir / f"httpx_{_safe_stem(stem)}.json"
    cmd = [hx, "-silent", "-json", "-o", str(out_file)]
    # PD httpx 2.x hangs when the target is passed via -u; piping hosts over
    # stdin is the reliable path. -l is used for a file of hosts.
    stdin_data = None
    if list_file:
        if not Path(list_file).exists():
            return {"error": f"Input file not found: {list_file}"}
        cmd.extend(["-l", list_file])
    elif target:
        stdin_data = "\n".join(
            h.strip() for h in target.replace(",", "\n").splitlines() if h.strip())
    if status_codes:
        cmd.extend(["-mc", status_codes])
    if include_title:
        cmd.append("-title")
    if tech_detect:
        cmd.append("-td")
    if follow_redirects:
        cmd.append("-follow-redirects")
    if threads > 0:
        cmd.extend(["-threads", str(threads)])
    try:
        r = subprocess.run(cmd, input=stdin_data, capture_output=True, text=True,
                           timeout=timeout)
        rows = _load_jsonl(out_file)
        hosts = []
        for row in rows:
            hosts.append({
                "url": row.get("url") or f"{row.get('scheme','http')}://{row.get('host','')}",
                "host": row.get("host", ""),
                "status_code": row.get("status_code"),
                "title": row.get("title", ""),
                "webserver": row.get("webserver", ""),
                "tech": row.get("tech") or [],
                "cdn": row.get("cdn_name", ""),
            })
        result = {"rc": r.returncode, "output_file": str(out_file),
                  "total": len(hosts), "hosts": hosts}
        if r.stderr.strip():
            result["stderr"] = r.stderr[:1000]
        return result
    except subprocess.TimeoutExpired:
        return {"error": f"Timed out after {timeout}s"}
    except Exception as e:
        return {"error": str(e)}


def naabu_scan(target: str, *, ports: str = "", top_ports: int = 0,
               rate: int = 0, service_detect: bool = False,
               output_dir: Optional[Path] = None, timeout: int = 900) -> Dict:
    """Fast port scan with ProjectDiscovery naabu.

    Scans a single host (or comma-separated hosts). Use ports like
    '80,443,8080' or '1-1000'; top_ports=1000 is a sane default when neither
    is given. service_detect (-sV) adds nmap-based version detection.
    """
    nb = _find_pd_bin("naabu")
    if not nb:
        return {"error": "naabu not found (checked PATH and ~/.pdtm/go/bin)"}
    out_dir = _default_out_dir("naabu_output", output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"naabu_{_safe_stem(target)}.json"
    # naabu 2.6.x hangs when hosts are passed via -host/-l; piping them over
    # stdin is the reliable path for raw targets and -list mode alike.
    cmd = [nb, "-silent", "-json", "-o", str(out_file)]
    if ports:
        cmd.extend(["-p", ports])
    elif top_ports > 0:
        cmd.extend(["-top-ports", str(top_ports)])
    if rate > 0:
        cmd.extend(["-rate", str(rate)])
    if service_detect:
        cmd.append("-sV")
    stdin_hosts = "\n".join(
        h.strip() for h in target.replace(",", "\n").splitlines() if h.strip())
    try:
        r = subprocess.run(cmd, input=stdin_hosts, capture_output=True, text=True,
                           timeout=timeout)
        rows = _load_jsonl(out_file)
        ports_found = sorted({row.get("port") for row in rows if row.get("port")})
        hosts = {}
        for row in rows:
            h = row.get("host", "")
            p = row.get("port")
            hosts.setdefault(h, []).append({"port": p, "protocol": row.get("protocol", "tcp")})
        result = {"rc": r.returncode, "output_file": str(out_file),
                  "hosts_scanned": target, "ports": ports_found,
                  "total_open": len(ports_found), "detail": hosts}
        if r.stderr.strip():
            result["stderr"] = r.stderr[:1000]
        return result
    except subprocess.TimeoutExpired:
        return {"error": f"Timed out after {timeout}s"}
    except Exception as e:
        return {"error": str(e)}


def dnsx_probe(domain: str = "", list_file: str = "",
               record_types: str = "a,aaaa,cname,mx,ns,txt,soa",
               resp_only: bool = False, output_dir: Optional[Path] = None,
               timeout: int = 600) -> Dict:
    """Run DNS lookups with ProjectDiscovery dnsx.

    Supports multiple record types in one pass. Provide a domain (-d) or a
    list_file of domains (-l); a blank domain reads from stdin (chaining
    subfinder output).
    """
    dx = _find_pd_bin("dnsx")
    if not dx:
        return {"error": "dnsx not found (checked PATH and ~/.pdtm/go/bin)"}
    if not domain and not list_file:
        return {"error": "Provide domain or list_file of domains"}
    out_dir = _default_out_dir("dnsx_output", output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = Path(list_file).stem if list_file else (domain or "dns")
    out_file = out_dir / f"dnsx_{_safe_stem(stem)}.json"
    cmd = [dx, "-silent", "-json", "-o", str(out_file)]
    # dnsx 2.x requires -w wordlist with -d, so a single domain is piped via
    # stdin; -l is used for a file of domains. Blank input chains subfinder.
    stdin_data = None
    if list_file:
        if not Path(list_file).exists():
            return {"error": f"Input file not found: {list_file}"}
        cmd.extend(["-l", list_file])
    elif domain:
        stdin_data = "\n".join(
            h.strip() for h in domain.replace(",", "\n").splitlines() if h.strip())
    type_flags = {
        "a": "-a", "aaaa": "-aaaa", "cname": "-cname", "mx": "-mx",
        "ns": "-ns", "txt": "-txt", "soa": "-soa", "srv": "-srv",
        "ptr": "-ptr", "caa": "-caa",
    }
    for t in [x.strip() for x in record_types.split(",") if x.strip()]:
        flag = type_flags.get(t.lower())
        if flag:
            cmd.append(flag)
    if resp_only:
        cmd.append("-resp")
    try:
        r = subprocess.run(cmd, input=stdin_data, capture_output=True, text=True,
                           timeout=timeout)
        rows = _load_jsonl(out_file)
        records = []
        for row in rows:
            for key in ("a", "aaaa", "cname", "mx", "ns", "txt", "soa", "srv", "ptr", "caa"):
                val = row.get(key)
                if val:
                    records.append({"host": row.get("host", ""), "type": key.upper(), "value": val})
        result = {"rc": r.returncode, "output_file": str(out_file),
                  "total": len(records), "records": records}
        if r.stderr.strip():
            result["stderr"] = r.stderr[:1000]
        return result
    except subprocess.TimeoutExpired:
        return {"error": f"Timed out after {timeout}s"}
    except Exception as e:
        return {"error": str(e)}


def katana_crawl(url: str = "", list_file: str = "", *, depth: int = 2,
                 js_crawl: bool = False, known_files: bool = False,
                 output_dir: Optional[Path] = None, timeout: int = 900) -> Dict:
    """Crawl a web app with ProjectDiscovery katana.

    Discovers endpoints, JS files, and hidden paths. js_crawl (-jc) parses JS
    files for further endpoints; known_files (-kf) requests common files.
    """
    kt = _find_pd_bin("katana")
    if not kt:
        return {"error": "katana not found (checked PATH and ~/.pdtm/go/bin)"}
    if not url and not list_file:
        return {"error": "Provide url or list_file of URLs"}
    out_dir = _default_out_dir("katana_output", output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = Path(list_file).stem if list_file else (url or "crawl").split("://")[-1].replace("/", "_")
    out_file = out_dir / f"katana_{_safe_stem(stem)}.txt"
    cmd = [kt, "-silent", "-o", str(out_file), "-d", str(depth)]
    # PD katana 2.x hangs when the seed URL is passed via -u; pipe it via stdin.
    stdin_data = None
    if list_file:
        if not Path(list_file).exists():
            return {"error": f"Input file not found: {list_file}"}
        cmd.extend(["-l", list_file])
    elif url:
        stdin_data = "\n".join(
            u.strip() for u in url.replace(",", "\n").splitlines() if u.strip())
    if js_crawl:
        cmd.append("-jc")
    if known_files:
        cmd.append("-kf")
    try:
        r = subprocess.run(cmd, input=stdin_data, capture_output=True, text=True,
                           timeout=timeout)
        urls = []
        if out_file.exists():
            urls = [ln.strip() for ln in out_file.read_text().splitlines()
                    if ln.strip() and not ln.startswith("[")][:5000]
        result = {"rc": r.returncode, "output_file": str(out_file),
                  "total": len(urls), "urls": urls[:1000]}
        if r.stderr.strip():
            result["stderr"] = r.stderr[:1000]
        return result
    except subprocess.TimeoutExpired:
        urls = []
        if out_file.exists():
            urls = [ln.strip() for ln in out_file.read_text().splitlines()
                    if ln.strip() and not ln.startswith("[")][:5000]
        return {"rc": -1, "output_file": str(out_file), "total": len(urls),
                "urls": urls[:1000],
                "stderr": f"Timed out after {timeout}s; returning partial results"}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Auto-recon pipeline — chain nmap → ffuf → nuclei → nikto
# ---------------------------------------------------------------------------
def auto_recon(target: str, wordlist_dir: Optional[str] = None,
               output_dir: Optional[Path] = None) -> Dict:
    """Run a chained reconnaissance pipeline: nmap → ffuf → nuclei.

    1. Nmap initial TCP scan (top 1000)
    2. Parse open ports
    3. If port 80/443 open, run ffuf directory fuzzing
    4. Run nuclei against web services
    """
    from .nmap_wrapper import scan_initial_tcp, parse_results
    out_dir = Path(output_dir or Path.cwd() / "autorecon" / target)
    out_dir.mkdir(parents=True, exist_ok=True)
    wl_dir = Path(wordlist_dir or "/usr/share/wordlists")
    results = {"target": target, "output_dir": str(out_dir), "phases": {}}

    # Phase 1: Nmap
    print(f"[autorecon] Phase 1: Nmap ({target})")
    nmap_result = scan_initial_tcp(target, output_dir=out_dir)
    results["phases"]["nmap"] = nmap_result.get("rc", "FAIL")
    if nmap_result.get("error"):
        results["error"] = nmap_result["error"]
        return results

    # Phase 2: Parse ports for web
    parsed = parse_results(target, output_dir=out_dir)
    open_ports = parsed.get("open_ports_tcp", [])
    results["open_ports"] = open_ports
    web_ports = [p for p in open_ports if p in (80, 443, 8080, 8443, 3000, 5000, 8000, 8888)]

    # Phase 3: ffuf if web ports found
    if web_ports:
        print(f"[autorecon] Phase 2: ffuf on ports {web_ports}")
        dir_wl = wl_dir / "directory-list-2.3-medium.txt"
        if dir_wl.exists():
            ffuf_results = {}
            for port in web_ports[:3]:  # limit to 3 web ports
                url = f"https://{target}:{port}/FUZZ" if port in (443, 8443) else f"http://{target}:{port}/FUZZ"
                r = ffuf_fuzz(url, str(dir_wl), timeout=300)
                ffuf_results[str(port)] = r.get("total", 0)
            results["phases"]["ffuf"] = ffuf_results
    else:
        results["phases"]["ffuf"] = "skipped"

    # Phase 4: Nuclei
    print("[autorecon] Phase 3: Nuclei")
    nuc = which("nuclei")
    if nuc:
        nuc_out = out_dir / f"nuclei_{target}.json"
        nuc_cmd = [nuc, "-u", target, "-json", "-o", str(nuc_out), "-rl", "50"]
        if web_ports:
            nuc_cmd.extend(["-p", ",".join(str(p) for p in web_ports)])
        try:
            r = subprocess.run(nuc_cmd, capture_output=True, text=True, timeout=600)
            results["phases"]["nuclei"] = {"rc": r.returncode, "output": str(nuc_out)}
        except Exception as e:
            results["phases"]["nuclei"] = {"error": str(e)}
    else:
        results["phases"]["nuclei"] = "skipped (not installed)"

    return results


# ---------------------------------------------------------------------------
# Loot DB — centralized credential/hash/token storage
# ---------------------------------------------------------------------------
class LootDB:
    """Simple SQLite-backed loot storage for credentials, hashes, tokens."""

    def __init__(self, path: Optional[Path] = None):
        self.db_path = Path(path or Path.cwd() / "loot.db")
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._init_db()

    def _init_db(self):
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT, target TEXT, username TEXT, password TEXT,
                hash TEXT, hash_type TEXT, domain TEXT,
                protocol TEXT, port INTEGER, notes TEXT,
                discovered TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT, token_type TEXT, token_value TEXT,
                target TEXT, expires TIMESTAMP, notes TEXT,
                discovered TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT, session_id TEXT, target TEXT,
                protocol TEXT, data TEXT,
                discovered TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_user ON credentials(username);
            CREATE INDEX IF NOT EXISTS idx_target ON credentials(target);
        """)
        self._conn.commit()

    def add_credential(self, source: str, target: str, username: str,
                       password: str = "", hash: str = "", hash_type: str = "",
                       domain: str = "", protocol: str = "",
                       port: int = 0, notes: str = "") -> int:
        cur = self._conn.execute(
            "INSERT INTO credentials (source,target,username,password,hash,hash_type,domain,protocol,port,notes) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (source, target, username, password, hash, hash_type,
             domain, protocol, port if port else None, notes))
        self._conn.commit()
        return cur.lastrowid

    def add_token(self, source: str, token_type: str, token_value: str,
                  target: str = "", expires: str = "", notes: str = "") -> int:
        cur = self._conn.execute(
            "INSERT INTO tokens (source,token_type,token_value,target,expires,notes) "
            "VALUES (?,?,?,?,?,?)",
            (source, token_type, token_value, target, expires, notes))
        self._conn.commit()
        return cur.lastrowid

    def add_session(self, source: str, session_id: str, target: str = "",
                    protocol: str = "", data: str = "") -> int:
        cur = self._conn.execute(
            "INSERT INTO sessions (source,session_id,target,protocol,data) "
            "VALUES (?,?,?,?,?)",
            (source, session_id, target, protocol, data))
        self._conn.commit()
        return cur.lastrowid

    def search(self, query: str) -> Dict:
        """Search across all loot tables."""
        like = f"%{query}%"
        creds = self._conn.execute(
            "SELECT * FROM credentials WHERE username LIKE ? OR password LIKE ? OR target LIKE ? OR hash LIKE ? OR notes LIKE ?",
            (like, like, like, like, like)).fetchall()
        tokens = self._conn.execute(
            "SELECT * FROM tokens WHERE token_value LIKE ? OR target LIKE ? OR notes LIKE ?",
            (like, like, like)).fetchall()
        sessions = self._conn.execute(
            "SELECT * FROM sessions WHERE session_id LIKE ? OR target LIKE ?",
            (like, like)).fetchall()
        return {
            "credentials": [dict(zip(["id","source","target","username","password","hash","hash_type","domain","protocol","port","notes","discovered"], c)) for c in creds],
            "tokens": [dict(zip(["id","source","token_type","token_value","target","expires","notes","discovered"], t)) for t in tokens],
            "sessions": [dict(zip(["id","source","session_id","target","protocol","data","discovered"], s)) for s in sessions],
        }

    def list_credentials(self, limit: int = 50) -> List[Dict]:
        rows = self._conn.execute(
            "SELECT * FROM credentials ORDER BY discovered DESC LIMIT ?", (limit,)).fetchall()
        return [dict(zip(["id","source","target","username","password","hash","hash_type","domain","protocol","port","notes","discovered"], r)) for r in rows]

    def close(self):
        self._conn.close()


# ---------------------------------------------------------------------------
# Phishing — EvilGinx2 / GoPhish
# ---------------------------------------------------------------------------
def evilginx_start(domain: str, config_dir: Optional[str] = None,
                   phishing_dir: Optional[str] = None) -> Dict:
    """Start EvilGinx2 with a given phishing domain."""
    eg = which("evilginx")
    if not eg:
        return {"error": "evilginx not found in PATH"}
    cmd = [eg, "-d", domain, "-p", phishing_dir or "/var/www/phishing"]
    if config_dir:
        cmd.extend(["-c", config_dir])
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"status": f"EvilGinx2 started for {domain}", "pid": proc.pid}
    except Exception as e:
        return {"error": str(e)}


def gophish_import_campaign(campaign_file: str, gophish_url: str = "",
                            api_key: str = "") -> Dict:
    """Import a GoPhish campaign JSON file (or send via API)."""
    cf = Path(campaign_file)
    if not cf.exists():
        return {"error": f"Campaign file not found: {campaign_file}"}

    if gophish_url and api_key:
        # Send via GoPhish API
        try:
            import urllib.request
            data = cf.read_text()
            req = urllib.request.Request(
                f"{gophish_url}/api/campaigns/",
                data=data.encode(),
                headers={"Content-Type": "application/json",
                         "Authorization": f"Bearer {api_key}"},
            )
            with urllib.request.urlopen(req) as resp:
                return {"status": "Campaign created via API",
                        "response": resp.read().decode()[:500]}
        except Exception as e:
            return {"error": str(e)}
    else:
        # Just validate and report
        try:
            campaign = json.loads(cf.read_text())
            return {"status": "Campaign JSON valid",
                    "name": campaign.get("name", ""),
                    "targets": len(campaign.get("targets", [])),
                    "template": campaign.get("template", {}).get("name", "")}
        except Exception as e:
            return {"error": f"Invalid campaign JSON: {e}"}


# ---------------------------------------------------------------------------
# pypykatz — LSASS dump parsing
# ---------------------------------------------------------------------------
def pypykatz_parse(dump_file: str, output_dir: Optional[Path] = None) -> Dict:
    """Parse a LSASS minidump or dump file with pypykatz."""
    ppk = which("pypykatz")
    if not ppk:
        return {"error": "pypykatz not found in PATH"}
    dp = Path(dump_file)
    if not dp.exists():
        return {"error": f"Dump file not found: {dump_file}"}
    out_dir = _default_out_dir("pypykatz_output", output_dir)
    out_file = out_dir / f"lsass_{dp.stem}.json"
    # --json is required for a machine-readable outfile: without it pypykatz
    # writes human text and the json.loads() below would always fail.
    cmd = [ppk, "lsa", "minidump", str(dp), "-o", str(out_file), "--json"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        result = {"rc": r.returncode}
        if out_file.exists():
            try:
                data = json.loads(out_file.read_text())
                result["parsed"] = data
                # Summarize what was found
                logon_sessions = data.get("logon_sessions", [])
                result["logon_sessions"] = len(logon_sessions)
                creds = data.get("credentials", [])
                result["total_credentials"] = len(creds)
                usernames = set()
                for ls in logon_sessions:
                    u = ls.get("username", "")
                    if u:
                        usernames.add(u)
                result["usernames"] = sorted(usernames)
            except Exception:
                result["output_file"] = str(out_file)
        else:
            result["stdout"] = r.stdout[:2000]
        return result
    except subprocess.TimeoutExpired:
        return {"error": "Timed out"}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# BloodHound.py — AD relationship ingestor
# ---------------------------------------------------------------------------
def bloodhound_ingest(domain: str, username: str, password: str,
                      dc_ip: str = "", dns_server: str = "",
                      collection_method: str = "All",
                      output_dir: Optional[Path] = None) -> Dict:
    """Run BloodHound.py Python ingestor against a domain."""
    bh_script = None
    for p in [Path("/share/tools/BloodHound.py/bloodhound.py"),
              Path.cwd() / "bloodhound.py"]:
        if p.exists():
            bh_script = p
            break
    if not bh_script:
        which_bh = which("bloodhound-python") or which("bloodhound.py")
        if which_bh:
            bh_script = Path(which_bh)
    if not bh_script:
        # Try pip package: python3 -m bloodhound
        try:
            r = subprocess.run(["python3", "-m", "bloodhound", "--help"],
                               capture_output=True, timeout=10)
            if r.returncode == 0:
                bh_script = Path("_pip_module_")
        except Exception:

            logger.debug("Exception in tool_wrappers.py", exc_info=True)
    if not bh_script:
        return {"error": "BloodHound.py not found. pip install bloodhound, or clone to /share/tools/BloodHound.py/"}

    out_dir = _default_out_dir("bloodhound_output", output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if str(bh_script) == "_pip_module_":
        cmd = ["python3", "-m", "bloodhound"]
        cwd = str(out_dir)
    else:
        cmd = ["python3", str(bh_script)]
        cwd = str(bh_script.parent)
    cmd += ["-d", domain, "-u", username, "-p", password,
            "-c", collection_method, "--zip"]
    if dc_ip:
        cmd += ["--dc", dc_ip]
    if dns_server:
        cmd += ["--dns-server", dns_server]
    cmd += ["--output-dir", str(out_dir)]
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=600)
        result = {"rc": r.returncode, "output_dir": str(out_dir)}
        zips = list(out_dir.glob("*.zip"))
        if zips:
            result["zip_file"] = str(zips[-1])
        result["stdout"] = r.stdout[-2000:]
        result["stderr"] = r.stderr[-500:] if r.stderr else ""
        return result
    except subprocess.TimeoutExpired:
        return {"error": "Timed out after 600s"}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Convenience: loot_db instance
# ---------------------------------------------------------------------------
def get_loot_db(path: Optional[str] = None) -> LootDB:
    """Get or create a LootDB instance (path defaults to cwd/loot.db)."""
    return LootDB(Path(path) if path else None)


# ---------------------------------------------------------------------------
# Metasploit — MSF RPC / resource script automation
# ---------------------------------------------------------------------------
def metasploit_resource(resource_script: str, *,
                        output_dir: Optional[Path] = None,
                        timeout: int = 300) -> Dict:
    """Run a Metasploit resource script (.rc) via msfconsole -q -r."""
    msf = which("msfconsole")
    if not msf:
        return {"error": "msfconsole not found in PATH"}
    rc = Path(resource_script)
    if not rc.exists():
        return {"error": f"Resource script not found: {resource_script}"}
    out_dir = Path(output_dir or Path.cwd())
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"msf_{rc.stem}.log"
    cmd = [msf, "-q", "-r", str(rc)]
    try:
        with open(out_file, "w") as f:
            r = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT,
                               text=True, timeout=timeout)
        return {"rc": r.returncode, "output_file": str(out_file),
                "stdout": out_file.read_text()[:2000]}
    except subprocess.TimeoutExpired:
        return {"error": f"Timed out after {timeout}s"}
    except Exception as e:
        return {"error": str(e)}


def metasploit_module(module: str, payload: str, target: str,
                      lhost: str = "", lport: int = 4444,
                      *options: str, output_dir: Optional[Path] = None,
                      timeout: int = 120) -> Dict:
    """Generate a temporary Metasploit .rc script and run it."""
    out_dir = Path(output_dir or Path.cwd())
    out_dir.mkdir(parents=True, exist_ok=True)
    rc_file = out_dir / f"msf_{module.replace('/', '_')}.rc"
    lines = [
        f"use {module}",
        f"set PAYLOAD {payload}",
        f"set RHOSTS {target}",
    ]
    if lhost:
        lines.append(f"set LHOST {lhost}")
    if lport:
        lines.append(f"set LPORT {lport}")
    for opt in options:
        lines.append(f"set {opt}")
    lines.append("run")
    lines.append("exit")
    rc_file.write_text("\n".join(lines) + "\n")
    return metasploit_resource(str(rc_file), output_dir=output_dir, timeout=timeout)


# ---------------------------------------------------------------------------
# SQLMap — automated SQL injection detection and exploitation
# ---------------------------------------------------------------------------
def sqlmap_detect(url: str, *,
                  data: str = "", cookie: str = "",
                  method: str = "", level: int = 1, risk: int = 1,
                  output_dir: Optional[Path] = None,
                  extra_args: str = "") -> Dict:
    """Run SQLMap to detect SQL injection vulnerabilities."""
    sm = which("sqlmap")
    if not sm:
        return {"error": "sqlmap not found in PATH"}
    out_dir = Path(output_dir or Path.cwd())
    out_dir.mkdir(parents=True, exist_ok=True)
    output_sub = out_dir / "sqlmap_output"
    output_sub.mkdir(parents=True, exist_ok=True)
    cmd = [sm, "-u", url, "--batch", "--output-dir", str(output_sub),
           f"--level={level}", f"--risk={risk}"]
    if data:
        cmd.extend(["--data", data])
    if cookie:
        cmd.extend(["--cookie", cookie])
    if method:
        cmd.extend(["--method", method])
    if extra_args:
        cmd.extend(shlex.split(extra_args))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        result = {
            "rc": r.returncode,
            "output_dir": str(output_sub),
            "stdout": r.stdout[:3000],
            "stderr": r.stderr[:1000],
            "note": "Check output_dir for logs and session files",
        }
        for line in r.stdout.splitlines():
            if "Parameter:" in line and "vulnerable" in r.stdout:
                result["vulnerable"] = True
                break
        return result
    except subprocess.TimeoutExpired:
        return {"error": "Timed out"}
    except Exception as e:
        return {"error": str(e)}


def sqlmap_exploit(url: str, *, data: str = "", cookie: str = "",
                   os_shell: bool = False, dump: bool = False,
                   db: str = "", table: str = "",
                   level: int = 1, risk: int = 1,
                   output_dir: Optional[Path] = None) -> Dict:
    """Exploit SQL injection with SQLMap (OS shell, dump DB, etc.)."""
    sm = which("sqlmap")
    if not sm:
        return {"error": "sqlmap not found in PATH"}
    out_dir = Path(output_dir or Path.cwd())
    out_dir.mkdir(parents=True, exist_ok=True)
    output_sub = out_dir / "sqlmap_exploit"
    output_sub.mkdir(parents=True, exist_ok=True)
    cmd = [sm, "-u", url, "--batch", "--output-dir", str(output_sub),
           f"--level={level}", f"--risk={risk}"]
    if data:
        cmd.extend(["--data", data])
    if cookie:
        cmd.extend(["--cookie", cookie])
    if os_shell:
        cmd.append("--os-shell")
    if dump:
        cmd.append("--dump")
    if db:
        cmd.extend(["-D", db])
    if table:
        cmd.extend(["-T", table])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        return {"rc": r.returncode, "output_dir": str(output_sub),
                "stdout": r.stdout[:3000]}
    except subprocess.TimeoutExpired:
        return {"error": "Timed out"}
    except Exception as e:
        return {"error": str(e)}