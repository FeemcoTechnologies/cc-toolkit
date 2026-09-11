"""Nmap pipeline — structured port scanning leveraging your nmaptest.sh workflow."""

import re
import subprocess
import time
from pathlib import Path
from shutil import which
from typing import Dict, List, Optional


def _nmap_path() -> str:
    nmap = which("nmap")
    if not nmap:
        raise FileNotFoundError("nmap not found in PATH")
    return nmap


def _parse_open_ports_from_outputs(output_dir: Path) -> str:
    """Parse open TCP/UDP ports from existing .nmap or .md output files."""
    ports = set()
    for f in output_dir.glob("*.nmap"):
        text = f.read_text(errors="ignore")
        for m in re.finditer(r"^(\d+)/(tcp|udp)\s+open", text, re.MULTILINE):
            ports.add(f"{m.group(1)}/{m.group(2)}")
    if not ports:
        for f in output_dir.glob("*.md"):
            text = f.read_text(errors="ignore")
            for m in re.finditer(r"^(\d+)/(tcp|udp)\s+open", text, re.MULTILINE):
                ports.add(f"{m.group(1)}/{m.group(2)}")
    if not ports:
        return ""
    # Deduplicate by port number — keep /tcp if both exist
    tcp_ports = sorted({int(p.split("/")[0]) for p in ports if "/tcp" in p})
    udp_ports = sorted({int(p.split("/")[0]) for p in ports if "/udp" in p})
    all_tcp = ",".join(str(p) for p in tcp_ports) if tcp_ports else ""
    all_udp = ",".join(str(p) for p in udp_ports) if udp_ports else ""
    if all_tcp and all_udp:
        return f"-p {all_tcp} -sS -sU --top-ports 0"
    if all_tcp:
        return f"-p {','.join(f'{p}' for p in sorted(tcp_ports))}"
    return f"-p {','.join(f'{p}' for p in sorted(udp_ports))}"


def _run_nmap(cmd: List[str], output_dir: Path, log_name: str,
              timeout: int = 1200) -> Dict:
    """Execute a single nmap command with output capture."""
    out_file = output_dir / log_name
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        # Append stdout to the output file
        if out_file.exists():
            existing = out_file.read_text()
            out_file.write_text(existing + "\n" + r.stdout)
        else:
            out_file.write_text(r.stdout)
        return {
            "rc": r.returncode,
            "output_file": str(out_file),
            "stdout": r.stdout[-2000:] if len(r.stdout) > 2000 else r.stdout,
            "stderr": r.stderr[-500:] if r.stderr else "",
        }
    except subprocess.TimeoutExpired:
        return {"error": f"Timed out after {timeout}s"}
    except Exception as e:
        return {"error": str(e)}


_WAIT_DELAY = 1


def _wait_for_nmap():
    """Busy-wait until no nmap process is running (poll every 30s)."""
    while True:
        r = subprocess.run(
            ["pgrep", "-x", "nmap"],
            capture_output=True,
            text=True,
        )
        if r.returncode != 0:
            break
        time.sleep(30)


def _dry_parse_ports(text: str, protocol: str = "tcp") -> List[int]:
    """Parse open port numbers from nmap output text."""
    ports = []
    for m in re.finditer(rf"^(\d+)/{protocol}\s+open", text, re.MULTILINE):
        ports.append(int(m.group(1)))
    return sorted(ports)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_initial_tcp(target: str, output_dir: Optional[Path] = None,
                     top_ports: int = 1000) -> Dict:
    """Initial TCP scan — top ports, SYN scan, no DNS."""
    nmap = _nmap_path()
    out_dir = Path(output_dir or Path.cwd() / "nmap_scans")
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [nmap, "-sS", "-Pn", "-n", "--open",
           f"--top-ports={top_ports}", "-oN", str(out_dir / "init-tcp.nmap"),
           target]
    return _run_nmap(cmd, out_dir, "init-tcp.log")


def scan_initial_udp(target: str, output_dir: Optional[Path] = None,
                     top_ports: int = 1000) -> Dict:
    """Initial UDP scan — top ports, fast timing."""
    nmap = _nmap_path()
    out_dir = Path(output_dir or Path.cwd() / "nmap_scans")
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [nmap, "-sU", "-Pn", "-n", "--open",
           f"--top-ports={top_ports}", "-T5",
           "-oN", str(out_dir / "init-udp.nmap"), target]
    return _run_nmap(cmd, out_dir, "init-udp.log")


def scan_service_version(target: str, output_dir: Optional[Path] = None,
                         ports: str = "") -> Dict:
    """Service/version scan on open ports (sVC). Combines TCP+UDP."""
    nmap = _nmap_path()
    out_dir = Path(output_dir or Path.cwd() / "nmap_scans")
    out_dir.mkdir(parents=True, exist_ok=True)
    if not ports:
        port_arg = _parse_open_ports_from_outputs(out_dir)
        if not port_arg:
            return {"error": "No open ports found. Run initial scans first."}
    else:
        port_arg = f"-p{ports}"
    cmd = [nmap, "-sVC", "-sU", "-sS", "-Pn", "-n"]
    cmd.extend(port_arg.split())
    cmd.extend(["-oN", str(out_dir / "script.nmap"), target])
    return _run_nmap(cmd, out_dir, "script.log")


def scan_full_tcp(target: str, output_dir: Optional[Path] = None) -> Dict:
    """Full TCP port scan (1-65535)."""
    nmap = _nmap_path()
    out_dir = Path(output_dir or Path.cwd() / "nmap_scans")
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [nmap, "-sS", "-T5", "-Pn", "-n", "--open", "-p1-",
           "-oN", str(out_dir / "full-tcp.nmap"), target]
    return _run_nmap(cmd, out_dir, "full-tcp.log", timeout=3600)


def scan_ack_tcp(target: str, output_dir: Optional[Path] = None) -> Dict:
    """TCP ACK scan for firewall rule mapping (all ports)."""
    nmap = _nmap_path()
    out_dir = Path(output_dir or Path.cwd() / "nmap_scans")
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [nmap, "-sA", "-T5", "-Pn", "-n", "--open", "-p1-",
           "-oN", str(out_dir / "full-ack.nmap"), target]
    return _run_nmap(cmd, out_dir, "full-ack.log", timeout=3600)


def scan_versions_intense(target: str, output_dir: Optional[Path] = None,
                          ports: str = "") -> Dict:
    """Intense version detection (--version-intensity 9) on open ports."""
    nmap = _nmap_path()
    out_dir = Path(output_dir or Path.cwd() / "nmap_scans")
    out_dir.mkdir(parents=True, exist_ok=True)
    if not ports:
        port_arg = _parse_open_ports_from_outputs(out_dir)
        if not port_arg:
            return {"error": "No open ports found."}
    else:
        port_arg = f"-p{ports}"
    cmd = [nmap, "-sSV", "--version-intensity", "9", "-Pn"]
    cmd.extend(port_arg.split())
    cmd.extend(["-oN", str(out_dir / "versions-tcp.nmap"), target])
    return _run_nmap(cmd, out_dir, "versions-tcp.log", timeout=1800)


def scan_versions_udp_intense(target: str, output_dir: Optional[Path] = None,
                              ports: str = "") -> Dict:
    """Intense UDP version detection (--version-intensity 9)."""
    nmap = _nmap_path()
    out_dir = Path(output_dir or Path.cwd() / "nmap_scans")
    out_dir.mkdir(parents=True, exist_ok=True)
    if not ports:
        port_arg = _parse_open_ports_from_outputs(out_dir)
        if not port_arg:
            return {"error": "No open ports found."}
    else:
        port_arg = f"-p{ports}"
    cmd = [nmap, "-sUV", "-T5", "--version-intensity", "9", "-Pn"]
    cmd.extend(port_arg.split())
    cmd.extend(["-oN", str(out_dir / "versions-udp.nmap"), target])
    return _run_nmap(cmd, out_dir, "versions-udp.log", timeout=1800)


def scan_vuln(target: str, output_dir: Optional[Path] = None,
              ports: str = "") -> Dict:
    """Vulnerability scan with vuln, smb, http, ssh, intrusive scripts."""
    nmap = _nmap_path()
    out_dir = Path(output_dir or Path.cwd() / "nmap_scans")
    out_dir.mkdir(parents=True, exist_ok=True)
    if not ports:
        port_arg = _parse_open_ports_from_outputs(out_dir)
        if not port_arg:
            return {"error": "No open ports found."}
    else:
        port_arg = f"-p{ports}"
    cmd = [nmap, "-T5", "-sU", "-sS", "-Pn"]
    cmd.extend(port_arg.split())
    cmd.extend(["--script", "vuln*,smb*,http*,ssh*,intrusive",
                "-oN", str(out_dir / "script-vuln.nmap"), target])
    return _run_nmap(cmd, out_dir, "script-vuln.log", timeout=3600)


def scan_custom(target: str, args: str, output_dir: Optional[Path] = None,
                log_name: str = "custom") -> Dict:
    """Run nmap with arbitrary arguments string."""
    nmap = _nmap_path()
    out_dir = Path(output_dir or Path.cwd() / "nmap_scans")
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [nmap] + args.split() + ["-oN", str(out_dir / f"{log_name}.nmap"), target]
    return _run_nmap(cmd, out_dir, f"{log_name}.log")


def scan_pipeline(target: str, output_dir: Optional[Path] = None,
                  skip_full: bool = False) -> Dict:
    """Run the full nmaptest.sh pipeline in sequence.

    Order: initial TCP → initial UDP → service/version → full TCP (bg)
    → ACK (bg) → intense versions → UDP intense → vulnerability scripts.
    """
    out_dir = Path(output_dir or Path.cwd() / "nmap_scans" / target)
    out_dir.mkdir(parents=True, exist_ok=True)
    phases = {}

    def _phase(name: str, fn, **kw):
        print(f"[nmap] Phase: {name}")
        r = fn(target=target, output_dir=out_dir, **kw)
        phases[name] = r
        if r.get("error"):
            print(f"  ERROR: {r['error']}")
        else:
            print(f"  Exit: {r.get('rc', '?')}")
        return r

    _phase("init-tcp", scan_initial_tcp)
    _phase("init-udp", scan_initial_udp)

    # Service/version on discovered ports
    r = phases.get("init-tcp", {})
    if r.get("rc") == 0:
        _phase("service-version", scan_service_version)

    # Full TCP and ACK in background
    print("[nmap] Spawning full TCP scan (background)...")
    full_cmd = [_nmap_path(), "-sS", "-T5", "-Pn", "-n", "--open", "-p1-",
                "-oN", str(out_dir / "full-tcp.nmap"), target]
    full_proc = subprocess.Popen(full_cmd, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)

    ack_cmd = [_nmap_path(), "-sA", "-T5", "-Pn", "-n", "--open", "-p1-",
               "-oN", str(out_dir / "full-ack.nmap"), target]
    ack_proc = subprocess.Popen(ack_cmd, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)

    print("[nmap] Waiting for full and ACK scans...")
    full_proc.wait()
    ack_proc.wait()
    phases["full-tcp"] = {"rc": full_proc.returncode, "note": "background"}
    phases["full-ack"] = {"rc": ack_proc.returncode, "note": "background"}

    _phase("versions-tcp", scan_versions_intense)
    _phase("versions-udp", scan_versions_udp_intense)
    _phase("vuln-scan", scan_vuln)

    return {
        "target": target,
        "output_dir": str(out_dir),
        "phases": phases,
        "summary": {k: "OK" if v.get("rc") == 0 else v.get("error", "FAIL")
                     for k, v in phases.items()},
    }


def parse_results(target: str, output_dir: Optional[Path] = None) -> Dict:
    """Parse all nmap output files into a structured summary dict."""
    out_dir = Path(output_dir or Path.cwd() / "nmap_scans" / target)
    if not out_dir.exists():
        out_dir = Path(output_dir or Path.cwd() / "nmap_scans")

    results = {
        "target": target,
        "open_ports_tcp": [],
        "open_ports_udp": [],
        "services": [],
        "os_detection": [],
        "vuln_findings": [],
    }

    for f in sorted(out_dir.glob("*.nmap")):
        text = f.read_text(errors="ignore")
        for m in re.finditer(r"^(\d+)/(tcp|udp)\s+open\s+(\S*)\s*(.*)$",
                              text, re.MULTILINE):
            port = int(m.group(1))
            proto = m.group(2)
            svc = m.group(3)
            extra = m.group(4).strip()
            results["open_ports_tcp" if proto == "tcp" else "open_ports_udp"].append(port)
            if svc:
                results["services"].append({
                    "port": port, "protocol": proto,
                    "service": svc, "extra": extra,
                })

        for m in re.finditer(r"OS details:\s*(.*)", text):
            results["os_detection"].append(m.group(1).strip())

        for m in re.finditer(r"\|([\w-]+):[\s\S]*?(?=^[^\s])", text, re.MULTILINE):
            script_name = m.group(1).strip()
            if script_name in ("osclass", "fingerprint"):
                continue
            if script_name and ("vuln" in script_name.lower()
                                or "VULNERABLE" in m.group(0)):
                results["vuln_findings"].append({
                    "script": script_name,
                    "output": m.group(0)[:500],
                })

    for k in ("open_ports_tcp", "open_ports_udp"):
        results[k] = sorted(set(results[k]))

    return results
