#!/usr/bin/env python3
"""
CC Toolkit — Command Center CLI

Objective-driven namespace organization. Use --help on each for details.

QUICK COMMANDS (top-level):
  start|stop|monitor|dashboard   Service & system management
  config|doctor                  Configuration & health checks
  run                            Run any tool from PATH
  dns|route-scan                 Network analysis / IR tools
  wsgidav|swaks                  Utility servers (WebDAV, SMTP)
  watch|papermill                Automation (playbook scheduler, notebooks)
  wordlists                      Browse & search wordlists

CATEGORY NAMESPACES:
  recon                          Reconnaissance & discovery (scan, nuclei)
  web                            Web application testing (nuclei, graphw00f, jwt-tool)
  ad                             Active Directory security (bloodyd, certipy, kerbrute, ldapnomnom, netexec-pre2k)
  exploit                        Exploitation & payloads (trufflehog, mitm, hexstrike, searchsploit)
  wifi                           WiFi operations (scan, crack, handshake, eaphammer, wirelessgraph)
  forensics                      Digital forensics & IR (yara, sigma, kape, semgrep)
  case                           Case management (create, evidence, scope, tasks)
  playbook                       YAML runbook engine (list, show, run)
  report                         Reporting & output (nmap, nuclei, engagement, timeline, obsidian)
  findings                       Structured findings per case
  tools                          Tool discovery & launcher
  infra                          Infrastructure (vm, arsenal, profile, notify, remote)
  binary                         Binary exploitation analysis (check, analyze, vulns, gadgets, exploit, ...)
  ref                            Reference data (LDAP filters, event IDs, CVEs)
  bb                             Bug bounty dashboard (HackerOne / Bugcrowd)
  history                        Command audit log

MCP SERVER:
  cc_mcp_server.py — exposes cc toolkit tools as MCP-callable functions
  Register in opencode.json alongside hexstrike:
    "cc-toolkit": { "type": "local", "command": ["python3", "/path/to/cc_mcp_server.py"], "enabled": true }

EXAMPLES:
  cc recon scan --target 10.10.10.1
  cc ad certipy find --domain corp.local --target dc01
  cc web graphw00f --target http://target/graphql
  cc wifi eaphammer --bssid AA:BB:CC:DD:EE:FF --essid CorpWiFi --iface wlan0
  cc forensics yara --rules /path/to/rules --target /mnt/evidence
  cc report engagement --case-id case_20240101
  cc papermill run new-scans --param target=10.10.10.1
  cc infra vm list
  cc ref ldap-filters as-rep
  cc infra hexstrike start && cc infra hexstrike opencode
"""

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import time
import zlib
from pathlib import Path
from shutil import which

try:
    import yaml
except ImportError:
    yaml = None

# ---------------------------------------------------------------------------
# Import all modules
# ---------------------------------------------------------------------------
from modules.config import (
    CONFIG_DIR, load_config, save_config,
    CASES_DIR, OBSIDIAN_DIR,
    SCRIPTS_DIR, TOOLS_DIR, ARSENAL_DIR, ARSENAL_RULES_FILE,
    ENV_PROFILES_FILE,
    CAIDO_HOST, CAIDO_PORT, WORDLISTS_DIR,
)


def ensure_dirs():
    for d in [CASES_DIR, CONFIG_DIR, TOOLS_DIR]:
        d.mkdir(parents=True, exist_ok=True)
from modules.case_manager import CaseManager
from modules.playbook_engine import PlaybookEngine
from modules.obsidian_bridge import ObsidianBridge
from modules.doctor import Doctor
from modules.report_generator import (
    generate_nmap_report, generate_nuclei_report,
    generate_engagement_report, generate_timeline_html,
)
from modules.tool_wrappers import (
    trufflehog_org, trufflehog_local,
    mitm_start, route_scan,
    yara_scan, semgrep_scan, sigma_convert,
    nuclei_scan, wireless_graph,
    bloodyad_exec, bloodyad_dump,
    certipy_find, certipy_request,
    ldapnomnom_enum,
    kerbrute_userenum, kerbrute_bruteforce,
    eaphammer_attack,
    jwt_tool_scan, jwt_tool_attack,
    graphw00f_scan,
    wsgidav_serve,
    kape_collect,
    swaks_send,
    netexec_pre2k,
)
import secrets
import shlex
from modules.findings_db import FindingsDB
from modules.checklist_manager import ChecklistInstance, list_templates as list_checklist_templates
from modules.compliance_export import export_case as export_case_results
from modules.notifier import Notifier
from modules.remote_runner import RemoteRunner
from modules.history_logger import HistoryLogger
from modules.references import (
    search_ldap, search_event_ids, search_cves,
)


# ---------------------------------------------------------------------------
# Config helpers (re-exported)
# ---------------------------------------------------------------------------
def _load_config(): return load_config()
def _save_config(cfg): return save_config(cfg)


# ---------------------------------------------------------------------------
# Service / Start / Stop (preserved from original)
# ---------------------------------------------------------------------------
def _tmux_running(s: str) -> bool:
    r = subprocess.run(["tmux", "has-session", "-t", s],
                       capture_output=True, text=True)
    return r.returncode == 0


def _run_bg(cmd, session):
    if _tmux_running(session):
        return True
    shell = " ".join(cmd)
    r = subprocess.run(
        ["tmux", "new-session", "-d", "-s", session,
         "bash", "-c", f"{shell} > /dev/null 2>&1"],
        capture_output=True, text=True
    )
    return r.returncode == 0


def cmd_start(args):
    cfg = _load_config()
    started = []
    if not _tmux_running("jupyter"):
        # Write a Jupyter config that allows iframe embedding
        jupyter_config = (
            'c.ServerApp.allow_origin = "*"\n'
            'c.ServerApp.disable_check_xsrf = True\n'
            'c.ServerApp.token = ""\n'
            'c.ServerApp.password = ""\n'
            'c.ServerApp.tornado_settings = {\n'
            '    "headers": {\n'
            '        "X-Frame-Options": "ALLOWALL",\n'
            '        "Content-Security-Policy": "frame-ancestors * \'self\'",\n'
            '    }\n'
            '}\n'
            '# Also set NotebookApp for older versions\n'
            'c.NotebookApp.allow_origin = "*"\n'
            'c.NotebookApp.disable_check_xsrf = True\n'
            'c.NotebookApp.token = ""\n'
            'c.NotebookApp.password = ""\n'
            'c.NotebookApp.tornado_settings = {\n'
            '    "headers": {\n'
            '        "X-Frame-Options": "ALLOWALL",\n'
            '        "Content-Security-Policy": "frame-ancestors * \'self\'",\n'
            '    }\n'
            '}\n'
        )
        config_dir = Path("/root/.jupyter")
        config_dir.mkdir(parents=True, exist_ok=True)
        config_path = config_dir / "jupyter_server_config.py"
        config_path.write_text(jupyter_config)
        cfg_path = config_dir / "jupyter_notebook_config.py"
        cfg_path.write_text(jupyter_config)

        cmd = [
            "sudo", "python3", "-m", "jupyterlab",
            "--port", str(cfg["jupyter_port"]),
            "--ip", "0.0.0.0",
            "--allow-root", "--no-browser",
            "--notebook-dir", str(cfg.get("jupyter_dir", "/")),
        ]
        if _run_bg(cmd, "jupyter"):
            started.append(f"JupyterLab on port {cfg['jupyter_port']}")
    cu = cfg.get("caido_url", f"http://{CAIDO_HOST}:{CAIDO_PORT}")
    started.append(f"Caido (remote) \u2192 {cu}")
    for s in started:
        print(f"  \u2713 {s}")


def cmd_stop(args):
    for sess in ["jupyter", _ai_tunnel_session()]:
        if _tmux_running(sess):
            subprocess.run(["tmux", "kill-session", "-t", sess],
                           capture_output=True)
            print(f"Stopped {sess}")
    # Also kill any lingering jupyter processes
    try:
        subprocess.run(["sudo", "pkill", "-f", "jupyter-lab"], capture_output=True)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Dashboard / Monitor (preserved from original)
# ---------------------------------------------------------------------------
def _cpu():
    try:
        with open("/proc/stat") as f:
            v = [int(x) for x in f.readline().strip().split()[1:]]
        return f"{(1 - v[3] / sum(v)) * 100:.1f}%"
    except Exception:
        return "N/A"


def _mem():
    try:
        with open("/proc/meminfo") as f:
            d = {}
            for line in f:
                p = line.split()
                if p[0] in ("MemTotal:", "MemAvailable:"):
                    d[p[0].rstrip(":")] = int(p[1]) / 1024 / 1024
        u = d.get("MemTotal", 0) - d.get("MemAvailable", 0)
        t = d.get("MemTotal", 0)
        return f"{u:.1f}G / {t:.1f}G ({u / t * 100:.1f}%)" if t else "N/A"
    except Exception:
        return "N/A"


def _disk(p="/"):
    try:
        u = __import__("shutil").disk_usage(p)
        return f"{u.used / 1e9:.1f}G / {u.total / 1e9:.1f}G ({u.used / u.total * 100:.1f}%)"
    except Exception:
        return "N/A"


def _net():
    lines = []
    try:
        for line in open("/proc/net/tcp").readlines()[1:]:
            parts = line.strip().split()
            if len(parts) >= 4 and int(parts[3], 16) == 1:
                lines.append(f"  ESTABLISHED {_h(parts[1])} <-> {_h(parts[2])}")
    except Exception:
        pass
    return lines


def _h(hs):
    try:
        a, b = hs.split(":")
        ip = ".".join(str(i) for i in reversed(bytes.fromhex(a)))
        return f"{ip}:{int(b, 16)}"
    except Exception:
        return hs


def _wifi_iface():
    try:
        r = subprocess.run(["iwconfig"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            m = re.match(r"^(\S+)\s+IEEE\s+802\.11", line)
            if m and m.group(1) != "lo":
                return m.group(1)
    except Exception:
        pass
    return None


def _wifi_mon(iface):
    try:
        return "Mode:Monitor" in subprocess.run(
            ["iwconfig", iface], capture_output=True, text=True, timeout=5
        ).stdout
    except Exception:
        return False


def cmd_monitor(args):
    print(f"{'CPU':<12} {_cpu()}")
    print(f"{'Memory':<12} {_mem()}")
    print(f"{'Disk /':<12} {_disk('/')}")
    iface = _wifi_iface()
    if iface:
        print(f"{'WiFi':<12} {iface}  monitor={'ON' if _wifi_mon(iface) else 'OFF'}")
    conns = _net()
    if conns:
        print("\nActive connections:")
        for c in conns:
            print(c)


def _web_dashboard_path():
    return Path(__file__).resolve().parent / "web_dashboard" / "app.py"

def cmd_dashboard_web(args):
    """Start the Flask web dashboard."""
    app_script = _web_dashboard_path()
    if not app_script.exists():
        print(f"Error: web dashboard not found at {app_script}")
        sys.exit(1)
    host = getattr(args, "host", "0.0.0.0")
    port = getattr(args, "port", 5000)
    debug = getattr(args, "debug", False)
    env = os.environ.copy()
    env["FLASK_APP"] = str(app_script)
    # Forward the CLI --host/--port/--debug to the dashboard app so they are
    # actually honored (web_dashboard/app.py reads these env overrides).
    env["CC_LISTEN_HOST"] = host
    env["CC_LISTEN_PORT"] = str(port)
    env["CC_DEBUG"] = "1" if debug else "0"
    cmd = [sys.executable, str(app_script)]
    print(f"Starting CC Web Dashboard on http://{host}:{port}")
    print(f"Debug: {'on' if debug else 'off'}")
    print("Press Ctrl+C to stop")
    try:
        subprocess.run(cmd, env=env, cwd=str(app_script.parent))
    except KeyboardInterrupt:
        print("\nDashboard stopped.")

def cmd_dashboard_tui(args):
    try:
        from modules.tui_app import main as tui_main
        tui_main()
    except ImportError as e:
        print(f"Error loading TUI: {e}")
        print("Try: pip install prompt_toolkit")
        sys.stdout.flush()


# ---------------------------------------------------------------------------
# Tools (preserved from original)
# ---------------------------------------------------------------------------
SYSTEM_TOOL_CATEGORIES = {
    "recon": {"bins": ["nmap","masscan","dnsrecon","dnsenum","amass","subfinder","assetfinder","httpx","gau","waybackurls","gospider","katana","whatweb","theharvester","sublist3r"], "desc": "Reconnaissance & OSINT"},
    "web": {"bins": ["ffuf","dirb","gobuster","wfuzz","feroxbuster","nuclei","burpsuite","sqlmap","xsstrike","commix","dalfox"], "desc": "Web application testing"},
    "exploitation": {"bins": ["msfconsole","msfvenom","searchsploit","impacket","crackmapexec","bettercap","responder","evil-winrm","beef"], "desc": "Exploitation"},
    "password": {"bins": ["hashcat","john","hydra","medusa","cewl","crunch","fcrackzip","pdfcrack"], "desc": "Password cracking"},
    "forensics": {"bins": ["volatility","autopsy","sleuthkit","binwalk","foremost","bulk_extractor","scalpel","photorec","testdisk","guymager"], "desc": "Digital forensics"},
    "memory": {"bins": ["volatility","avml","lime-forensics","rekall"], "desc": "Memory analysis"},
    "reverse": {"bins": ["ghidra","radare2","rizin","gdb","objdump","strings","ltrace","strace","binwalk"], "desc": "Reverse engineering"},
    "wifi": {"bins": ["airodump-ng","aireplay-ng","aircrack-ng","airmon-ng","reaver","wash","bully","kismet","wifite","bettercap","hcxdumptool","mdk4","wavemon"], "desc": "Wi-Fi auditing"},
    "sdr": {"bins": ["gnuradio-companion","gqrx","rtl_fm","rtl_sdr","hackrf","urh"], "desc": "Software-defined radio"},
    "osint": {"bins": ["theharvester","maltego","recon-ng","sherlock","holehe"], "desc": "OSINT"},
    "stego": {"bins": ["steghide","outguess","stegsolve","zsteg","jsteg"], "desc": "Steganography"},
    "crypto": {"bins": ["openssl","gpg","hashid","yara"], "desc": "Cryptography & hashing"},
    "cloud": {"bins": ["s3scanner","cloud_enum","pacu","scoutsuite","awscli"], "desc": "Cloud testing"},
    "malware": {"bins": ["capa","cuckoo"], "desc": "Malware analysis"},
    "mobile": {"bins": ["apktool","dex2jar","jadx","frida","adb","objection"], "desc": "Mobile security"},
    "database": {"bins": ["sqlmap","sqlninja","jsql"], "desc": "Database testing"},
}


_TOOL_CACHE = {"ts": 0, "system": {}, "custom": {}}


def _index_system_tools(force=False):
    now = time.time()
    if not force and (now - _TOOL_CACHE["ts"]) < 30:
        return _TOOL_CACHE["system"]
    idx = {}
    for cat, data in SYSTEM_TOOL_CATEGORIES.items():
        found = [b for b in data["bins"] if which(b)]
        if found:
            idx[cat] = found
    try:
        r = subprocess.run(["dpkg","--get-selections"], capture_output=True, text=True, timeout=10)
        pkgs = [l.split()[0] for l in r.stdout.strip().splitlines() if l.strip() and "deinstall" not in l]
        idx["_dpkg"] = len(pkgs)
        idx["_kali"] = len([p for p in pkgs if p.startswith("kali-")])
    except Exception:
        idx["_dpkg"] = idx.get("_dpkg", 0)
    _TOOL_CACHE["system"] = idx
    _TOOL_CACHE["ts"] = now
    return idx


def _index_custom_tools(force=False):
    now = time.time()
    if not force and (now - _TOOL_CACHE["ts"]) < 30 and _TOOL_CACHE["custom"]:
        return _TOOL_CACHE["custom"]
    cfg = _load_config()
    td = Path(cfg.get("tools_dir", str(TOOLS_DIR)))
    if not td.exists():
        return {}
    tools = {}
    for f in sorted(td.rglob("*")):
        if f.is_file() and f.suffix in (".sh", ".py", "") and not f.name.startswith("."):
            tools[f.name] = str(f)
    _TOOL_CACHE["custom"] = tools
    _TOOL_CACHE["ts"] = now
    return tools


def cmd_tools(args):
    a = getattr(args, "tools_action", "list") or "list"
    if a == "list-system":
        idx = _index_system_tools()
        for cat in sorted(SYSTEM_TOOL_CATEGORIES):
            tools = idx.get(cat, [])
            desc = SYSTEM_TOOL_CATEGORIES[cat]["desc"]
            print(f"  {cat:<18} ({len(tools):3d})  {desc}")
            for t in tools[:6]:
                print(f"    {'':18} {t:<25} {which(t) or ''}")
            if len(tools) > 6:
                print(f"    {'':18} ... +{len(tools)-6} more")
            print()
        print(f"  Total dpkg packages: {idx.get('_dpkg', 0)}  (kali-*: {idx.get('_kali', 0)})")
    elif a == "list-custom":
        tools = _index_custom_tools()
        for n, p in tools.items():
            sz = Path(p).stat().st_size // 1024
            print(f"  {n:<40} {p:<55} {sz}K")
    elif a == "list":
        idx, cus = _index_system_tools(), _index_custom_tools()
        sys_c = sum(len(v) for k, v in idx.items() if not k.startswith("_"))
        print(f"System tools (in PATH):    {sys_c}")
        print(f"Custom tools (/share/tools): {len(cus)}")
    elif a == "search":
        kw = getattr(args, "keyword", "") or ""
        results = []
        for cat, tools in _index_system_tools().items():
            if cat.startswith("_"):
                continue
            for t in tools:
                if kw.lower() in t.lower():
                    results.append(("system", t, which(t) or "", SYSTEM_TOOL_CATEGORIES.get(cat, {}).get("desc", "")))
        for n, p in _index_custom_tools().items():
            if kw.lower() in n.lower():
                results.append(("custom", n, p, "/share/tools"))
        if not results:
            print(f"No matches for '{kw}'")
            return
        print(f"Matches ({len(results)}):")
        for src, n, p, c in results:
            print(f"  [{src:<8}] {n:<35} {p:<50} {c}")
    elif a == "info":
        tn = getattr(args, "tool_name", "") or ""
        sp = which(tn)
        if sp:
            sz = Path(sp).stat().st_size
            print(f"Path: {sp}\nSize: {sz//1024}K\nType: system")
        else:
            for n, p in _index_custom_tools().items():
                if tn in n:
                    print(f"Path: {p}\nSize: {Path(p).stat().st_size//1024}K\nType: custom")
                    return
            print(f"'{tn}' not found")
    elif a in ("run",):
        tn = getattr(args, "tool_name", "") or ""
        tp = which(tn)
        if not tp:
            for n, p in _index_custom_tools().items():
                if tn in n:
                    tp = p
                    break
        if not tp:
            print(f"'{tn}' not found")
            return
        cmd = [tp] + (getattr(args, "tool_args", None) or [])
        subprocess.run(cmd)
    elif a == "list-forensic":
        for cat in ("forensics","memory","stego","malware","crypto"):
            tools = _index_system_tools().get(cat, [])
            if tools:
                print(f"[{cat}] {SYSTEM_TOOL_CATEGORIES.get(cat,{}).get('desc',cat)}:")
                for t in tools:
                    print(f"  - {t}")
    elif a == "list-pentest":
        for cat in ("recon","web","exploitation","password","wifi","osint","cloud","database","mobile"):
            tools = _index_system_tools().get(cat, [])
            if tools:
                print(f"[{cat}] {SYSTEM_TOOL_CATEGORIES.get(cat,{}).get('desc',cat)}:")
                for t in tools:
                    print(f"  - {t}")
    elif a == "list-wifi":
        for t in _index_system_tools().get("wifi", []):
            print(f"  {t:<30} {which(t) or 'not in PATH'}")


# ---------------------------------------------------------------------------
# WiFi (preserved from original, simplified)
# ---------------------------------------------------------------------------
def cmd_wifi(args):
    a = getattr(args, "wifi_action", "status") or "status"
    iface = getattr(args, "iface", None) or _wifi_iface()

    if a == "status":
        if not iface:
            print("No wireless interface detected")
            return
        print(f"Interface:    {iface}")
        print(f"Monitor mode: {'ON' if _wifi_mon(iface) else 'OFF'}")
        try:
            r = subprocess.run(["iwconfig", iface], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                s = line.strip()
                if any(k in s for k in ("ESSID:","Mode:","Frequency:","Access Point:","Bit Rate:")):
                    print(f"  {s}")
        except Exception:
            pass
    elif a == "monitor":
        st = getattr(args, "state", None)
        if not iface:
            print("No wireless interface detected")
            return
        if st == "on":
            if _wifi_mon(iface):
                print(f"{iface} already in monitor mode")
                return
            r = subprocess.run(["sudo","airmon-ng","start",iface],
                               capture_output=True, text=True)
            # Detect actual monitor interface name from airmon-ng output
            mon = f"{iface}mon"
            for line in r.stdout.splitlines():
                m = re.search(r"\((\S+mon)\)", line)
                if m:
                    mon = m.group(1)
                    break
            if Path(f"/sys/class/net/{mon}").exists():
                print(f"Monitor mode on {mon}")
            else:
                print(f"Monitor mode enabled ({r.stdout.strip()[:100]})")
        else:
            subprocess.run(["sudo","airmon-ng","stop",iface],
                           capture_output=True)
            print("Monitor mode disabled")
    elif a == "scan":
        if not iface:
            print("No wireless interface")
            return
        out = args.output or f"scan-{datetime.datetime.now():%Y%m%d-%H%M%S}"
        dur = args.duration or 15
        print(f"Scanning {iface} for {dur}s...")
        cmd = ["sudo","airodump-ng","--write",out,"--output-format","csv",
               "--band",getattr(args,"band","abg"),iface]
        p = subprocess.Popen(cmd)
        try:
            p.wait(timeout=dur)
        except subprocess.TimeoutExpired:
            p.terminate()
            p.wait()
        csv = Path(f"{out}-01.csv")
        if csv.exists():
            print(f"\nNetworks:\n{'BSSID':20} {'CH':4} {'Enc':12} {'ESSID'}")
            for line in csv.read_text().splitlines():
                parts = line.strip().split(",")
                if len(parts) >= 14 and len(parts[0]) == 17:
                    print(f"{parts[0]:20} {parts[3]:4} {parts[5] or parts[6] or 'OPN':12} {parts[13].strip('\" ')}")
    elif a == "handshake":
        if not iface:
            print("No wireless interface")
            return
        bssid, ch = args.bssid, args.channel or "1"
        out = args.output or f"hs_{bssid.replace(':','')}"
        subprocess.run(["sudo","iwconfig",iface,"channel",ch], capture_output=True)
        cmd = ["sudo","airodump-ng","--bssid",bssid,"--channel",ch,"--write",out,iface]
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nStopped")
        cap = Path(f"{out}-01.cap")
        if cap.exists():
            print(f"Capture: {cap}")
    elif a == "deauth":
        if not iface:
            return
        cmd = ["sudo","aireplay-ng","--deauth",str(args.count or 1),
               "-a",args.bssid,"-c",args.client or "FF:FF:FF:FF:FF:FF",iface]
        subprocess.run(cmd)
    elif a == "crack":
        if not args.cap_file:
            print("Specify --cap-file")
            return
        wl = args.wordlist or "/usr/share/wordlists/rockyou.txt"
        cmd = ["sudo","aircrack-ng","-w",wl,args.cap_file]
        if args.bssid:
            cmd.extend(["-b",args.bssid])
        subprocess.run(cmd)
    elif a == "heatmap":
        sp = SCRIPTS_DIR / "automation-tools" / "beacon-heatmap.py"
        if not sp.exists():
            print("beacon-heatmap.py not found")
            return
        if args.pcap:
            cmd = [sys.executable,str(sp),"--pcap",args.pcap]
            if args.mac:
                cmd.extend(["--mac",args.mac])
            subprocess.run(cmd)
        elif args.iface or iface:
            cmd = [sys.executable,str(sp),"--iface",args.iface or iface]
            if args.max_hosts:
                cmd.extend(["-m",str(args.max_hosts)])
            subprocess.run(cmd)
    elif a == "list":
        for c,d in [("status","Interface status"),("monitor on/off","Toggle monitor mode"),
                     ("scan","Scan APs (airodump)"),("handshake","Capture WPA handshake"),
                     ("deauth","Send deauth"),("crack","Crack handshake"),
                     ("heatmap","WiFi heatmap"),
                     ("scan2","BetterCAP scan"),("handshake-capture","BetterCAP handshake"),
                     ("connect","Connect to WiFi"),("netscan","ARP scan after connect"),
                     ("arp-spoof","BetterCAP ARP spoof"),("proxy","BetterCAP transparent proxy"),
                     ("rogue-ap","Rogue AP (airbase-ng/hostapd)"),
                     ("sycophant","WPA relay (wpa_sycophant)"),
                     ("mitmproxy","Traffic interception"),("evil-twin","Full evil twin + portal + proxy"),
                     ("auto-attack","Auto: handshake→deauth→evil-twin→relay")]:
            print(f"  {c:<25} {d}")
    elif a == "scan2":
        from modules.wifi_wrapper import wifi_scan
        dur = getattr(args, "timeout", 45) or 45
        result = wifi_scan(iface=args.iface or iface or "wlan0", timeout=dur)
        if result.get("error"):
            print(f"Error: {result['error']}")
            return
        aps = result.get("aps", [])
        print(f"Found {len(aps)} AP(s) (source: {result.get('source', '?')}):")
        print(f"{'BSSID':20} {'CH':4} {'Signal':7} {'Encryption':12} {'ESSID'}")
        for ap in sorted(aps, key=lambda x: int(x.get("channel", 0))):
            b = ap.get("bssid","?")
            ch = ap.get("channel","?")
            sig = ap.get("signal","?")
            enc = ap.get("encryption","?")
            essid = ap.get("essid","?")
            print(f"{b:20} {ch:4} {sig:7} {enc:12} {essid}")
    elif a == "handshake-capture":
        from modules.wifi_wrapper import wifi_handshake_capture
        bssid = getattr(args, "bssid", "") or ""
        ch = getattr(args, "channel", "1") or "1"
        essid = getattr(args, "essid", "") or ""
        to = getattr(args, "timeout", 60) or 60
        result = wifi_handshake_capture(bssid, ch, iface=args.iface or iface or "wlan0",
                                        essid=essid, timeout=to)
        if result.get("error"):
            print(f"Error: {result['error']}")
        elif result.get("capture"):
            print(f"Handshake captured: {result['capture']} ({result.get('size', 0)} bytes)")
        else:
            print(result.get("status", "No handshake captured"))
    elif a == "connect":
        from modules.wifi_wrapper import wifi_connect
        ssid = getattr(args, "ssid", "") or ""
        pw = getattr(args, "password", "") or ""
        result = wifi_connect(ssid, password=pw, iface=args.iface or iface or "wlan0")
        if result.get("error"):
            print(f"Error: {result['error']}")
        else:
            print(result.get("status", f"Connected to {ssid}"))
    elif a == "netscan":
        from modules.wifi_wrapper import wifi_network_scan
        sub = getattr(args, "subnet", "") or ""
        result = wifi_network_scan(iface=args.iface or iface or "wlan0", subnet=sub)
        if result.get("error"):
            print(f"Error: {result['error']}")
            return
        hosts = result.get("hosts", [])
        print(f"Found {len(hosts)} host(s) on {result.get('subnet', '?')}:")
        for h in hosts:
            print(f"  {h.get('ip','?'):16} {h.get('status','?')}")
    elif a == "arp-spoof":
        from modules.wifi_wrapper import wifi_arp_spoof
        target = getattr(args, "target", "") or ""
        gw = getattr(args, "gateway", "") or ""
        result = wifi_arp_spoof(target, gateway=gw, iface=args.iface or iface or "wlan0")
        print(result.get("status", result.get("error", "ARP spoof completed")))
    elif a == "proxy":
        from modules.wifi_wrapper import wifi_proxy
        port = getattr(args, "port", 8080) or 8080
        sslstrip = getattr(args, "sslstrip", True)
        result = wifi_proxy(port=port, iface=args.iface or iface or "wlan0", sslstrip=sslstrip)
        print(result.get("status", result.get("error", "Proxy completed")))
    elif a == "rogue-ap":
        from modules.wifi_wrapper import airbase_rogue_ap
        essid = getattr(args, "essid", "") or ""
        ch = getattr(args, "channel", "6") or "6"
        bssid = getattr(args, "bssid", "") or ""
        result = airbase_rogue_ap(essid, iface=args.iface or iface or "wlan0",
                                  channel=ch, bssid=bssid)
        if result.get("error"):
            print(f"Error: {result['error']}")
        else:
            print(result.get("status", f"Rogue AP '{essid}' started"))
    elif a == "sycophant":
        from modules.wifi_wrapper import wpa_sycophant_relay
        tb = getattr(args, "target_bssid", "") or ""
        te = getattr(args, "target_essid", "") or ""
        result = wpa_sycophant_relay(iface=args.iface or iface or "wlan0",
                                     target_bssid=tb, target_essid=te)
        if result.get("error"):
            print(f"Error: {result['error']}")
        else:
            print(result.get("status", "Relay started"))
    elif a == "mitmproxy":
        from modules.wifi_wrapper import mitmproxy_intercept
        port = getattr(args, "port", 8080) or 8080
        addr = getattr(args, "listen_addr", "0.0.0.0") or "0.0.0.0"
        mode = getattr(args, "mode", "transparent") or "transparent"
        result = mitmproxy_intercept(port=port, listen_addr=addr, mode=mode)
        if result.get("error"):
            print(f"Error: {result['error']}")
        else:
            print(result.get("status", f"mitmproxy on :{port}"))
    elif a == "evil-twin":
        from modules.wifi_wrapper import evil_twin_full
        essid = getattr(args, "essid", "") or ""
        ch = getattr(args, "channel", "6") or "6"
        bssid = getattr(args, "bssid", "") or ""
        portal = getattr(args, "portal_dir", "") or ""
        pport = getattr(args, "proxy_port", 8080) or 8080
        result = evil_twin_full(essid, iface=args.iface or iface or "wlan0",
                                channel=ch, bssid=bssid, portal_dir=portal,
                                proxy_port=pport)
        if result.get("error"):
            print(f"Error: {result['error']}")
        else:
            print(result.get("status", f"Evil twin '{essid}' running"))
            print(f"  Portal: :80  Proxy: :{pport}")
    elif a == "auto-attack":
        from modules.wifi_wrapper import wifi_auto_attack
        tb = getattr(args, "target_bssid", "") or ""
        te = getattr(args, "target_essid", "") or ""
        ch = getattr(args, "channel", "") or ""
        result = wifi_auto_attack(iface=args.iface or iface or "wlan0",
                                  target_bssid=tb, target_essid=te, channel=ch)
        attacks = result.get("attacks", {})
        print(f"Auto-attack against {result.get('target', '?')}:")
        for name, res in attacks.items():
            status = res.get("status", res.get("capture", res.get("error", "done")))
            print(f"  {name}: {status[:80]}" if status else f"  {name}: done")


# ---------------------------------------------------------------------------
# VM (preserved from original)
# ---------------------------------------------------------------------------
def cmd_vm_list(args):
    vbox = which("VBoxManage")
    virsh = which("virsh")
    found = False
    if vbox:
        r = subprocess.run([vbox,"list","vms"], capture_output=True, text=True)
        if r.stdout.strip():
            found = True
            print("VirtualBox:")
            for line in r.stdout.strip().splitlines():
                print(f"  {line}")
    if virsh:
        r = subprocess.run([virsh,"list","--all","--name"], capture_output=True, text=True)
        vms = [v.strip() for v in r.stdout.strip().splitlines() if v.strip()]
        if vms:
            found = True
            print("libvirt:")
            for vm in vms:
                sr = subprocess.run([virsh,"domstate",vm], capture_output=True, text=True)
                print(f"  {vm:<30} [{sr.stdout.strip()}]")
    if not found:
        print("No VMs found")


def cmd_vm_create_vbox(args):
    vbox = which("VBoxManage")
    if not vbox:
        print("VBoxManage not found")
        return
    cfg = _load_config()
    name = args.name or "kali"
    base = cfg["vms_dir"]
    vnc_pass = getattr(args, "vnc_password", None) or secrets.token_urlsafe(12)
    cmds = [
        [vbox,"createvm","--name",name,"--ostype","Linux_64","--register","--basefolder",base],
        [vbox,"modifyvm",name,"--ioapic","on"],
        [vbox,"modifyvm",name,"--memory",str(args.memory or 2048),"--vram",str(args.vram or 128)],
        [vbox,"modifyvm",name,"--nic1","nat"],
        [vbox,"createhd","--filename",str(Path(base)/"disks"/f"{name}.vdi"),"--size",str(args.disk or 80000),"--format","VDI"],
        [vbox,"storagectl",name,"--name","SATA Controller","--add","sata","--controller","IntelAhci"],
        [vbox,"storageattach",name,"--storagectl","SATA Controller","--port","0","--device","0","--type","hdd","--medium",str(Path(base)/"disks"/f"{name}.vdi")],
        [vbox,"storagectl",name,"--name","IDE Controller","--add","ide","--controller","PIIX4"],
        [vbox,"storageattach",name,"--storagectl","IDE Controller","--port","1","--device","0","--type","dvddrive","--medium",args.iso or str(Path(cfg["isos_dir"])/"kali-linux-2024.1-installer-netinst-amd64.iso")],
        [vbox,"modifyvm",name,"--boot1","dvd","--boot2","disk","--boot3","none","--boot4","none"],
        [vbox,"modifyvm",name,"--vrde","on"],
        [vbox,"modifyvm",name,"--vrdeauthtype","null","--vrdeproperty",f"VNCPassword={vnc_pass}"],
    ]
    # Deterministic port per VM name: builtin hash() is salted per process
    # (PYTHONHASHSEED), so the same VM would get a different RDP port each run.
    port = args.rdp_port or (9000 + zlib.crc32(name.encode("utf-8")) % 1000)
    cmds.append([vbox,"modifyvm",name,"--vrdemulticon","on","--vrdeport",str(port)])
    for c in cmds:
        print(f"  $ {' '.join(c)}")
        r = subprocess.run(c, capture_output=True, text=True)
        if r.returncode != 0:
            print(f"  Error: {r.stderr}")
            return
    if not getattr(args,"no_start",False):
        hl = which("VBoxHeadless")
        if hl:
            subprocess.Popen([hl,"--startvm",name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"VM '{name}' started (RDP port {port}, VNC password: {vnc_pass})")


def cmd_vm_create_kvm(args):
    cfg = _load_config()
    hostname = args.hostname or "ubuntu"
    domain = args.domain or "private"
    url = args.url or "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
    os_variant = args.os_variant or "ubuntu-stable-latest"
    size = args.size or "40G"
    ram = str(args.ram or 2048)
    import random, string
    uid = args.uid or "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    fqdn = f"{uid}.{hostname}.{domain}.private"
    wd = Path(cfg["disks_dir"]) / uid
    wd.mkdir(parents=True, exist_ok=True)

    def rc(cmd):
        print(f"  $ {cmd}")
        return subprocess.run(shlex.split(cmd), capture_output=True, text=True)

    img = wd / "provisionme.img"
    disk_img = wd / f"{fqdn}.img"
    cid = wd / "cidata.iso"
    meta = wd / "meta-data"
    user = wd / "user-data"
    if not img.exists():
        import urllib.request
        print("Downloading cloud image...")
        urllib.request.urlretrieve(url, str(img))
    rc(f"qemu-img create -b {img} -f qcow2 -F qcow2 {disk_img} {size}")
    meta.write_text(f"instance-id: {uid}\nlocal-hostname: {fqdn}\n")
    key = args.ssh_key or ""
    if not key:
        for kf in [Path.home()/".ssh"/"id_rsa.pub", Path.home()/".ssh"/"id_ecdsa.pub", Path.home()/".ssh"/"id_ed25519.pub"]:
            if kf.exists():
                key = kf.read_text().strip()
                break
    user.write_text(f"""#cloud-config
hostname: {uid}.{hostname}
fqdn: {fqdn}
package_update: true
users:
  - name: ansible
    ssh_authorized_keys:
      - {key}
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: sudo
    shell: /bin/bash
packages:
  - ncat
  - curl
  - git
  - ansible
  - nmap
  - python3-pip
  - podman
run_cmd:
  - [ pip, install, --upgrade, jupyter-lab ]
""")
    gi = which("genisoimage") or which("mkisofs")
    if gi:
        rc(f"{gi} -output {cid} -volid cidata -joliet -rock {meta} {user}")
    vi = which("virt-install")
    if not vi:
        print("virt-install not found")
        return
    rc(f"{vi} --virt-type qemu --name {fqdn} --ram {ram} --disk {disk_img},format=qcow2 "
       f"--network network=default --graphics vnc,listen=10.42.0.1 --noautoconsole "
       f"--os-variant={os_variant} --cdrom={cid} --check all=off")
    print(f"KVM VM '{fqdn}' provisioning started")


# ---------------------------------------------------------------------------
# Arsenal (preserved from original)
# ---------------------------------------------------------------------------
def _find_arsenal():
    ad = Path(_load_config().get("arsenal_dir", str(ARSENAL_DIR)))
    if ad.exists() and ad.is_dir():
        return ad
    # Try pip package data directory via import
    try:
        import arsenal as _arsenal_mod
        p = Path(_arsenal_mod.__file__).parent / "data" / "cheats"
        if p.exists():
            return p
    except ImportError:
        pass
    # Known installed locations
    for candidate in [
        Path("/usr/share/arsenal/data/cheats"),
        Path("/usr/local/share/arsenal/data/cheats"),
        TOOLS_DIR / "arsenal" / "data" / "cheats",
    ]:
        if candidate.exists():
            return candidate
    # Derive from which("arsenal") CLI
    ap = which("arsenal")
    if ap:
        pkg_dir = Path(ap).resolve().parent.parent
        for base in [pkg_dir / "lib", Path("/usr/lib"), Path("/usr/local/lib")]:
            for d in sorted(base.glob("python*")):
                p = d / "site-packages" / "arsenal" / "data" / "cheats"
                if p.exists():
                    return p
    return None


__VAULT_ARSENAL_DIR = None

def _vault_arsenal_dir():
    global __VAULT_ARSENAL_DIR
    if __VAULT_ARSENAL_DIR is None:
        cfg = _load_config()
        vault_arsenal = cfg.get("vault_arsenal_dir", "")
        if vault_arsenal:
            __VAULT_ARSENAL_DIR = Path(vault_arsenal)
        else:
            __VAULT_ARSENAL_DIR = OBSIDIAN_DIR / "Command Center" / "vault-arsenal"
    return __VAULT_ARSENAL_DIR


def _scan_vault_for_tools():
    """Scan Obsidian vault for shell command blocks and return structured entries."""
    md_files = sorted(OBSIDIAN_DIR.rglob("*.md"))
    entries = []
    for fp in md_files:
        rel = fp.relative_to(OBSIDIAN_DIR)
        text = fp.read_text(encoding="utf-8", errors="replace")
        # Extract triple-backtick code blocks with shell/bash/powershell
        blocks = re.findall(r"```(?:bash|sh|shell|powershell|cmd)?\s*\n(.*?)```", text, re.DOTALL)
        if not blocks:
            continue
        # Extract a tool name from the filename
        tool_name = rel.stem.lower().replace(" ", "-").replace("_", "-")
        category = rel.parts[0] if len(rel.parts) > 1 else "general"
        # Collect individual commands from blocks
        commands = []
        for b in blocks:
            for line in b.strip().split("\n"):
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("//"):
                    commands.append(line)
        if commands:
            entries.append({
                "name": tool_name,
                "category": category,
                "path": str(rel),
                "commands": commands[:20],  # cap at 20 per file
                "count": len(commands),
            })
    return entries


def _generate_vault_arsenal():
    """Generate arsenal-format cheat files from vault command references."""
    out_dir = _vault_arsenal_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    entries = _scan_vault_for_tools()
    generated = 0
    for e in entries:
        category_map = {
            "recon": "RECON", "ad": "ATTACK", "web": "ATTACK",
            "exploit": "ATTACK", "wifi": "ATTACK", "forensics": "POSTEXPLOIT",
            "detection": "CODE", "wordlist": "CRACKING",
            "external": "RECON", "internal": "ATTACK",
        }
        cat_tag = category_map.get(e["category"], "UTILS")
        target_tag = "remote" if cat_tag in ("ATTACK", "RECON") else "local"
        lines = [
            f"{e['name']}",
            f"% {e['name']}, {e['category']}",
            f"Commands extracted from {e['path']}",
            f"#cat/{cat_tag}",
            f"#target/{target_tag}",
            "#plateform/multiple",
            "",
        ]
        for cmd in e["commands"][:15]:
            lines.append("```")
            lines.append(cmd)
            lines.append("```")
            lines.append("")
        cheat_path = out_dir / f"{e['name']}.md"
        cheat_path.write_text("\n".join(lines) + "\n")
        generated += 1
    return generated, len(entries)


def cmd_arsenal(args):
    a = getattr(args, "action", "list") or "list"
    ad = _find_arsenal()
    if not ad:
        ap = which("arsenal")
        if ap:
            print(f"Arsenal CLI found at {ap}, but tools directory not detected.")
            print("  Set the path manually: cc config arsenal_dir /path/to/arsenal/tools")
            print("  Or run: cc infra arsenal setup")
        else:
            print(f"Arsenal not found at {ARSENAL_DIR} and 'arsenal' not in PATH")
            print("  Install: git clone https://github.com/Orange-Cyberdefense/arsenal /opt/arsenal")
            print("  Then:    cc config arsenal_dir /opt/arsenal")
        return
    if a == "list":
        tools = sorted(ad.rglob("*.py")) + sorted(ad.rglob("*.sh")) + sorted(ad.rglob("*.md"))
        tag = getattr(args, "filter_by_tag", None)
        if tag:
            tools = [t for t in tools if tag.lower() in t.stem.lower()]
        for t in tools:
            print(f"  {t.relative_to(ad)}")
    elif a == "filter":
        kw = getattr(args, "keyword", "") or ""
        tag = getattr(args, "tag", None)
        tools = sorted(ad.rglob("*.py")) + sorted(ad.rglob("*.sh")) + sorted(ad.rglob("*.md"))
        if kw:
            tools = [t for t in tools if kw.lower() in t.name.lower()]
        if tag:
            tools = [t for t in tools if tag.lower() in t.stem.lower()]
        for t in tools:
            print(f"  {t.relative_to(ad)}")
    elif a == "case":
        case = getattr(args, "case_type", "web_application") or "web_application"
        rules_p = ARSENAL_RULES_FILE
        if rules_p.exists():
            rules = json.loads(rules_p.read_text())
            c = rules.get("case_types", {}).get(case, {})
            if c:
                os.environ["ARSENAL_CASE"] = case
                print(f"Case: {case}\n  {c.get('description','')}")
                skip = c.get("skip_tools", [])
                if skip:
                    os.environ["ARSENAL_SKIP"] = ",".join(skip)
        else:
            print("Rules file not found")
    elif a == "run":
        tn = getattr(args, "tool_name", "")
        matches = list(ad.rglob(tn)) + list(ad.rglob(f"{tn}.py")) + list(ad.rglob(f"{tn}.sh")) + list(ad.rglob(f"{tn}.md"))
        if not matches:
            print(f"'{tn}' not found in arsenal")
            return
        cmd = [sys.executable if matches[0].suffix == ".py" else "bash", str(matches[0])]
        extra = getattr(args, "tool_args", None) or []
        cmd.extend(extra)
        subprocess.run(cmd)
    elif a == "setup":
        # Auto-detect arsenal location — try pip package first
        found = None
        try:
            import arsenal as _arsenal_mod
            p = Path(_arsenal_mod.__file__).parent / "data" / "cheats"
            if p.exists():
                found = p
        except ImportError:
            pass
        if not found:
            candidates = [
                Path(_load_config().get("arsenal_dir", str(ARSENAL_DIR))),
                TOOLS_DIR / "arsenal" / "data" / "cheats",
                Path("/usr/share/arsenal/data/cheats"),
                Path("/usr/local/share/arsenal/data/cheats"),
                Path("/root/arsenal"),
                Path.home() / "arsenal",
            ]
            ap = which("arsenal")
            if ap:
                pkg_dir = Path(ap).resolve().parent.parent
                for base in [pkg_dir / "lib", Path("/usr/lib"), Path("/usr/local/lib")]:
                    for d in sorted(base.glob("python*")):
                        p = d / "site-packages" / "arsenal" / "data" / "cheats"
                        if p.exists():
                            found = p
                            break
                    if found:
                        break
            if not found:
                for c in candidates:
                    if c.exists() and any(c.iterdir()):
                        found = c
                        break
        if found:
            cfg = _load_config()
            cfg["arsenal_dir"] = str(found)
            _save_config(cfg)
            tool_count = len(list(found.rglob("*.py")) + list(found.rglob("*.sh")) + list(found.rglob("*.md")))
            print(f"Arsenal configured at: {found} ({tool_count} tools)")
        else:
            print("Could not auto-detect arsenal. Install it:")
            print("  pip install orange-arsenal")
            print("  Or: git clone https://github.com/Orange-Cyberdefense/arsenal.git /opt/arsenal")
            print("  Then: cc config arsenal_dir /opt/arsenal")
    elif a == "vault":
        action = getattr(args, "vault_action", "list") or "list"
        if action == "list":
            entries = _scan_vault_for_tools()
            if not entries:
                print("No command references found in vault.")
                return
            print(f"Vault arsenal references ({len(entries)} files):")
            for e in sorted(entries, key=lambda x: x["name"]):
                print(f"  {e['name']:<30} {e['category']:<15} {e['count']:>3} commands  ({e['path']})")
        elif action == "generate":
            gen, total = _generate_vault_arsenal()
            out_dir = _vault_arsenal_dir()
            print(f"Generated {gen}/{total} arsenal cheat files in {out_dir}")
            if gen:
                print(f"  Add to arsenal: cc config arsenal_dir {out_dir}")
        elif action == "info":
            tn = getattr(args, "tool_name", "")
            entries = _scan_vault_for_tools()
            matches = [e for e in entries if tn.lower() in e["name"]]
            if not matches:
                print(f"'{tn}' not found in vault arsenal")
                return
            for e in matches:
                print(f"\n{e['name']} ({e['category']}) — {e['path']}")
                print(f"  {e['count']} commands found")
                for c in e["commands"][:10]:
                    print(f"    $ {c}")
                if e["count"] > 10:
                    print(f"    ... and {e['count'] - 10} more")


# ---------------------------------------------------------------------------
# Scan (preserved from original)
# ---------------------------------------------------------------------------
def cmd_scan_quick(args):
    t = getattr(args, "target", "") or ""
    if not t:
        print("Specify --target")
        return
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = CASES_DIR / f"scan_{ts}" if CASES_DIR.exists() else Path.cwd() / f"qs-{t.replace('/','_')}_{ts}"
    out.mkdir(parents=True, exist_ok=True)
    print(f"Output: {out}")
    nmap = which("nmap")
    if nmap:
        subprocess.run([nmap,"-sS","-sV","-Pn","-p-","-n","--open","-oN",str(out/"nmap.txt"),"-oX",str(out/"nmap.xml"),t])
    ww = which("whatweb")
    if ww:
        subprocess.run([ww,"-a3",t,"--log-verbose",str(out/"whatweb.txt")])


def cmd_scan_full(args):
    t = getattr(args, "target", "") or ""
    if not t:
        print("Specify --target")
        return
    hp = SCRIPTS_DIR / "recon_harness.py"
    if hp.exists():
        cmd = [sys.executable, str(hp), t]
        if getattr(args, "dry_run", False):
            cmd.append("--dry-run")
        if getattr(args, "enable_zap", False):
            cmd.append("--enable-zap")
        subprocess.run(cmd)
    else:
        cmd_scan_quick(args)


# ---------------------------------------------------------------------------
# AppSec — SBOM / SCA / secrets / SAST / OSV / CDN / existing SBOMs
# ---------------------------------------------------------------------------
def cmd_appsec(args):
    from modules.appsec import (sbom_generate, sca_grype_scan, sca_trivy_scan,
                                secret_scan, sast_scan, osv_scan, cdn_scan,
                                sbom_existing, appsec_scan)
    action = getattr(args, "appsec_action", "scan") or "scan"
    target = getattr(args, "target", "") or ""
    if action == "sbom":
        if not target:
            print("Specify --target (dir or image)")
            return
        r = sbom_generate(target, format=getattr(args, "format", "cyclonedx-json"),
                          tool=getattr(args, "tool", "syft"))
        if r.get("error"):
            print(f"Error: {r['error']}"); return
        print(f"SBOM ({r.get('tool')}): {r.get('output_file')}")
        s = r.get("summary", {})
        print(f"  components: {s.get('components', '?')}")
        return
    if action == "grype":
        if not target:
            print("Specify --target"); return
        r = sca_grype_scan(target)
        print(_appsec_fmt_sca(r)); return
    if action == "trivy":
        if not target:
            print("Specify --target"); return
        r = sca_trivy_scan(target)
        print(_appsec_fmt_sca(r)); return
    if action == "secrets":
        if not target:
            print("Specify --target"); return
        r = secret_scan(target)
        if r.get("error"):
            print(f"Error: {r['error']}"); return
        s = r.get("summary", {})
        print(f"Gitleaks: {s.get('leaks', 0)} leak(s) -> {r.get('report_file')}")
        for it in (s.get("sample") or [])[:10]:
            print(f"  {it.get('file')}:{it.get('line')} [{it.get('rule')}]")
        return
    if action == "sast":
        if not target:
            print("Specify --target"); return
        r = sast_scan(target)
        if r.get("error"):
            print(f"Error: {r['error']}"); return
        sev = r.get("by_severity") or {}
        print(f"SAST ({r.get('engine')}): {r.get('findings', 0)} finding(s) "
              f"(high={sev.get('high', 0)} med={sev.get('medium', 0)} "
              f"low={sev.get('low', 0)})")
        for f in (r.get("sample") or [])[:15]:
            print(f"  [{f.get('severity')}] {f.get('file')}:{f.get('line')} "
                  f"{f.get('id')} - {f.get('message')}")
        return
    if action == "osv":
        if not target:
            print("Specify --target"); return
        r = osv_scan(target)
        if r.get("error"):
            print(f"Error: {r['error']}"); return
        sev = r.get("by_severity") or {}
        print(f"OSV ({r.get('source')}): {r.get('checked', 0)} pkg(s), "
              f"{r.get('vulns', 0)} vuln(s) "
              f"(high={sev.get('high', 0)} med={sev.get('medium', 0)})")
        for v in (r.get("top_vulns") or [])[:15]:
            fix = f"  fix: {v.get('fixed')}" if v.get("fixed") else ""
            print(f"  [{v.get('severity','?')}] {v.get('id')} {v.get('pkg')}{fix}")
        return
    if action == "cdn":
        if not target:
            print("Specify --target"); return
        r = cdn_scan(target)
        if r.get("error"):
            print(f"Error: {r['error']}"); return
        print(f"CDN libs: {r.get('libs', 0)} found, {r.get('flagged', 0)} flagged")
        for lib in (r.get("inventory") or [])[:15]:
            print(f"  {lib.get('name')}@{lib.get('version')}  "
                  f"({', '.join(lib.get('files', [])[:2])})")
        for a in (r.get("advisories") or [])[:10]:
            print(f"  [!] {a.get('pkg')}@{a.get('version')} [{a.get('severity')}] "
                  f"{a.get('id')} - {a.get('summary')}")
        return
    if action == "sbom_existing":
        if not target:
            print("Specify --target"); return
        r = sbom_existing(target)
        if r.get("error"):
            print(f"Error: {r['error']}"); return
        print(f"Existing SBOMs: {r.get('sboms_found', 0)} found")
        for s in (r.get("sboms") or []):
            sev = s.get("by_severity") or {}
            print(f"  {s.get('file')}: {s.get('components')} components, "
                  f"{s.get('vulnerabilities')} vulns "
                  f"(crit={sev.get('critical', 0)} high={sev.get('high', 0)})")
        return
    if not target:
        print("Specify --target")
        return
    r = appsec_scan(target, do_sbom=not getattr(args, "no_sbom", False),
                    do_sca=not getattr(args, "no_sca", False),
                    do_secrets=not getattr(args, "no_secrets", False),
                    sca_tool=getattr(args, "sca_tool", "grype"))
    for stage, res in (r.get("stages") or {}).items():
        if isinstance(res, dict) and res.get("error"):
            print(f"[{stage}] Error: {res['error']}")
        elif stage == "sbom":
            print(f"[sbom] {res.get('tool')} -> {res.get('output_file')}")
        elif stage == "sca":
            print(_appsec_fmt_sca(res))
        elif stage == "secrets":
            s = res.get("summary", {})
            print(f"[secrets] gitleaks: {s.get('leaks', 0)} leak(s) -> {res.get('report_file')}")
        elif stage == "sast":
            sev = res.get("by_severity") or {}
            print(f"[sast] {res.get('engine')}: {res.get('findings', 0)} findings "
                  f"(high={sev.get('high', 0)} med={sev.get('medium', 0)})")
        elif stage == "osv":
            sev = res.get("by_severity") or {}
            print(f"[osv] {res.get('checked', 0)} pkg(s), {res.get('vulns', 0)} vulns "
                  f"(high={sev.get('high', 0)} med={sev.get('medium', 0)})")
        elif stage == "cdn":
            print(f"[cdn] {res.get('libs', 0)} lib(s), {res.get('flagged', 0)} flagged")
        elif stage == "sbom_existing":
            print(f"[sbom_existing] {res.get('sboms_found', 0)} pre-built SBOM(s)")


def _appsec_fmt_sca(r):
    if r.get("error"):
        return f"Error: {r['error']}"
    s = r.get("summary", {})
    sev = s.get("by_severity") or {}
    lines = [f"{r.get('tool')}: {s.get('total', 0)} vuln(s) "
             f"(crit={sev.get('critical', 0)} high={sev.get('high', 0)} "
             f"med={sev.get('medium', 0)} low={sev.get('low', 0)})"]
    for v in (s.get("top_vulns") or [])[:15]:
        fix = (v.get("fix") or v.get("fixed") or "")
        lines.append(f"  [{v.get('severity','?')}] {v.get('id')} {v.get('pkg')}"
                     f"@{v.get('version') or v.get('installed')}"
                     f"{'  fix: ' + fix if fix else ''}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# DAST — OWASP ZAP
# ---------------------------------------------------------------------------
def cmd_zap(args):
    from modules.zap_client import ZapClient
from modules.config import load_config
    zc = load_config().get("zap") or {}
    client = ZapClient(api_url=zc.get("url", "http://127.0.0.1:8080"),
                       api_key=zc.get("api_key", ""))
    action = getattr(args, "zap_action", "health") or "health"
    if action == "health":
        h = client.health()
        print(h if h.get("status") != "ok" else f"ZAP v{h.get('version')} up")
    elif action == "start":
        client.ensure_running(zap_bin=zc.get("bin", "zaproxy"))
        h = client.health()
        print(f"ZAP: {h}")
    elif action == "scan":
        url = getattr(args, "target", "") or ""
        if not url:
            print("Specify --target URL"); return
        client.ensure_running(zap_bin=zc.get("bin", "zaproxy"))
        mode = getattr(args, "mode", "active") or "active"
        if mode == "spider":
            r = client.spider_start(url)
            print(f"Spider started scan_id={r.get('scan_id')}" if "error" not in r else f"Error: {r['error']}")
        elif mode == "ajax":
            r = client.ajax_spider_start(url)
            print("AJAX spider started" if "error" not in r else f"Error: {r['error']}")
        else:
            r = client.active_scan_start(url)
            print(f"Active scan started scan_id={r.get('scan_id')}" if "error" not in r else f"Error: {r['error']}")
    elif action == "status":
        sid = getattr(args, "scan_id", "") or ""
        mode = getattr(args, "mode", "active") or "active"
        if mode == "ajax":
            print(client.ajax_spider_status())
        elif mode == "spider":
            print(client.spider_status(sid))
        else:
            print(client.active_scan_status(sid))
    elif action == "issues":
        risk = getattr(args, "risk", "") or ""
        alerts = client.alerts(risk=risk)
        if isinstance(alerts, list) and alerts and "error" in alerts[0]:
            print(f"Error: {alerts[0]['error']}"); return
        for a in alerts:
            print(f"[{a.get('risk')}] {a.get('name')} - {a.get('url')}")


# ---------------------------------------------------------------------------
# Compiled-binary CLI-surface scan
# ---------------------------------------------------------------------------
def cmd_bin_surface(args):
    from modules.bin_surface import scan_directory, scan_binary, format_report
    from pathlib import Path
    target = getattr(args, "target", "") or ""
    if not target:
        print("Specify --target (file or dir)")
        return
    p = Path(target)
    if p.is_file():
        r = {"target": str(p), "found": 1, "scanned": 1,
             "results": [scan_binary(p)], "errors": []}
    else:
        r = scan_directory(p, max_depth=getattr(args, "max_depth", 3) or 3,
                           with_strings=not getattr(args, "no_strings", False))
    print(format_report(r))


# ---------------------------------------------------------------------------
# Compiled-artifact security scan
# ---------------------------------------------------------------------------
def cmd_compiled_scan(args):
    from modules.compiled_scan import scan_target, format_report
    target = getattr(args, "target", "") or ""
    if not target:
        print("Specify --target (file or dir)")
        return
    with_yara = getattr(args, "yara", False)
    min_sev = getattr(args, "min_severity", "info") or "info"
    max_depth = getattr(args, "max_depth", 4) or 4
    r = scan_target(target, max_depth=max_depth, with_yara=with_yara,
                    min_severity=min_sev)
    print(format_report(r))


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------
def cmd_profile(args):
    pp = ENV_PROFILES_FILE
    if not pp.exists():
        print("Profiles file not found")
        return
    profs = json.loads(pp.read_text()).get("profiles", {})
    a = getattr(args, "profile_action", "list") or "list"
    if a == "list":
        for n, d in profs.items():
            svc = [k for k, v in d.get("services", {}).items() if v]
            print(f"  {n:<20} {d.get('description','')}  [{', '.join(svc)}]")
    elif a == "show":
        n = getattr(args, "profile_name", "default") or "default"
        d = profs.get(n)
        if d:
            print(json.dumps(d, indent=2))
    elif a == "apply":
        n = getattr(args, "profile_name", "default") or "default"
        d = profs.get(n, {})
        if d.get("services", {}).get("jupyter"):
            cmd_start(None)
        print(f"Profile '{n}' applied")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
def cmd_config(args):
    cfg = _load_config()
    if getattr(args, "show", False):
        print(json.dumps(cfg, indent=2))
    elif getattr(args, "key", None) and getattr(args, "value", None):
        cfg[args.key] = args.value
        _save_config(cfg)
        print(f"{args.key} = {args.value}")
    elif getattr(args, "key", None):
        print(f"{args.key} = {cfg.get(args.key, '<not set>')}")
    else:
        print(json.dumps(cfg, indent=2))


# ---------------------------------------------------------------------------
# RUN
# ---------------------------------------------------------------------------
def cmd_run(args):
    tool = getattr(args, "tool", "") or ""
    tp = which(tool)
    if not tp:
        for n, p in _index_custom_tools().items():
            if tool in n:
                tp = p
                break
    if not tp:
        print(f"'{tool}' not found")
        return
    subprocess.run([tp] + (getattr(args, "tool_args", None) or []))


# ---------------------------------------------------------------------------
# ========================== NEW MODULE COMMANDS ==========================
# ---------------------------------------------------------------------------

# --- Case Management ---
def cmd_case(args):
    cm = CaseManager()
    a = getattr(args, "case_action", "list") or "list"

    if a == "list":
        for c in cm.list_cases():
            print(f"  {c.get('case_id','?'):<25} {c.get('client',''):<20} "
                  f"status={c.get('status','?'):<8} "
                  f"evidence={len(c.get('evidence',[]))}")
    elif a == "create":
        cid = getattr(args, "case_id", "") or f"case_{datetime.datetime.now():%Y%m%d_%H%M%S}"
        targets_raw = getattr(args, "targets", "") or ""
        targets = [t.strip() for t in targets_raw.split(",") if t.strip()] if targets_raw else []
        try:
            cm.create(cid, getattr(args, "client", "") or "",
                          getattr(args, "case_type", "pentest") or "pentest",
                          getattr(args, "description", "") or "",
                          targets=targets,
                          goals=[g.strip() for g in (getattr(args, "goals", "") or "").split("|") if g.strip()])
            print(f"Case '{cid}' created at {CASES_DIR / cid}")
            if targets:
                print(f"  Scope: {len(targets)} target(s)")
            goals = (getattr(args, "goals", "") or "").strip()
            if goals:
                print(f"  Goals: {goals}")
        except FileExistsError as e:
            print(e)
    elif a == "info":
        cid = getattr(args, "case_id", "") or ""
        info = cm.info(cid)
        if info:
            print(json.dumps(info, indent=2, default=str))
        else:
            print(f"Case '{cid}' not found")
    elif a == "close":
        cm.close(getattr(args, "case_id", "") or "")
        print("Case closed")
    elif a == "evidence":
        cid = getattr(args, "case_id", "") or ""
        fp = getattr(args, "file", "") or ""
        cat = getattr(args, "category", "evidence") or "evidence"
        desc = getattr(args, "description", "") or ""
        rec = cm.add_evidence(cid, fp, cat, desc)
        if rec:
            print(f"Evidence added: SHA256={rec['sha256'][:16]}...")
        else:
            print("Failed to add evidence")
    elif a == "note":
        cid = getattr(args, "case_id", "") or ""
        body = getattr(args, "body", "") or ""
        note = cm.add_note(cid, body)
        if note:
            print("Note added")
    elif a == "verify":
        cid = getattr(args, "case_id", "") or ""
        results = cm.verify_evidence(cid)
        for r in results:
            if r.get("error"):
                print(f"  {r['error']}")
            else:
                icon = "\u2713" if r.get("status") == "valid" else "\u2717"
                print(f"  {icon} {r['filename']:<40} {r['status']}")
    elif a == "scope":
        cid = getattr(args, "case_id", "") or ""
        sa = getattr(args, "scope_action", "list") or "list"
        if sa == "list":
            s = cm.scope_list(cid)
            print("In scope:")
            for t in s.get("in_scope", []):
                print(f"  \u2713 {t}")
            print("Out of scope:")
            for t in s.get("out_of_scope", []):
                print(f"  \u2717 {t}")
        elif sa == "add":
            target = getattr(args, "target", "") or ""
            in_scope = not getattr(args, "out", False)
            cm.scope_add(cid, target, in_scope)
            print(f"{'In' if in_scope else 'Out of'} scope: {target}")
        elif sa == "remove":
            target = getattr(args, "target", "") or ""
            cm.scope_remove(cid, target)
            print(f"Removed: {target}")
        elif sa == "check":
            target = getattr(args, "target", "") or ""
            r = cm.scope_check(cid, target)
            print(f"{target}: {'in scope' if r['in_scope'] else 'OUT OF SCOPE'} ({r['reason']})")
    elif a == "task":
        cid = getattr(args, "case_id", "") or ""
        ta = getattr(args, "task_action", "list") or "list"
        if ta == "list":
            all_t = getattr(args, "all", False)
            for t in cm.task_list(cid, show_done=all_t):
                done = "\u2713" if t.get("done") else "\u2717"
                print(f"  {done} {t['id']:<6} [{t.get('priority','?')}] {t['description'][:60]}")
        elif ta == "add":
            desc = getattr(args, "description", "") or ""
            prio = getattr(args, "priority", "medium") or "medium"
            t = cm.task_add(cid, desc, prio)
            print(f"Task {t['id']} added")
        elif ta == "done":
            tid = getattr(args, "task_id", "") or ""
            t = cm.task_done(cid, tid)
            if t:
                print(f"Task {tid} completed")
            else:
                print(f"Task not found: {tid}")
    elif a == "goal":
        cid = getattr(args, "case_id", "") or ""
        ga = getattr(args, "goal_action", "list") or "list"
        if ga == "add":
            goal = getattr(args, "goal", "") or ""
            r = cm.goal_add(cid, goal)
            if r:
                print(f"Goal added: {goal}")
            else:
                print(f"Case '{cid}' not found")
        elif ga == "list":
            goals = cm.goal_list(cid)
            if goals:
                for i, g in enumerate(goals):
                    print(f"  [{i}] {g}")
            else:
                print("No goals defined.")
        elif ga == "remove":
            idx = getattr(args, "index", -1) or -1
            r = cm.goal_remove(cid, idx)
            if r:
                print(f"Removed: {r['removed']}")
            else:
                print("No goals to remove.")
    elif a == "strength":
        cid = getattr(args, "case_id", "") or ""
        sa = getattr(args, "strength_action", "list") or "list"
        if sa == "list":
            for i, s in enumerate(cm.list_strengths(cid)):
                print(f"  [{i}] {s}")
        elif sa == "add":
            text = getattr(args, "text", "") or ""
            r = cm.add_strength(cid, text)
            if r: print("Strength added")
            else: print("Failed to add strength")
        elif sa == "remove":
            idx = getattr(args, "index", -1) or -1
            r = cm.remove_strength(cid, idx)
            if r: print(f"Removed: {r['removed']}")
            else: print("No strengths to remove")
    elif a == "weakness":
        cid = getattr(args, "case_id", "") or ""
        wa = getattr(args, "weakness_action", "list") or "list"
        if wa == "list":
            for i, w in enumerate(cm.list_weaknesses(cid)):
                print(f"  [{i}] {w}")
        elif wa == "add":
            text = getattr(args, "text", "") or ""
            r = cm.add_weakness(cid, text)
            if r: print("Weakness added")
            else: print("Failed to add weakness")
        elif wa == "remove":
            idx = getattr(args, "index", -1) or -1
            r = cm.remove_weakness(cid, idx)
            if r: print(f"Removed: {r['removed']}")
            else: print("No weaknesses to remove")
    elif a == "archive":
        cid = getattr(args, "case_id", "") or ""
        r = cm.archive_case(cid)
        if "error" in r: print(r["error"])
        else: print(f"Case '{cid}' archived: {r.get('archive_path','')}")
    elif a == "unarchive":
        cid = getattr(args, "case_id", "") or ""
        r = cm.unarchive_case(cid)
        if "error" in r: print(r["error"])
        else: print(f"Case '{cid}' unarchived")
    elif a == "delete":
        cid = getattr(args, "case_id", "") or ""
        if cm.delete(cid):
            print(f"Case '{cid}' deleted")
        else:
            print(f"Case '{cid}' not found")
    elif a == "checklist":
        cid = getattr(args, "case_id", "") or ""
        ca = getattr(args, "checklist_action", "list") or "list"
        cl = ChecklistInstance(cm._case_path(cid))
        if ca == "init":
            tpl = getattr(args, "template", "") or ""
            replace = getattr(args, "replace", False)
            if not tpl:
                print("Available templates:")
                for t in list_checklist_templates():
                    print(f"  {t['id']:<40} {t['title']}")
                return
            r = cl.initialize(tpl, replace=replace)
            if "error" in r:
                print(f"Error: {r['error']}")
            else:
                print(f"Checklist '{tpl}' initialized (id={r.get('instance_id','')[:8]}, {len(r.get('items',{}))} items)")
        elif ca == "list":
            instances = cl.get()
            if not instances:
                print("No checklists. Use `cc case checklist init --template <name>` to create one.")
                return
            for idx, instance in enumerate(instances):
                iid = instance.get("instance_id", "?")[:8]
                title = instance.get("title", "Untitled")
                print(f"\n{'='*60}")
                print(f"  [{idx+1}] {title} (id: {iid}) — {len(instance.get('items',{}))} items")
                print(f"{'='*60}")
                for cat in instance.get("categories", []):
                    print(f"\n  {cat['name']}:")
                    for item in cat.get("items", []):
                        meta = instance.get("items", {}).get(item["id"], {})
                        status = meta.get("status", "not_started")
                        icons = {"passed": "\u2713", "failed": "\u2717",
                                 "in_progress": "\u25D8", "not_started": "\u25CB",
                                 "not_applicable": "\u2014"}
                        icon = icons.get(status, "\u25CB")
                        finding = f" [{meta.get('finding_id','')}]" if meta.get("finding_id") else ""
                        print(f"    {icon} {item['description']:<60} {status:<14}{finding}")
        elif ca == "status":
            item_id = getattr(args, "item_id", "") or ""
            status = getattr(args, "status", "") or ""
            instance_id = getattr(args, "instance_id", "") or ""
            if not item_id or not status:
                print("Usage: cc case checklist status --item-id <id> --status <value> [--instance-id <id>]")
                return
            r = cl.update_item(item_id, status=status, instance_id=instance_id)
            if r:
                print(f"  {item_id} -> {status}")
            else:
                print(f"Item '{item_id}' not found")
        elif ca == "delete":
            instance_id = getattr(args, "instance_id", "") or ""
            if not instance_id:
                print("Usage: cc case checklist delete --instance-id <id>")
                return
            ok = cl.delete_instance(instance_id)
            print("Deleted." if ok else "Instance not found.")
        elif ca == "from-findings":
            title = getattr(args, "title", "") or ""
            replace = getattr(args, "replace", False)
            db = FindingsDB(cm._case_path(cid))
            findings = db.list()
            if not findings:
                print("No findings to build a checklist from.")
                return
            r = cl.from_findings(findings, title=title, replace=replace)
            if "error" in r:
                print(f"Error: {r['error']}")
            else:
                print(f"Checklist built from {len(findings)} findings (id={r.get('instance_id','')[:8]})")
    elif a == "export":
        cid = getattr(args, "case_id", "") or ""
        fmt = getattr(args, "format", "sarif") or "sarif"
        output = getattr(args, "output", "") or ""
        no_checklist = getattr(args, "no_checklist", False)
        r = export_case_results(cid, fmt=fmt, output=output,
                                include_checklist=not no_checklist)
        if "error" in r:
            print(r["error"])
        else:
            print(f"Exported {r.get('format','?')} -> {r.get('path','')}")
            for k in ("findings", "checklist_items", "total_rules", "passed", "score"):
                if k in r:
                    print(f"  {k}: {r[k]}")
            if r.get("validate_hint"):
                print(f"  Validate: {r['validate_hint']}")


# --- Playbook ---
def cmd_playbook(args):
    pe = PlaybookEngine()
    a = getattr(args, "playbook_action", "list") or "list"

    if a == "list":
        for p in pe.list_runbooks():
            meta = ""
            try:
                data = yaml.safe_load(p.read_text())
                nm = data.get("name", "") or ""
                ver = data.get("version", "") or ""
                meta = f"  [{ver}] {nm}" if ver else f"  {nm}"
            except Exception:
                meta = ""
            print(f"  {p.name:<40} {meta}")
    elif a == "show":
        pb = getattr(args, "playbook", "") or ""
        try:
            data = pe.load(pb)
            print(yaml.safe_dump(data, default_flow_style=False, sort_keys=False))
        except Exception as e:
            print(f"Error: {e}")
    elif a == "run":
        pb = getattr(args, "playbook", "") or ""
        target = getattr(args, "target", "") or ""
        case_id = getattr(args, "case_id", "") or ""
        verbose = getattr(args, "verbose", False)
        vars_raw = getattr(args, "vars", "") or ""
        vars_override = {}
        if vars_raw:
            for pair in vars_raw.split(","):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    vars_override[k.strip()] = v.strip()
        try:
            targets = [t.strip() for t in target.split(",") if t.strip()]
            results = pe.run_file(pb, targets, case_id, vars_override, verbose)
            out = Path.cwd() / f"playbook_{datetime.datetime.now():%Y%m%d_%H%M%S}.json"
            pe.save_results(results, out)
            print(f"\nResults saved to {out}")
            failed = sum(1 for r in results if r.get("rc", 0) != 0)
            print(f"Steps: {len(results)}, Failed: {failed}")
        except Exception as e:
            print(f"Error: {e}")


# --- Obsidian ---
def cmd_obsidian(args):
    ob = ObsidianBridge()
    a = getattr(args, "obsidian_action", "status") or "status"

    if a == "status":
        s = ob.summary()
        print(f"Vault accessible:   {s.get('accessible')}")
        print(f"Vault path:        {s.get('vault')}")
        print(f"Total notes:       {s.get('total_notes', '?')}")
        print(f"Generated notes:   {s.get('generated_notes', 0)}")
        print(f"Output directory:  {s.get('generated_dir', '?')}")
    elif a == "note":
        title = getattr(args, "title", "") or "Untitled"
        content = getattr(args, "content", "") or ""
        tags = getattr(args, "tags", "") or ""
        tags_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
        fp = ob.write_note(title, content, tags=tags_list)
        if fp:
            print(f"Note written: {fp}")
        else:
            print("Failed to write note (vault not accessible)")
    elif a == "list":
        for n in ob.list_generated_notes():
            print(f"  {n}")


# --- Doctor ---
def cmd_doctor(args):
    d = Doctor()
    d.run_all()
    print(d.summary())


# --- MCP Feature groups (lightweight MCP) ---
def cmd_features(args):
    from modules.feature_groups import (FEATURE_GROUPS, summarize, enable_group,
                                        disable_group, TOOL_INDEX_PATH)
    cfg = _load_config()
    feats = dict(cfg.get("features") or {})
    action = getattr(args, "features_action", "list") or "list"
    names = [n.strip().lower() for n in (getattr(args, "names", None) or []) if n.strip()]

    def _persist():
        cfg["features"] = feats
        _save_config(cfg)

    if action == "index":
        try:
            import cc_mcp_server as mcpmod
            from modules.feature_groups import save_tool_index
            tools = [t.name for t in mcpmod.mcp._tool_manager.list_tools()]
            save_tool_index(tools)
            print(f"Tool index refreshed: {len(tools)} tools -> {TOOL_INDEX_PATH}")
        except Exception as exc:
            print(f"Could not refresh tool index: {exc}")
        return

    if action in ("on", "off"):
        feats["enabled_groups"] = sorted(FEATURE_GROUPS) if action == "on" else []
        _persist()
        state = "Enabled all" if action == "on" else "Disabled all"
        print(f"{state} feature groups ({len(feats['enabled_groups'])} on). Restart the MCP (opencode) to apply.")
        return

    if action in ("enable", "disable"):
        if not names:
            print(f"Usage: cc features {action} <group> [...]  | groups: {', '.join(FEATURE_GROUPS)}")
            return
        ok, bad = [], []
        for n in names:
            fn = enable_group if action == "enable" else disable_group
            (ok if fn(feats, n) else bad).append(n)
        _persist()
        for n in ok:
            print(f"  {'enabled' if action == 'enable' else 'disabled'} group '{n}'")
        for n in bad:
            print(f"  unknown group '{n}' (not changed)")
        print("Restart the MCP (opencode) to apply.")
        return

    if action == "tool-add":
        if not names:
            print("Usage: cc features tool-add <tool-or-prefix> [...]")
            return
        extra = set(feats.get("enabled_tools") or []); extra.update(names)
        feats["enabled_tools"] = sorted(extra)
        _persist()
        print(f"Force-enabled tools: {', '.join(sorted(extra))}. Restart the MCP (opencode) to apply.")
        return

    if action == "tool-rm":
        if not names:
            print("Usage: cc features tool-rm <tool-or-prefix> [...]")
            return
        blocked = set(feats.get("disabled_tools") or []); blocked.update(names)
        feats["disabled_tools"] = sorted(blocked)
        enabled = set(feats.get("enabled_tools") or [])
        enabled -= set(names)
        feats["enabled_tools"] = sorted(enabled)
        _persist()
        print(f"Force-disabled tools: {', '.join(sorted(blocked))}. Restart the MCP (opencode) to apply.")
        return

    if action == "allowlist":
        env = __import__("os").environ.get("CC_MCP_TOOLS", "")
        s = summarize(feats)
        print(f"Effective allowlist (config.json features):\n  {s['allowlist'] or '(all)'}")
        print(f"Effective denylist (force-off):\n  {s['denylist'] or '(none)'}")
        if env:
            print(f"  NOTE: env CC_MCP_TOOLS='{env}' overrides the config when the MCP starts.")
        return

    if action == "manifest":
from modules.config import CC_DIR
        env = __import__("os").environ.get("CC_MCP_TOOLS", "")
        s = summarize(feats)
        md = ["# CC Toolkit — MCP Feature Manifest",
              "",
              f"Generated: {datetime.datetime.now().isoformat(timespec='seconds')}",
              "",
              "This manifest reflects the tool surface the MCP server would expose",
              "at the next start, based on `config.json` `features` (and the "
              "`CC_MCP_TOOLS` env override if set).",
              "",
              f"- Feature groups: **{len(FEATURE_GROUPS)}** available, "
              f"**{len(s['enabled_groups'])}** enabled",
              f"- Tool index: **{s['total_tools']}** MCP tools",
              f"- Exposed at next start: **{s['included_count']}** "
              f"(always-on: {', '.join(s['always_on']) or 'none'})",
              f"- Env override `CC_MCP_TOOLS`: {env or 'none (config applies)'}",
              "",
              "## Enabled groups",
              ""]
        for name in sorted(s["enabled_groups"]):
            g = s["groups"].get(name, {})
            md.append(f"- **{name}** — {g.get('label', '')} ({g.get('tool_count', 0)} tools)")
        if s.get("unknown_groups"):
            md += ["",
                   f"> Warning: configured group(s) not defined (ignored): {', '.join(s['unknown_groups'])}",
                   "> Fix with `cc features disable <group>` or by editing config.json `features.enabled_groups`."]
        md += ["", "## Allowlist (prefixes)", "```", s["allowlist"] or "(all)", "```", ""]
        md += ["## Force-disabled (denylist)", ""]
        if s["denylist"]:
            md += [f"- `{t}`" for t in s["denylist"].split(",")]
        else:
            md.append("- (none)")
        if env:
            md += ["", "> Note: `CC_MCP_TOOLS` overrides the config allowlist when the MCP starts."]
        md += ["", "## Exposed tools", ""]
        for t in s["included_tools"]:
            md.append(f"- `{t}`")
        out = CC_DIR / "MCP_FEATURES.md"
        out.write_text("\n".join(md), encoding="utf-8")
        print(f"Manifest written: {out}")
        print(f"  {s['included_count']}/{s['total_tools']} tools would be exposed "
              f"({len(s['enabled_groups'])} groups enabled).")
        if env:
            print(f"  NOTE: env CC_MCP_TOOLS='{env}' overrides config at MCP start.")
        return

    # default: list
    s = summarize(feats)
    print(f"{'GROUP':<14} {'STATE':<8} {'TOOLS':<6} DESCRIPTION")
    print("-" * 90)
    for name, g in s["groups"].items():
        state = "ON " if g["enabled"] else "off"
        print(f"{name:<14} {state:<8} {g['tool_count']:<6} {g['label']} — {g['desc']}")
    print("-" * 90)
    print(f"Enabled groups : {', '.join(s['enabled_groups']) or '(none)'}")
    if s.get("unknown_groups"):
        print(f"WARNING: configured groups not defined (ignored): {', '.join(s['unknown_groups'])}")
    print(f"Enabled tools  : {', '.join(s['enabled_tools']) or '(none)'}")
    print(f"Disabled tools : {', '.join(s['disabled_tools']) or '(none)'}")
    print(f"Index          : {s['total_tools']} MCP tools indexed "
          f"({'ok' if s['total_tools'] else 'run `cc features index`'})")
    print(f"Exposed tools  : {s['included_count']} of {s['total_tools']} "
          f"(always-on: {', '.join(s['always_on'])})")
    if s["env_override"]:
        print(f"NOTE: env CC_MCP_TOOLS='{s['env_override']}' overrides config at MCP start.")
    print("Tip: `cc features disable <group>` trims the MCP surface; restart opencode to apply.")


# --- Report ---
def cmd_report(args):
    a = getattr(args, "report_cmd", "help") or "help"
    if a == "nmap":
        xml = getattr(args, "xml", "") or ""
        if not Path(xml).exists():
            print(f"File not found: {xml}")
            return
        html = generate_nmap_report(Path(xml))
        out = Path(xml).with_suffix(".html")
        out.write_text(html)
        print(f"Nmap report: {out}")
    elif a == "nuclei":
        js = getattr(args, "json", "") or ""
        if not Path(js).exists():
            print(f"File not found: {js}")
            return
        html = generate_nuclei_report(Path(js))
        out = Path(js).with_suffix(".html")
        out.write_text(html)
        print(f"Nuclei report: {out}")
    elif a == "engagement":
        case_id = getattr(args, "case_id", "") or ""
        case_dir = CASES_DIR / case_id
        if not case_dir.exists():
            print(f"Case '{case_id}' not found")
            return
        result_path = generate_engagement_report(case_dir)
        print(f"Engagement report: {result_path}")
    elif a == "obsidian-report":
        case_id = getattr(args, "case_id", "") or ""
        from modules.report_generator import generate_obsidian_report
        case_dir = CASES_DIR / case_id
        if not case_dir.exists():
            print(f"Case '{case_id}' not found")
            return
        fmt = getattr(args, "formats", "md,html,docx,pdf") or "md,html,docx,pdf"
        results = generate_obsidian_report(case_dir, write_sections=True,
                                           formats=[f.strip() for f in fmt.split(",") if f.strip()])
        print(f"Obsidian report for case '{case_id}':")
        for ext, path in results.items():
            print(f"  .{ext} → {path}")


# --- TruffleHog ---
def cmd_trufflehog(args):
    a = getattr(args, "truffle_action", "org") or "org"
    if a == "org":
        org = getattr(args, "org", "") or ""
        if not org:
            print("Specify --org <github-org>")
            return
        result = trufflehog_org(org)
        if result.get("error"):
            print(f"Error: {result['error']}")
            return
        parsed = result.get("parsed", {})
        print(f"Scan complete. Results in {result.get('raw_file', '?')}")
        print(f"  Credentials:  {len(parsed.get('combolist', []))}")
        print(f"  Users:         {len(parsed.get('users', []))}")
        print(f"  Passwords:    {len(parsed.get('passwords', []))}")
        print(f"  Detectors:    {len(parsed.get('detectors', []))}")
    elif a == "local":
        path = getattr(args, "path", "") or ""
        if not path:
            print("Specify --path <directory>")
            return
        result = trufflehog_local(path)
        print(json.dumps(result, indent=2))


# --- MITM ---
def cmd_mitm(args):
    port = args.port or 8080
    upstream = getattr(args, "upstream", "") or ""
    try:
        proc = mitm_start(port, upstream)
        print(f"MITM proxy running on 0.0.0.0:{port} (PID: {proc.pid})")
        print("Press Ctrl+C to stop")
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        print("\nMITM proxy stopped")
    except Exception as e:
        print(f"Error: {e}")


# --- DNS ---
def cmd_dns(args):
    """cc dns {resolve|monitor|list|history|remove|track}"""
    from modules.dns_wrapper import (
        resolve, list_monitors, start_monitor,
        remove_monitor, get_history, start_background_monitor
    )
    start_background_monitor()

    a = getattr(args, "dns_action", "") or ""

    if a == "resolve":
        r = resolve(args.domain, args.types.split(",") if args.types else None)
        print(f"\n  {r['domain']} @ {r['timestamp']}")
        print(f"  {'─' * 50}")
        for rtype, entries in r["records"].items():
            if entries:
                print(f"  {rtype:5}: {entries[0]['value']}")
                for e in entries[1:]:
                    print(f"         {e['value']}")

    elif a == "monitor":
        types = args.types.split(",") if args.types else None
        r = start_monitor(args.domain, types, args.interval, args.duration)
        if "error" in r:
            print(f"  {r['error']}")
        else:
            print(f"  Monitoring {args.domain} every {args.interval}s (types: {r['config']['record_types']})")

    elif a == "list":
        monitors = list_monitors()
        if not monitors:
            print("  No active monitors.")
            return
        print(f"  {'Domain':<40} {'Types':<20} {'Interval':<10} {'Changes':<8} {'Active'}")
        print(f"  {'─'*40} {'─'*20} {'─'*10} {'─'*8} {'─'*6}")
        for m in monitors:
            dom = m.get("domain", "?")
            types = ",".join(m.get("record_types", []))
            interval = f"{m.get('interval', 300)}s"
            changes = m.get("change_count", 0)
            active = "✓" if m.get("active") else "✗"
            print(f"  {dom:<40} {types:<20} {interval:<10} {changes:<8} {active}")

    elif a == "history":
        entries = get_history(args.domain, args.limit)
        if not entries:
            print(f"  No history for {args.domain}")
            return
        print(f"  History for {args.domain} (last {len(entries)} entries):")
        print(f"  {'Timestamp':<30} {'Type':<6} {'Value':<50} {'Changed'}")
        for e in entries:
            ch = "CHANGED" if e.get("changed") else ""
            print(f"  {e['ts'][:19]:<30} {e['type']:<6} {e['value']:<50} {ch}")

    elif a in ("remove",):
        result = remove_monitor(args.domain)
        print(f"  {result.get('status', result.get('error', 'done'))}")

    elif a in ("track",):
        types = args.types.split(",") if args.types else None
        r = start_monitor(args.domain, types, args.interval, args.duration)
        if "error" in r:
            print(f"  {r['error']}")
        else:
            print(f"  Tracking {args.domain} every {args.interval}s")


# --- Prompt Library ---
def cmd_prompts(args):
    import yaml
    prompts_dir = Path(__file__).resolve().parent / "prompts"
    if args.create:
        path = prompts_dir / f"{args.create}.yaml"
        if path.exists():
            print(f"Prompt '{args.create}' already exists")
            return
        print(f"Creating prompt '{args.create}' (Ctrl+Z then Enter to finish):")
        lines = []
        try:
            while True:
                line = input()
                lines.append(line)
        except (EOFError, KeyboardInterrupt):
            pass
        content = "\n".join(lines).strip()
        doc = {"title": args.create, "description": "", "tags": [], "prompt": content}
        prompts_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.dump(doc, default_flow_style=False, allow_unicode=True))
        print(f"Created prompts/{args.create}.yaml")
        return
    if not prompts_dir.exists():
        print("No prompts directory found")
        return
    files = sorted(prompts_dir.glob("*.yaml"))
    if not files:
        print("No prompt templates found")
        return
    if args.list or not args.show:
        print(f"\nPrompt templates ({len(files)}):\n")
        for f in files:
            data = yaml.safe_load(f.read_text())
            tags = ", ".join(data.get("tags", []))
            print(f"  {f.stem}")
            print(f"    {data.get('description', '')}")
            if tags:
                print(f"    tags: {tags}")
            print()
    if args.show:
        match = [f for f in files if f.stem == args.show]
        if match:
            data = yaml.safe_load(match[0].read_text())
            print(f"\n=== {data.get('title', args.show)} ===\n")
            print(data.get("prompt", "").strip())
            print()


# --- Flashcards ---
def cmd_flashcards(args):
    import yaml
    decks_dir = Path(__file__).resolve().parent / "flashcards"
    if args.list:
        if not decks_dir.is_dir():
            print("No flashcards directory found"); return
        for f in sorted(decks_dir.glob("*.yaml")):
            try:
                data = yaml.safe_load(f.read_text()) or {}
                print(f"  {f.stem:<20} {data.get('title','?'):<30} {len(data.get('cards',[]))} cards")
            except Exception as e:
                print(f"  {f.stem:<20} ERROR: {e}")
        return
    if args.show:
        path = decks_dir / f"{args.show}.yaml"
        if not path.is_file():
            print(f"Deck '{args.show}' not found"); return
        data = yaml.safe_load(path.read_text()) or {}
        print(f"\n=== {data.get('title', args.show)} ===\n")
        for i, c in enumerate(data.get("cards", []), 1):
            print(f"  {i}. {c.get('question','')}")
            print(f"     → {c.get('answer','')}\n")
        return
    if args.create:
        path = decks_dir / f"{args.create}.yaml"
        if path.exists():
            print(f"Deck '{args.create}' already exists"); return
        title = input("Title: ").strip() or args.create
        desc = input("Description: ").strip() or ""
        cards = []
        print("Enter cards (question|answer), blank line to finish:")
        while True:
            line = input()
            if not line.strip():
                break
            if "|" in line:
                q, a = line.split("|", 1)
                cards.append({"question": q.strip(), "answer": a.strip()})
            else:
                print("  Skip (no | separator)")
        doc = {"title": title, "description": desc, "cards": cards}
        decks_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.dump(doc, default_flow_style=False, allow_unicode=True))
        print(f"Created flashcards/{args.create}.yaml ({len(cards)} cards)")
        return
    if args.delete:
        path = decks_dir / f"{args.delete}.yaml"
        if not path.is_file():
            print(f"Deck '{args.delete}' not found"); return
        path.unlink()
        print(f"Deleted flashcards/{args.delete}.yaml")
        return


# --- Route Scan ---
def cmd_route_scan(args):
    target = getattr(args, "target_range", "172.16.0.0/12") or "172.16.0.0/12"
    workers = args.workers or 10
    results = route_scan(target, workers)
    print(f"\nSuspicious hops: {len(results)}")
    for ip in results:
        print(f"  {ip}")


# --- YARA ---
def cmd_yara(args):
    rules = getattr(args, "rules", "") or ""
    target = getattr(args, "target", "") or ""
    if not rules or not target:
        print("Specify --rules and --target")
        return
    result = yara_scan(rules, target)
    if result.get("error"):
        print(f"Error: {result['error']}")
        return
    print(f"YARA scan: {result.get('rule_file', '?')} vs {target}")
    print(f"  Matches: {result.get('total', 0)}")
    for m in result.get("matches", [])[:30]:
        print(f"  Rule: {m['rule']:<30} File: {m['file']}")


# --- Semgrep ---
def cmd_semgrep(args):
    config = getattr(args, "config", "auto") or "auto"
    target = getattr(args, "target", "") or ""
    if not target:
        print("Specify --target")
        return
    result = semgrep_scan(config, target)
    print(json.dumps(result, indent=2))


# --- Sigma ---
def cmd_sigma(args):
    inf = getattr(args, "input_file", "") or ""
    fmt = getattr(args, "format", "splunk") or "splunk"
    if not inf:
        print("Specify --input-file")
        return
    result = sigma_convert(inf, fmt)
    print(json.dumps(result, indent=2))


# --- Nuclei ---
def cmd_nuclei(args):
    target = getattr(args, "target", "") or ""
    template = getattr(args, "template", "") or ""
    if not target:
        print("Specify --target")
        return
    result = nuclei_scan(target, template)
    print(f"Nuclei: {result.get('finding_count', 0)} findings")
    if result.get("error"):
        print(f"Error: {result['error']}")


# --- Wireless Graph ---
def cmd_wireless(args):
    pcap = getattr(args, "pcap", "") or ""
    iface = getattr(args, "iface", "") or ""
    result = wireless_graph(pcap, iface)
    if result.get("error"):
        print(f"Error: {result['error']}")
    else:
        print(f"Wireless graph complete (rc={result.get('rc', '?')})")


# --- Papermill notebook execution ---
NOTEBOOKS_DIR = SCRIPTS_DIR / "automation-tools"

NOTEBOOK_PARAMS = {
    "new-scans": {
        "path": "New-Scans.ipynb",
        "desc": "Full recon: nmap, httpx, whatweb, ffuf, ldap, kerb, smb, dns, rpc, winrm",
        "params": {
            "target": "Target IP/hostname",
            "workingDir": "Working directory (default: ./ScanDir-Automation)",
            "vpn_config": "Path to OpenVPN config",
            "use_vpn": "Auto-connect VPN (True/False)",
        },
    },
    "initial-scans": {
        "path": "initial-scans.ipynb",
        "desc": "Legacy recon: nmap, whatweb, ffuf, dnsrecon, ldap, rpc, gospider",
        "params": {
            "input_data": "Target IP or hostname",
        },
    },
}


def cmd_papermill(args):
    a = getattr(args, "pm_action", "list") or "list"

    # Check papermill availability
    pm = which("papermill")
    if not pm:
        pm_py = None
        try:
            import papermill
            pm_py = papermill
        except ImportError:
            pm_py = None
    else:
        pm_py = True

    if a == "list":
        print(f"Papermill-compatible notebooks ({'available' if pm_py else 'NOT available — pip install papermill'}):\n")
        for name, info in NOTEBOOK_PARAMS.items():
            nb_path = NOTEBOOKS_DIR / info["path"]
            status = "\u2713" if nb_path.exists() else "\u2717"
            print(f"  {status} {name:<20} {info['desc']}")
            if info.get("params"):
                print("      Parameters:")
                for p, d in info["params"].items():
                    print(f"        --{p:<20} {d}")
            print()

    elif a == "info":
        name = getattr(args, "notebook_name", "") or ""
        info = NOTEBOOK_PARAMS.get(name)
        if not info:
            print(f"Unknown notebook '{name}'. Available: {', '.join(NOTEBOOK_PARAMS)}")
            return
        nb_path = NOTEBOOKS_DIR / info["path"]
        print(f"  Notebook: {info['path']}")
        print(f"  Path:     {nb_path}")
        print(f"  Desc:     {info['desc']}")
        print(f"  Exists:   {'yes' if nb_path.exists() else 'no'}")
        if info.get("params"):
            print("  Parameters:")
            for p, d in info["params"].items():
                print(f"    {p:<25} {d}")

    elif a == "run":
        if not pm_py:
            print("Papermill not installed. Run: pip install papermill")
            return
        name = getattr(args, "notebook_name", "") or ""
        info = NOTEBOOK_PARAMS.get(name)
        if not info:
            print(f"Unknown notebook '{name}'. Available: {', '.join(NOTEBOOK_PARAMS)}")
            return
        nb_path = NOTEBOOKS_DIR / info["path"]
        if not nb_path.exists():
            print(f"Notebook not found: {nb_path}")
            return

        # Parse --param key=value overrides
        overrides = {}
        for p in getattr(args, "param", []) or []:
            if "=" in p:
                k, v = p.split("=", 1)
                overrides[k.strip()] = v.strip()
            else:
                print(f"Invalid param format: {p} (use key=value)")
                return

        # Set default output path
        output = getattr(args, "output", "") or str(
            Path.cwd() / f"{name}_output_{datetime.datetime.now():%Y%m%d_%H%M%S}.ipynb"
        )

        print(f"Executing notebook: {nb_path}")
        print(f"Output: {output}")
        if overrides:
            print(f"Overrides: {overrides}")

        try:
            import papermill as pm_lib
            pm_lib.execute_notebook(
                str(nb_path),
                output,
                parameters=overrides if overrides else None,
                kernel_name="python3",
                report_mode=True,
            )
            print(f"\nDone. Output notebook: {output}")
        except Exception as e:
            print(f"Error executing notebook: {e}")


# --- Wordlists ---
def _scan_wordlists(wl_dir):
    """Lazy scan — only walks dirs on first call, cached for 60s."""
    if hasattr(_scan_wordlists, "_cache"):
        cache_ts, cache_val = _scan_wordlists._cache
        if time.time() - cache_ts < 60:
            return cache_val
    paths = set()
    for p in [wl_dir, Path("/usr/share/wordlists")]:
        if p.exists():
            paths.add(p)
            for f in p.rglob("*"):
                if f.is_file() and f.stat().st_size > 0:
                    paths.add(f)
    _scan_wordlists._cache = (time.time(), paths)
    return paths


def cmd_wordlists(args):
    a = getattr(args, "wordlist_action", "list") or "list"
    cfg = _load_config()
    wl_dir = Path(cfg.get("wordlists_dir", str(WORDLISTS_DIR)))

    if a == "paths":
        print("Configured wordlist paths:\n")
        print(f"  wordlists_dir (config): {cfg.get('wordlists_dir', 'not set')}")
        print(f"  wordlist_dns (config):  {cfg.get('wordlist_dns', 'not set')}")
        print(f"  wordlist_web (config):  {cfg.get('wordlist_web', 'not set')}")
        print(f"  /usr/share/wordlists:   {'exists' if Path('/usr/share/wordlists').exists() else 'not found'}")
        print(f"  /usr/share/seclists:    {'exists' if Path('/usr/share/seclists').exists() else 'not found'}")
        print("\n  Tip: set wordlists_dir in config if your path differs:")
        print("    cc config wordlists_dir /path/to/your/wordlists")
        return

    paths = _scan_wordlists(wl_dir)
    files = [p for p in paths if p.is_file()]

    if a == "list":
        dirs = [p for p in paths if p.is_dir()]
        print(f"Wordlists ({len(files)} files, source: {wl_dir}):\n")
        if dirs:
            print("Directories:")
            for d in sorted(dirs):
                print(f"  {d}")
            print()
        if files:
            print("Files:")
            for f in sorted(files)[:50]:
                sz = f.stat().st_size
                sz_str = f"{sz/1024/1024:.1f}M" if sz > 1024**2 else f"{sz/1024:.1f}K"
                print(f"  {f:<65} {sz_str:>8}")
            if len(files) > 50:
                print(f"  ... and {len(files)-50} more")

    elif a == "search":
        kw = getattr(args, "keyword", "") or ""
        matches = [f for f in files if kw.lower() in f.name.lower()]
        print(f"Wordlists matching '{kw}' ({len(matches)}):\n")
        for f in sorted(matches):
            sz = f.stat().st_size
            sz_str = f"{sz/1024/1024:.1f}M" if sz > 1024**2 else f"{sz/1024:.1f}K"
            print(f"  {f:<65} {sz_str:>8}")

    elif a == "stats":
        total = len(files)
        total_size = 0
        largest = None
        largest_size = 0
        for f in files:
            sz = f.stat().st_size
            total_size += sz
            if sz > largest_size:
                largest_size = sz
                largest = f
        print("Wordlist statistics:\n")
        print(f"  Total files:     {total}")
        print(f"  Total size:      {total_size/1024/1024/1024:.2f}G")
        print(f"  Base directory:  {wl_dir}")
        print("  Also checked:    /usr/share/wordlists")
        if largest:
            print(f"  Largest file:    {largest} ({largest_size/1024/1024/1024:.2f}G)")


# --- Reference data ---
def cmd_ref(args):
    a = getattr(args, "ref_action", "ldap-filters") or "ldap-filters"
    kw = getattr(args, "keyword", "") or ""

    if a == "ldap-filters":
        results = search_ldap(kw)
        print(f"LDAP Filters{' matching "' + kw + '"' if kw else ''} ({len(results)}):\n")
        for f in results:
            print(f"  {f['name']:<35} {f['filter']}")
            print(f"  {'':<35} {f['desc']}")
            print()
    elif a == "event-ids":
        results = search_event_ids(kw)
        print(f"Windows Event IDs{' matching "' + kw + '"' if kw else ''} ({len(results)}):\n")
        print(f"  {'ID':>6}  {'Log':<20}  Description")
        print(f"  {'-'*6}  {'-'*20}  {'-'*50}")
        for e in results:
            print(f"  {e['id']:>6}  {e['log']:<20}  {e['desc']}")
    elif a == "cve-list":
        results = search_cves(kw)
        print(f"CVE References{' matching "' + kw + '"' if kw else ''} ({len(results)}):\n")
        for c in results:
            print(f"  {c['id']:<20} {c['name']:<30} [{c['category']}]")
            print(f"  {'':<20} {c['desc']}")
            print()


# --- BloodyAD ---
def cmd_bloodyad(args):
    a = getattr(args, "bloodyad_action", "exec") or "exec"
    server = getattr(args, "server", "") or ""
    if not server:
        print("Specify --server <AD host>")
        return
    if a == "exec":
        action = getattr(args, "action", "") or ""
        if not action:
            print("Specify action argument")
            return
        result = bloodyad_exec(
            server, action,
            username=getattr(args, "username", "") or "",
            password=getattr(args, "password", "") or "",
            domain=getattr(args, "domain", "") or "",
            target_dn=getattr(args, "dn", "") or "",
            ldap_filter=getattr(args, "filter", "") or "",
        )
        print(json.dumps(result, indent=2))
    elif a == "dump":
        result = bloodyad_dump(
            server,
            username=getattr(args, "username", "") or "",
            password=getattr(args, "password", "") or "",
            domain=getattr(args, "domain", "") or "",
            object_class=getattr(args, "object_class", "user") or "user",
        )
        print(result.get("stdout", result.get("error", "No output")))


# --- Certipy ---
def cmd_certipy(args):
    a = getattr(args, "certipy_action", "find") or "find"
    domain = getattr(args, "domain", "") or ""
    target = getattr(args, "target", "") or ""
    if not domain or not target:
        print("Specify --domain and --target")
        return
    if a == "find":
        result = certipy_find(
            domain, target,
            username=getattr(args, "username", "") or "",
            password=getattr(args, "password", "") or "",
            ca=getattr(args, "ca", "") or "",
        )
        if result.get("error"):
            print(f"Error: {result['error']}")
        else:
            print(result.get("stdout", "Certipy find complete"))
            if result.get("output_dir"):
                print(f"Output: {result['output_dir']}")
    elif a == "req":
        template = getattr(args, "template", "") or ""
        if not template:
            print("Specify --template")
            return
        result = certipy_request(
            domain, target, template,
            username=getattr(args, "username", "") or "",
            password=getattr(args, "password", "") or "",
            upn=getattr(args, "upn", "") or "",
            dns=getattr(args, "dns", "") or "",
        )
        print(result.get("stdout", result.get("error", "No output")))


# --- LdapNomNom ---
def cmd_ldapnomnom(args):
    target = getattr(args, "target", "") or ""
    if not target:
        print("Specify --target <LDAP server>")
        return
    result = ldapnomnom_enum(
        target,
        base_dn=getattr(args, "base_dn", "") or "",
    )
    if result.get("error"):
        print(f"Error: {result['error']}")
    else:
        print("LDAP enumeration complete")
        if result.get("output_file"):
            print(f"Output: {result['output_file']}")


# --- Kerbrute ---
def cmd_kerbrute(args):
    a = getattr(args, "kerbrute_action", "userenum") or "userenum"
    domain = getattr(args, "domain", "") or ""
    if not domain:
        print("Specify --domain")
        return
    if a == "userenum":
        wordlist = getattr(args, "wordlist", "") or ""
        if not wordlist:
            print("Specify --wordlist")
            return
        result = kerbrute_userenum(
            domain, wordlist,
            dc_ip=getattr(args, "dc_ip", "") or "",
        )
        if result.get("error"):
            print(f"Error: {result['error']}")
        else:
            print(result.get("stdout", "Kerbrute userenum complete"))
        if result.get("output_file"):
            print(f"Output: {result['output_file']}")
    elif a == "bruteforce":
        user = getattr(args, "user", "") or ""
        wordlist = getattr(args, "wordlist", "") or ""
        if not user or not wordlist:
            print("Specify --user and --wordlist")
            return
        result = kerbrute_bruteforce(
            domain, user, wordlist,
            dc_ip=getattr(args, "dc_ip", "") or "",
        )
        print(result.get("stdout", result.get("error", "No output")))


def cmd_responder(args):
    action = getattr(args, "responder_action", "") or ""
    iface = getattr(args, "iface", "eth0") or "eth0"
    timeout = getattr(args, "timeout", 60) or 60
    verbose = getattr(args, "verbose", False)
    from modules.tool_wrappers import responder_analyze
    analyze = action == "analyze"
    result = responder_analyze(interface=iface, analyze_mode=analyze,
                               verbose=verbose, timeout=timeout)
    if result.get("error"):
        print(f"Error: {result['error']}")
    else:
        print(f"Responder {result.get('mode', '?')} on {iface} ({timeout}s)")
        for line in result.get("output_lines", [])[-20:]:
            print(f"  {line}")


def cmd_evil_winrm(args):
    ip = getattr(args, "ip", "") or ""
    username = getattr(args, "username", "") or ""
    password = getattr(args, "password", "") or ""
    hash_ = getattr(args, "hash", "") or ""
    command = getattr(args, "command", "") or ""
    from modules.tool_wrappers import evil_winrm_connect
    result = evil_winrm_connect(ip=ip, username=username, password=password,
                                hash_value=hash_, command=command)
    if result.get("error"):
        print(f"Error: {result['error']}")
    else:
        out = result.get("stdout", result.get("output_file", "Connected"))
        print(out[:2000])


def cmd_hydra(args):
    protocol = getattr(args, "protocol", "") or ""
    target = getattr(args, "target", "") or ""
    userlist = getattr(args, "userlist", "") or ""
    passlist = getattr(args, "passlist", "") or ""
    port = getattr(args, "port", 0) or 0
    service = getattr(args, "service", "") or ""
    from modules.tool_wrappers import hydra_bruteforce
    result = hydra_bruteforce(protocol, target, userlist, passlist,
                              port=port, service=service)
    if result.get("error"):
        print(f"Error: {result['error']}")
    else:
        print(result.get("output", result.get("stdout", "Hydra complete"))[:2000])


def cmd_john(args):
    hf = getattr(args, "hash_file", "") or ""
    wl = getattr(args, "wordlist", "") or ""
    fmt = getattr(args, "format", "") or ""
    show = getattr(args, "show", False)
    from modules.tool_wrappers import john_crack
    result = john_crack(hf, wordlist=wl, format=fmt, show=show)
    if result.get("error"):
        print(f"Error: {result['error']}")
    elif show and result.get("cracked"):
        print(f"Cracked {len(result['cracked'])} hashes:")
        for line in result["cracked"][:30]:
            print(f"  {line}")
    else:
        print(result.get("stdout", "John complete")[:2000])


def cmd_metasploit(args):
    action = getattr(args, "metasploit_action", "") or ""
    from modules.tool_wrappers import metasploit_module, metasploit_resource
    if action == "module":
        mod = getattr(args, "module", "") or ""
        payload = getattr(args, "payload", "") or ""
        target = getattr(args, "target", "") or ""
        lhost = getattr(args, "lhost", "") or ""
        lport = getattr(args, "lport", 4444) or 4444
        timeout = getattr(args, "timeout", 120) or 120
        result = metasploit_module(mod, payload, target, lhost=lhost,
                                    lport=lport, timeout=timeout)
    elif action == "resource":
        script = getattr(args, "script", "") or ""
        timeout = getattr(args, "timeout", 300) or 300
        result = metasploit_resource(script, timeout=timeout)
    else:
        print("Specify 'module' or 'resource' subcommand")
        return
    if result.get("error"):
        print(f"Error: {result['error']}")
    else:
        print(result.get("stdout", "Metasploit complete")[:2000])


def cmd_sqlmap(args):
    action = getattr(args, "sqlmap_action", "") or ""
    url = getattr(args, "url", "") or ""
    data = getattr(args, "data", "") or ""
    cookie = getattr(args, "cookie", "") or ""
    level = getattr(args, "level", 1) or 1
    risk = getattr(args, "risk", 1) or 1
    from modules.tool_wrappers import sqlmap_detect, sqlmap_exploit
    if action == "detect":
        result = sqlmap_detect(url, data=data, cookie=cookie,
                                level=level, risk=risk)
    elif action == "exploit":
        os_shell = getattr(args, "os_shell", False)
        dump = getattr(args, "dump", False)
        db = getattr(args, "db", "") or ""
        table = getattr(args, "table", "") or ""
        result = sqlmap_exploit(url, data=data, cookie=cookie,
                                os_shell=os_shell, dump=dump,
                                db=db, table=table, level=level, risk=risk)
    else:
        print("Specify 'detect' or 'exploit' subcommand")
        return
    if result.get("error"):
        print(f"Error: {result['error']}")
    else:
        if action == "detect" and result.get("vulnerable"):
            print("VULNERABLE: SQL injection detected")
        print(result.get("stdout", "SQLMap complete")[:3000])


# --- EapHammer ---
def cmd_eaphammer(args):
    bssid = getattr(args, "bssid", "") or ""
    essid = getattr(args, "essid", "") or ""
    iface = getattr(args, "iface", "") or ""
    if not bssid or not essid or not iface:
        print("Specify --bssid, --essid, and --iface")
        return
    result = eaphammer_attack(
        bssid, essid, iface,
        pmkid=getattr(args, "pmkid", False),
        captive=getattr(args, "captive", False),
        auth_type=getattr(args, "auth_type", "WPA2-EAP") or "WPA2-EAP",
    )
    if result.get("error"):
        print(f"Error: {result['error']}")
    else:
        print("EAPHammer attack complete")
        if result.get("output_dir"):
            print(f"Output: {result['output_dir']}")


# --- JWT Tool ---
def cmd_jwt_tool(args):
    a = getattr(args, "jwt_action", "scan") or "scan"
    token = getattr(args, "token", "") or ""
    if not token:
        print("Specify --token <JWT>")
        return
    if a == "scan":
        result = jwt_tool_scan(token)
        print(result.get("stdout", result.get("error", "No output")))
    elif a == "attack":
        attack = getattr(args, "attack_type", "none") or "none"
        result = jwt_tool_attack(
            token, attack,
            payload_field=getattr(args, "payload_field", "") or "",
            payload_value=getattr(args, "payload_value", "") or "",
            signing_key=getattr(args, "key", "") or "",
        )
        print(result.get("stdout", result.get("error", "No output")))


# --- graphw00f ---
def cmd_graphw00f(args):
    target = getattr(args, "target", "") or ""
    if not target:
        print("Specify --target <GraphQL URL>")
        return
    result = graphw00f_scan(target)
    if result.get("error"):
        print(f"Error: {result['error']}")
    else:
        print(result.get("stdout", "GraphQL fingerprint complete"))
        if result.get("output_file"):
            print(f"Output: {result['output_file']}")


# --- WSGIDAV ---
def cmd_wsgidav(args):
    directory = getattr(args, "directory", "") or ""
    if not directory:
        print("Specify --directory <path>")
        return
    port = getattr(args, "port", 8080) or 8080
    host = getattr(args, "host", "0.0.0.0") or "0.0.0.0"
    try:
        proc = wsgidav_serve(
            directory, host=host, port=port,
            auth=getattr(args, "auth", True),
            username=getattr(args, "username", "") or "",
            password=getattr(args, "password", "") or "",
        )
        print(f"WebDAV server running on http://{host}:{port}/")
        print(f"  Root: {directory}")
        print("Press Ctrl+C to stop")
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        print("\nWebDAV server stopped")
    except Exception as e:
        print(f"Error: {e}")


# --- KAPE ---
def cmd_kape(args):
    target = getattr(args, "target", "") or ""
    if not target:
        print("Specify --target <source path or remote>")
        return
    result = kape_collect(
        target,
        targets=getattr(args, "targets", "!BasicCollection") or "!BasicCollection",
        module=getattr(args, "module", "") or "",
    )
    if result.get("error"):
        print(f"Error: {result['error']}")
    else:
        print("KAPE collection complete")
        if result.get("output_dir"):
            print(f"Output: {result['output_dir']}")


# --- Swaks ---
def cmd_swaks(args):
    to = getattr(args, "to", "") or ""
    server = getattr(args, "server", "") or ""
    if not to or not server:
        print("Specify --to <email> and --server <SMTP host>")
        return
    result = swaks_send(
        to, server,
        from_addr=getattr(args, "from", "") or "",
        subject=getattr(args, "subject", "Test") or "Test",
        body=getattr(args, "body", "") or "",
        port=getattr(args, "port", 25) or 25,
        tls=getattr(args, "tls", False),
        auth_user=getattr(args, "auth_user", "") or "",
        auth_pass=getattr(args, "auth_pass", "") or "",
        attach=getattr(args, "attach", "") or "",
        header=getattr(args, "header", "") or "",
    )
    print(result.get("stdout", result.get("error", "No output")))


# --- NetExec pre2k ---
def cmd_netexec_pre2k(args):
    domain = getattr(args, "domain", "") or ""
    dc_ip = getattr(args, "dc_ip", "") or ""
    wordlist = getattr(args, "wordlist", "") or ""
    if not domain or not dc_ip or not wordlist:
        print("Specify --domain, --dc-ip, and --wordlist")
        return
    result = netexec_pre2k(domain, dc_ip, wordlist)
    if result.get("error"):
        print(f"Error: {result['error']}")
    else:
        print(result.get("stdout", "NetExec pre2k check complete"))
        if result.get("output_file"):
            print(f"Output: {result['output_file']}")


# ===========================================================================
# NEW FEATURE COMMANDS
# ===========================================================================

# --- Findings ---
def cmd_findings(args):
    case_id = getattr(args, "case_id", "") or ""
    a = getattr(args, "findings_action", "list") or "list"
    case_dir = CASES_DIR / case_id
    if not case_dir.exists():
        print(f"Case '{case_id}' not found")
        return
    db = FindingsDB(case_dir)

    if a == "list":
        sev = getattr(args, "severity", "") or ""
        status = getattr(args, "status", "") or ""
        for f in db.list(severity=sev, status=status):
            print(f"  {f['id']:<6} {f['severity']:<10} {f['status']:<8} {f['title'][:60]}")
        s = db.summary()
        print(f"\n  Total: {s['total']}  Open: {s['open']}  By severity: {s['by_severity']}")
    elif a == "add":
        f = db.add(
            title=getattr(args, "title", "") or "",
            severity=getattr(args, "severity", "medium") or "medium",
            description=getattr(args, "description", "") or "",
            remediation=getattr(args, "remediation", "") or "",
            source=getattr(args, "source", "manual") or "manual",
        )
        print(f"Finding {f['id']} added")
    elif a == "show":
        f = db.get(getattr(args, "finding_id", "") or "")
        if f:
            for k, v in f.items():
                print(f"  {k}: {v}")
        else:
            print("Finding not found")
    elif a == "close":
        f = db.close(getattr(args, "finding_id", "") or "")
        if f:
            print(f"Finding {f['id']} closed")
        else:
            print("Finding not found")
    elif a == "import-nuclei":
        path = getattr(args, "path", "") or ""
        count = db.import_from_nuclei(Path(path))
        print(f"Imported {count} findings from {path}")

    elif a == "link-evidence":
        finding_id = getattr(args, "finding_id", "") or ""
        evidence_files = getattr(args, "evidence", []) or []
        f = db.get(finding_id)
        if not f:
            print(f"Finding '{finding_id}' not found")
            return
        existing = set(f.get("evidence_refs", []))
        added = []
        for ef in evidence_files:
            if ef not in existing:
                existing.add(ef)
                added.append(ef)
        db.update(finding_id, evidence_refs=sorted(existing))
        print(f"Linked {len(added)} evidence file(s) to {finding_id}")

    elif a == "unlink-evidence":
        finding_id = getattr(args, "finding_id", "") or ""
        evidence_files = getattr(args, "evidence", []) or []
        f = db.get(finding_id)
        if not f:
            print(f"Finding '{finding_id}' not found")
            return
        existing = set(f.get("evidence_refs", []))
        removed = []
        for ef in evidence_files:
            if ef in existing:
                existing.remove(ef)
                removed.append(ef)
        db.update(finding_id, evidence_refs=sorted(existing))
        print(f"Unlinked {len(removed)} evidence file(s) from {finding_id}")


# --- Notify Config ---
def cmd_notify_config(args):
    cfg = _load_config()
    a = getattr(args, "notify_action", "show") or "show"
    if a == "show":
        for k in ("slack_webhook", "discord_webhook", "telegram_token", "telegram_chat_id"):
            v = cfg.get(k, "")
            masked = v[:8] + "..." if v and len(v) > 12 else "(not set)"
            print(f"  {k:<25} {masked}")
        print("\n  Set with: cc notify set <key> <value>")
    elif a == "set":
        key = getattr(args, "key", "") or ""
        val = getattr(args, "value", "") or ""
        if key in ("slack_webhook", "discord_webhook", "telegram_token", "telegram_chat_id"):
            cfg[key] = val
            _save_config(cfg)
            print(f"{key} updated")
        else:
            print(f"Unknown key: {key}")
    elif a == "test":
        msg = getattr(args, "message", "CC Toolkit test notification") or ""
        targets = getattr(args, "targets", None)
        if targets:
            targets = [t.strip() for t in targets.split(",")]
        n = Notifier(cfg)
        results = n.send(msg, targets=targets)
        for r in results:
            for k, v in r.items():
                status = "sent" if v.get("sent") else f"FAILED: {v.get('error', '?')}"
                print(f"  {k}: {status}")


# --- HexStrike ---
def _build_mcp_registrations(proj_dir: Path) -> dict:
    """Build the "mcp" block for opencode.json from the CC toolkit scripts.

    Registers cc-toolkit always (run.py mcp), plus ghidra and fuzz-guide
    when the corresponding server files are present. Paths are relative to
    the project dir so the block is portable across hosts/containers.
    """
    regs = {}
    run_py = proj_dir / "run.py"
    cc_entry = {"type": "local", "enabled": True}
    if run_py.exists():
        cc_entry.update({"command": ["python3", str(run_py)], "args": ["mcp"]})
    else:
        mcp_py = proj_dir / "cc_mcp_server.py"
        cc_entry.update({"command": ["python3", str(mcp_py)]})
    regs["cc-toolkit"] = cc_entry

    fg_py = proj_dir / "fuzz_guide_mcp.py"
    if fg_py.exists():
        regs["fuzz-guide"] = {
            "type": "local",
            "command": ["python3", str(fg_py)],
            "environment": {
                "FUZZ_GUIDE_WORKDIR": os.environ.get(
                    "FUZZ_GUIDE_WORKDIR", "/tmp/fuzz_guide_workdir"),
            },
            "enabled": True,
        }

    gh_py = proj_dir / "ghidra_mcp.py"
    gh_svc = os.environ.get("GHIDRA_SERVICE_DIR", "")
    if gh_py.exists() and gh_svc:
        regs["ghidra"] = {
            "type": "local",
            "command": ["python3", str(gh_py)],
            "environment": {"GHIDRA_SERVICE_DIR": gh_svc},
            "enabled": True,
        }

    hs = which("hexstrike_server")
    if hs:
        regs["hexstrike"] = {
            "type": "local",
            "command": ["hexstrike_server"],
            "enabled": True,
        }

    return regs


def cmd_hexstrike(args):
    a = getattr(args, "hexstrike_action", "status") or "status"
    session = "hexstrike"
    if a == "start":
        port = getattr(args, "port", 8989) or 8989
        tmux = which("tmux")
        if not tmux:
            print("tmux not found — install with: apt install tmux")
            return
        # Check if already running
        r = subprocess.run([tmux, "has-session", "-t", session],
                           capture_output=True, text=True)
        if r.returncode == 0:
            print(f"HexStrike already running in tmux session '{session}'")
            return
        hs = which("hexstrike_server")
        if not hs:
            print("hexstrike_server not found in PATH")
            return
        cmd = [tmux, "new-session", "-d", "-s", session,
               hs, "--port", str(port)]
        try:
            subprocess.run(cmd, timeout=10)
            print(f"HexStrike server started in tmux session '{session}' on port {port}")
        except Exception as e:
            print(f"Error: {e}")
    elif a == "stop":
        tmux = which("tmux")
        if not tmux:
            print("tmux not found")
            return
        r = subprocess.run([tmux, "has-session", "-t", session],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print("HexStrike is not running")
            return
        subprocess.run([tmux, "kill-session", "-t", session], timeout=10)
        print("HexStrike server stopped")
    elif a == "status":
        tmux = which("tmux")
        if not tmux:
            print("tmux not found")
            return
        r = subprocess.run([tmux, "has-session", "-t", session],
                           capture_output=True, text=True)
        if r.returncode == 0:
            print("HexStrike server: RUNNING")
            # Check opencode MCP config
            oc_cfg = Path.home() / ".config" / "opencode" / "opencode.json"
            if oc_cfg.exists():
                print(f"  opencode MCP configured: yes ({oc_cfg})")
            else:
                print("  opencode MCP configured: no")
        else:
            print("HexStrike server: STOPPED")
    elif a == "opencode":
        oc = which("opencode")
        if not oc:
            print("opencode not found in PATH")
            return
        # Ensure hexstrike is running
        tmux = which("tmux")
        if tmux:
            r = subprocess.run([tmux, "has-session", "-t", session],
                               capture_output=True, text=True)
            if r.returncode != 0:
                print("HexStrike server not running — start it first: cc infra hexstrike start")
                return
        print("Launching opencode (connected to HexStrike)...")
        try:
            subprocess.run([oc])
        except KeyboardInterrupt:
            print("\nopencode closed")


# --- AI Infrastructure ---
def _ai_tunnel_session():
    return "ai-tunnel"

def cmd_infra_ai_setup(args):
    a = getattr(args, "ai_action", "status") or "status"
    session = _ai_tunnel_session()
    tmux = which("tmux")

    if a == "up":
        jump_host = getattr(args, "jump_host", os.environ.get("CC_AI_JUMP_HOST", "automation"))
        jump_user = getattr(args, "jump_user", os.environ.get("CC_AI_JUMP_USER", "jump-user"))
        target_host = getattr(args, "target_host", os.environ.get("CC_AI_TARGET_HOST", "10.42.0.21"))
        target_user = getattr(args, "target_user", os.environ.get("CC_AI_TARGET_USER", "target-user"))
        model = getattr(args, "model", os.environ.get("CC_AI_MODEL", "qwen2.5:3b"))
        gpu_layers = getattr(args, "gpu_layers", int(os.environ.get("CC_AI_GPU_LAYERS", "10")))
        local_port = getattr(args, "local_port", int(os.environ.get("CC_AI_LOCAL_PORT", "11434")))
        remote_port = getattr(args, "ollama_port", int(os.environ.get("CC_AI_OLLAMA_PORT", "11434")))

        if not tmux:
            print("tmux not found — install with: apt install tmux")
            return

        # Step 1: Start ollama on remote host, pull model only if missing
        print(f"[1/4] Starting ollama on {target_host} via {jump_host}...")
        sq = shlex.quote
        ssh_base = ["ssh", "-J", f"{sq(jump_user)}@{sq(jump_host)}", f"{sq(target_user)}@{sq(target_host)}"]
        safe_model = shlex.quote(model)
        remote_cmd = (
            f"sudo systemctl start ollama 2>/dev/null; "
            f"if ollama list 2>/dev/null | grep -qF {safe_model} || "
            f"sudo ollama list 2>/dev/null | grep -qF {safe_model}; then "
            f"echo {shlex.quote('EXISTS:' + model)}; "
            f"else echo {shlex.quote('PULLING:' + model)} && sudo ollama pull {safe_model} 2>&1 | tail -3; fi"
        )
        try:
            r = subprocess.run(ssh_base + [remote_cmd], timeout=300,
                               capture_output=True, text=True)
            out = r.stdout.strip()[:500] or r.stderr.strip()[:300]
            if out.startswith("EXISTS:"):
                print(f"  {model} already present, skipping pull")
            elif out.startswith("PULLING:"):
                detail = out.replace("PULLING:" + model, "").strip()
                print(f"  Pulled {model} ({detail})" if detail else f"  Pull initiated for {model}")
            elif r.returncode == 0:
                print(f"  ollama ready ({out})")
            else:
                print(f"  ollama start issued ({out})")
        except subprocess.TimeoutExpired:
            print("  Timeout — model may still be pulling (check with: cc infra ai-setup status)")

        # Step 1b: Configure GPU layers if requested
        sq = shlex.quote
        ssh_base = ["ssh", "-J", f"{sq(jump_user)}@{sq(jump_host)}", f"{sq(target_user)}@{sq(target_host)}"]
        if gpu_layers > 0:
            print(f"[1b/4] Setting OLLAMA_NUM_GPU_LAYERS={gpu_layers} on {target_host}...")
            override_cmd = (
                f"sudo mkdir -p /etc/systemd/system/ollama.service.d && "
                f"printf '{sq('[Service]')}\\nEnvironment=OLLAMA_NUM_GPU_LAYERS={sq(str(gpu_layers))}\\n' "
                f"| sudo tee /etc/systemd/system/ollama.service.d/override.conf >/dev/null && "
                f"sudo systemctl daemon-reload && sudo systemctl restart ollama"
            )
            try:
                subprocess.run(ssh_base + [override_cmd], timeout=30,
                               capture_output=True, text=True)
                print(f"  OLLAMA_NUM_GPU_LAYERS={gpu_layers} set, ollama restarted")
            except subprocess.TimeoutExpired:
                print("  Timeout setting GPU layers")
        elif gpu_layers == 0:
            # Remove override if exists → let ollama auto-detect
            reset_cmd = (
                "sudo rm -f /etc/systemd/system/ollama.service.d/override.conf && "
                "sudo systemctl daemon-reload && sudo systemctl restart ollama 2>/dev/null"
            )
            subprocess.run(ssh_base + [reset_cmd], timeout=15, capture_output=True)

        # Step 2: Set up SSH tunnel in tmux
        print(f"[2/4] Creating SSH tunnel (:{local_port} → {target_host}:{remote_port})...")
        if _tmux_running(session):
            subprocess.run(["tmux", "kill-session", "-t", session],
                           capture_output=True)
        tunnel_cmd = [
            tmux, "new-session", "-d", "-s", session,
            "ssh", "-J", f"{jump_user}@{jump_host}",
            "-L", f"{local_port}:localhost:{remote_port}",
            "-N", f"{target_user}@{target_host}",
        ]
        try:
            subprocess.run(tunnel_cmd, timeout=10)
            print(f"  Tunnel active in tmux session '{session}'")
        except Exception as e:
            print(f"  Tunnel failed: {e}")
            return

        # Step 3: Test the tunnel
        print("[3/4] Testing ollama reachability...")
        import time
        time.sleep(1)
        try:
            r = subprocess.run(
                ["curl", "-s", f"http://localhost:{local_port}/api/tags"],
                capture_output=True, text=True, timeout=10
            )
            if r.returncode == 0:
                models = r.stdout.count('"name"')
                print(f"  ollama reachable at :{local_port} ({models} models)")
            else:
                print("  Tunnel up, waiting for ollama... (no response yet)")
        except Exception:
            print("  Could not verify — check tunnel manually")

        # Step 4: Configure opencode
        print("[4/4] Updating opencode MCP config for local LLM + MCP servers...")
        oc_dir = Path.home() / ".config" / "opencode"
        oc_cfg = oc_dir / "opencode.json"
        provider_name = "ollama"
        model_ref = f"{provider_name}/{model}"
        provider_config = {
            provider_name: {
                "api": "openai",
                "name": "Ollama Local",
                "options": {
                    "baseURL": f"http://localhost:{local_port}/v1",
                    "apiKey": "ollama"
                },
                "models": {
                    model: {
                        "id": model,
                        "name": model.replace(":", " ").title(),
                    }
                }
            }
        }
        mcp_servers = _build_mcp_registrations(Path(__file__).resolve().parent)
        if oc_cfg.exists():
            try:
                cfg_data = json.loads(oc_cfg.read_text())
            except Exception:
                cfg_data = {}
            # Strip invalid top-level keys that opencode schema rejects
            for bad_key in ["models", "providers", "disabled_providers"]:
                cfg_data.pop(bad_key, None)
            cfg_data.setdefault("provider", {})
            cfg_data["provider"].update(provider_config)
            cfg_data["model"] = model_ref
            cfg_data["mcp"] = mcp_servers
            cfg_data["instructions"] = [
                "You are a helpful AI assistant for penetration testing, security assessment, and system administration.",
                "Always respond in English.",
                "You have MCP tools available for file operations, network scanning, AD security, WiFi, forensics, and system commands. Use them when appropriate.",
            ]
            oc_cfg.write_text(json.dumps(cfg_data, indent=2, default=str))
            print(f"  Updated {oc_cfg} with ollama provider + MCP servers ({', '.join(mcp_servers)})")
        else:
            oc_dir.mkdir(parents=True, exist_ok=True)
            cfg_data = {
                "$schema": "https://opencode.ai/config.json",
                "provider": provider_config,
                "model": model_ref,
                "mcp": mcp_servers,
                "instructions": [
                    "You are a helpful AI assistant for penetration testing, security assessment, and system administration.",
                    "Always respond in English.",
                    "You have MCP tools available for file operations, network scanning, AD security, WiFi, forensics, and system commands. Use them when appropriate.",
                ],
            }
            oc_cfg.write_text(json.dumps(cfg_data, indent=2, default=str))
            print(f"  Created {oc_cfg} with ollama provider + MCP servers ({', '.join(mcp_servers)})")
        if len(mcp_servers) < 4:
            print("  Note: some optional MCP servers were skipped (see _build_mcp_registrations).")

        print()
        print("  AI infrastructure is up!")
        print(f"  ollama:  http://localhost:{local_port}")
        print(f"  API:     http://localhost:{local_port}/v1")
        print(f"  Model:   {model_ref}")
        print(f"  Tunnel:  tmux session '{session}'")
        print()
        print("  Run: cc infra hexstrike opencode")
        print("  Or set model in web dashboard: /ai")

    elif a == "down":
        if _tmux_running(session):
            subprocess.run(["tmux", "kill-session", "-t", session],
                           capture_output=True)
            print(f"AI tunnel '{session}' stopped")
        else:
            print("AI tunnel not running")

    elif a == "status":
        running = _tmux_running(session)
        if running:
            print(f"AI tunnel: RUNNING (tmux session '{session}')")
        else:
            print("AI tunnel: STOPPED")
        try:
            r = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "http://localhost:11434/api/tags"],
                capture_output=True, text=True, timeout=5
            )
            if r.stdout.strip() == "200":
                print("ollama API:  REACHABLE (localhost:11434)")
            else:
                print(f"ollama API:  no response (HTTP {r.stdout.strip()})")
        except Exception:
            print("ollama API:  UNREACHABLE")

    elif a == "check-gpu":
        jump_host = getattr(args, "jump_host", os.environ.get("CC_AI_JUMP_HOST", "automation"))
        jump_user = getattr(args, "jump_user", os.environ.get("CC_AI_JUMP_USER", "jump-user"))
        target_host = getattr(args, "target_host", os.environ.get("CC_AI_TARGET_HOST", "10.42.0.21"))
        target_user = getattr(args, "target_user", os.environ.get("CC_AI_TARGET_USER", "target-user"))
        sq = shlex.quote
        ssh_base = ["ssh", "-J", f"{sq(jump_user)}@{sq(jump_host)}", f"{sq(target_user)}@{sq(target_host)}"]

        print(f"Checking GPU on {target_host} via {jump_host}...\n")

        checks = [
            ("nvidia-smi", "nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader 2>/dev/null || echo NOT_FOUND"),
            ("CUDA version", "nvcc --version 2>/dev/null | grep 'release' || echo NOT_FOUND"),
            ("ROCm", "rocminfo 2>/dev/null | grep 'Device Name' | head -3 || echo NOT_FOUND"),
            ("Ollama service status", "sudo systemctl is-active ollama 2>/dev/null; sudo systemctl is-enabled ollama 2>/dev/null"),
            ("Ollama process", "pgrep -a ollama 2>/dev/null | head -3 || echo 'not running'"),
            ("Ollama models loaded", "curl -s http://localhost:11434/api/tags 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); print(len(d.get(\"models\",[])),\"models loaded\")' 2>/dev/null || echo 'ollama not responding'"),
            ("Ollama recent logs", "sudo journalctl -u ollama --since '10 min ago' --no-pager 2>/dev/null | tail -10"),
            ("Override file", "cat /etc/systemd/system/ollama.service.d/override.conf 2>/dev/null || echo '(no override file)'"),
        ]
        for label, cmd in checks:
            print(f"  [{label}]")
            try:
                r = subprocess.run(
                    ssh_base + [cmd],
                    capture_output=True, text=True, timeout=30
                )
                out = (r.stdout or r.stderr or "").strip()
                for line in out.split("\n")[:5]:
                    print(f"    {line}" if line else "    (empty)")
            except subprocess.TimeoutExpired:
                print("    Timeout")
            except Exception as e:
                print(f"    Error: {e}")
            print()


# --- Remote ---
def cmd_remote(args):
    a = getattr(args, "remote_action", "exec") or "exec"
    if a == "exec":
        host = getattr(args, "host", "") or ""
        cmd = getattr(args, "command", "") or ""
        user = getattr(args, "user", "root") or "root"
        port = getattr(args, "port", 22) or 22
        key = getattr(args, "key", "") or ""
        timeout = getattr(args, "timeout", 60) or 60
        rr = RemoteRunner(host, user=user, port=port, key_file=key, timeout=timeout)
        result = rr.exec(cmd)
        print(f"Remote: {host}  rc={result.get('rc', '?')}")
        if result.get("stdout"):
            print(result["stdout"][:2000])
        if result.get("stderr"):
            print(f"stderr: {result['stderr'][:500]}")
        if result.get("error"):
            print(f"Error: {result['error']}")
    elif a == "tool":
        host = getattr(args, "host", "") or ""
        tool = getattr(args, "tool", "") or ""
        user = getattr(args, "user", "root") or "root"
        port = getattr(args, "port", 22) or 22
        key = getattr(args, "key", "") or ""
        timeout = getattr(args, "timeout", 120) or 120
        rr = RemoteRunner(host, user=user, port=port, key_file=key, timeout=timeout)
        extra = getattr(args, "tool_args", None) or []
        result = rr.run_tool(tool, extra)
        print(f"Remote tool: {host}:{tool}  rc={result.get('rc', '?')}")
        if result.get("stdout"):
            print(result["stdout"][:2000])
        if result.get("error"):
            print(f"Error: {result['error']}")


# --- History ---
def cmd_history(args):
    hl = HistoryLogger()
    a = getattr(args, "history_action", "recent") or "recent"
    if a == "recent":
        n = getattr(args, "limit", 25) or 25
        for h in hl.recent(n):
            print(f"  {h.get('ts','?')[:19]}  {h.get('command','?'):<12}  "
                  f"case={h.get('case_id','') or '-':<15}  target={h.get('target','') or '-'}")
    elif a == "search":
        q = getattr(args, "query", "") or ""
        for h in hl.search(q):
            print(f"  {h.get('ts','?')[:19]}  {h.get('command','?'):<12}  {json.dumps(h.get('args',{}))}")
    elif a == "summary":
        s = hl.summary()
        print(f"Total commands: {s['total']}")
        print(f"Unique commands: {s['unique_commands']}")


# --- Nmap pipeline ---
def cmd_nmap(args):
    a = getattr(args, "nmap_cmd", "") or ""
    target = getattr(args, "target", "") or ""
    if not target:
        print("Specify --target")
        return
    od = getattr(args, "output_dir", "") or None
    case_id = getattr(args, "case_id", None) or None

    # If case_id is provided, resolve case path and use case scans/ dir
    case_path = None
    if case_id:
        from modules.case_manager import CaseManager
        cm = CaseManager()
        case_info = cm.info(case_id)
        if case_info:
            case_path = cm._case_path(case_id)
        else:
            print(f"Case '{case_id}' not found, running scan without case linkage")
            case_id = None

    scan_dir = str(case_path / "scans") if case_path else (od if od else None)

    from modules.nmap_wrapper import (scan_initial_tcp, scan_initial_udp,
                                       scan_full_tcp, scan_service_version,
                                       scan_versions_intense, scan_versions_udp_intense,
                                       scan_vuln, scan_ack_tcp, scan_pipeline,
                                       parse_results, scan_custom)
    fns = {
        "init-tcp": lambda: scan_initial_tcp(target, output_dir=Path(scan_dir) if scan_dir else None,
                                              top_ports=getattr(args, "top_ports", 1000) or 1000),
        "init-udp": lambda: scan_initial_udp(target, output_dir=Path(scan_dir) if scan_dir else None,
                                              top_ports=getattr(args, "top_ports", 1000) or 1000),
        "full-tcp": lambda: scan_full_tcp(target, output_dir=Path(scan_dir) if scan_dir else None),
        "full-ack": lambda: scan_ack_tcp(target, output_dir=Path(scan_dir) if scan_dir else None),
        "service-version": lambda: scan_service_version(target, output_dir=Path(scan_dir) if scan_dir else None,
                                                         ports=getattr(args, "ports", "") or ""),
        "versions-tcp": lambda: scan_versions_intense(target, output_dir=Path(scan_dir) if scan_dir else None,
                                                       ports=getattr(args, "ports", "") or ""),
        "versions-udp": lambda: scan_versions_udp_intense(target, output_dir=Path(scan_dir) if scan_dir else None,
                                                           ports=getattr(args, "ports", "") or ""),
        "vuln": lambda: scan_vuln(target, output_dir=Path(scan_dir) if scan_dir else None,
                                   ports=getattr(args, "ports", "") or ""),
        "pipeline": lambda: scan_pipeline(target, output_dir=Path(scan_dir) if scan_dir else None,
                                           skip_full=getattr(args, "skip_full", False)),
        "parse": lambda: parse_results(target, output_dir=Path(scan_dir) if scan_dir else None),
        "custom": lambda: scan_custom(target, getattr(args, "args", "") or "",
                                       output_dir=Path(scan_dir) if scan_dir else None,
                                       log_name=getattr(args, "log_name", "custom") or "custom"),
    }
    fn = fns.get(a)
    if not fn:
        print(f"Unknown nmap command: {a}")
        return
    result = fn()

    # If linked to a case, add output files as evidence and create port findings
    if case_id and case_path and isinstance(result, dict):
        output_file = result.get("output_file", "")
        if output_file:
            from pathlib import Path as PPath
            out_path = PPath(output_file)
            if out_path.exists():
                cm.add_evidence(case_id, str(out_path), category="scans",
                                description=f"Nmap {a} scan of {target}")
                print(f"  Evidence added to case {case_id}")
            # Also add .nmap output if separate
            nmap_out = out_path.with_suffix(".nmap")
            if nmap_out.exists() and str(nmap_out) != output_file:
                cm.add_evidence(case_id, str(nmap_out), category="scans",
                                description=f"Nmap {a} scan output ({target})")
        # Create info-severity findings for open ports
        if a != "parse" and a != "pipeline":
            try:
                from modules.findings_db import FindingsDB
                db = FindingsDB(case_path)
                for f in sorted((case_path / "scans").glob("*.nmap")):
                    text = f.read_text(errors="ignore")
                    import re as _re
                    for m in _re.finditer(r"^(\d+)/(tcp|udp)\s+open\s+(\S*)\s*(.*)$", text, _re.MULTILINE):
                        port = m.group(1)
                        proto = m.group(2)
                        svc = m.group(3)
                        extra = m.group(4).strip()
                        title = f"Open Port {port}/{proto} — {svc}"
                        desc = f"Port {port}/{proto} is open. Service: {svc} {extra}".strip()
                        # Don't duplicate existing port findings
                        existing = db.list()
                        if not any(title in e.get("title", "") for e in existing):
                            db.add(title=title, severity="info", description=desc,
                                   source=f"nmap:{a}")
                print(f"  Port findings created for case {case_id}")
            except Exception as e:
                print(f"  Note: could not create port findings ({e})")

    if isinstance(result, dict):
        if result.get("error"):
            print(f"Error: {result['error']}")
        elif a == "parse":
            for k, v in result.items():
                if isinstance(v, list) and k.endswith("ports"):
                    print(f"  {k}: {', '.join(str(p) for p in v[:20])}")
                elif isinstance(v, list):
                    print(f"  {k}: {len(v)} items")
                else:
                    print(f"  {k}: {v}")
        elif a == "pipeline":
            for name, status in result.get("summary", {}).items():
                print(f"  {name}: {status}")
            print(f"  Output: {result.get('output_dir', '')}")
        else:
            print(result.get("stdout", result.get("output_file", "Complete"))[:1000])
    else:
        print(str(result)[:1000])


# --- Browser forensics ---
def cmd_browser(args):
    a = getattr(args, "browser_cmd", "") or ""
    path = getattr(args, "path", "") or ""
    if not path:
        print("Specify --path")
        return
    from modules.browser_db import analyze_leveldb, analyze_chrome_profile, extract_sensitive
    if a == "leveldb":
        result = analyze_leveldb(path)
    elif a == "chrome-profile":
        result = analyze_chrome_profile(path)
    elif a == "extract-sensitive":
        result = extract_sensitive(path)
    else:
        print(f"Unknown browser command: {a}")
        return
    if result.get("error"):
        print(f"Error: {result['error']}")
    elif a == "extract-sensitive":
        print(f"Sensitive items: {result.get('sensitive_found', 0)}")
        print(f"  By category: {result.get('by_category', {})}")
        print(f"  Output: {result.get('output_file', '')}")
    else:
        print(f"Store: {result.get('store_detection', result.get('path', path))}")
        print(f"  Entries: {result.get('total_entries', 0)}")
        for cat, count in result.get("summary", {}).items():
            if count:
                print(f"    {cat}: {count}")


# --- Impacket (AD) ---
def cmd_impacket(args):
    a = getattr(args, "impacket_action", "") or ""
    target = getattr(args, "target", "") or ""
    username = getattr(args, "username", "") or ""
    password = getattr(args, "password", "") or ""
    domain = getattr(args, "domain", "") or ""
    hash_ = getattr(args, "hash", "") or ""
    from modules.tool_wrappers import impacket_secretsdump, impacket_ticketer
    if a == "secretsdump":
        just_dc = getattr(args, "just_dc", False)
        result = impacket_secretsdump(target, username=username, password=password,
                                       domain=domain, hash=hash_, just_dc=just_dc)
    elif a == "ticketer":
        ntlm = getattr(args, "ntlm_hash", "") or ""
        sid = getattr(args, "domain_sid", "") or ""
        krb = getattr(args, "krbtgt_hash", "") or ""
        dur = getattr(args, "duration_hours", 10) or 10
        result = impacket_ticketer(domain=domain, username=username, ntlm_hash=ntlm,
                                    domain_sid=sid, krbtgt_hash=krb, duration_hours=dur)
    else:
        print(f"Unknown: {a}")
        return
    if result.get("error"):
        print(f"Error: {result['error']}")
    else:
        print(result.get("stdout", "Complete")[:1500])
        if result.get("output_file"):
            print(f"Output: {result['output_file']}")


# --- Exploit Impacket ---
def cmd_exploit_impacket(args):
    a = getattr(args, "exploit_impacket_action", "") or ""
    target = getattr(args, "target", "") or ""
    username = getattr(args, "username", "") or ""
    password = getattr(args, "password", "") or ""
    domain = getattr(args, "domain", "") or ""
    hash_ = getattr(args, "hash", "") or ""
    command = getattr(args, "command", "whoami") or "whoami"
    from modules.tool_wrappers import impacket_wmiexec, impacket_psexec, impacket_smbexec
    fns = {
        "wmiexec": lambda: impacket_wmiexec(target, username=username, password=password,
                                            domain=domain, hash=hash_, command=command),
        "psexec": lambda: impacket_psexec(target, username=username, password=password,
                                          domain=domain, hash=hash_, command=command),
        "smbexec": lambda: impacket_smbexec(target, username=username, password=password,
                                            domain=domain, hash=hash_, command=command),
    }
    fn = fns.get(a)
    if not fn:
        print(f"Unknown: {a}")
        return
    result = fn()
    if result.get("error"):
        print(f"Error: {result['error']}")
    else:
        print(result.get("stdout", "Complete")[:2000])


# --- Web tools ---
def cmd_ffuf(args):
    url = getattr(args, "url", "") or ""
    wl = getattr(args, "wordlist", "") or ""
    mode = getattr(args, "mode", "dir") or "dir"
    ext = getattr(args, "extensions", "") or ""
    from modules.tool_wrappers import ffuf_fuzz
    result = ffuf_fuzz(url, wl, mode=mode, extensions=ext)
    if result.get("error"):
        print(f"Error: {result['error']}")
    else:
        print(f"ffuf: {result.get('total', 0)} results")
        print(f"Output: {result.get('output_file', '')}")


def cmd_gobuster(args):
    url = getattr(args, "url", "") or ""
    wl = getattr(args, "wordlist", "") or ""
    ext = getattr(args, "extensions", "") or ""
    from modules.tool_wrappers import gobuster_dir
    result = gobuster_dir(url, wl, extensions=ext)
    if result.get("error"):
        print(f"Error: {result['error']}")
    else:
        print(result.get("output", result.get("stdout", "Complete"))[:2000])


def cmd_burp_import(args):
    xml = getattr(args, "xml_file", "") or ""
    from modules.tool_wrappers import burp_import_xml
    result = burp_import_xml(xml)
    if result.get("error"):
        print(f"Error: {result['error']}")
    else:
        print(f"Imported {result.get('total_findings', 0)} findings")
        for f in result.get("findings", [])[:10]:
            print(f"  [{f.get('severity','?')}] {f.get('name','?')}")


def cmd_caido_import(args):
    jf = getattr(args, "json_file", "") or ""
    from modules.tool_wrappers import caido_import_json
    result = caido_import_json(jf)
    if result.get("error"):
        print(f"Error: {result['error']}")
    else:
        print(f"Imported {result.get('total_findings', 0)} findings")
        print(f"Output: {result.get('output_file', '')}")


# --- Hashcat ---
def cmd_hashcat(args):
    hf = getattr(args, "hash_file", "") or ""
    wl = getattr(args, "wordlist", "") or ""
    hm = getattr(args, "hash_mode", 0) or 0
    from modules.tool_wrappers import hashcat_crack
    result = hashcat_crack(hf, wordlist=wl, hash_mode=hm)
    if result.get("error"):
        print(f"Error: {result['error']}")
    else:
        cnt = result.get("cracked_count", 0)
        print(f"Cracked: {cnt}")
        for c in result.get("cracked", [])[:20]:
            print(f"  {c}")


# --- PyPykatz ---
def cmd_pypykatz(args):
    df = getattr(args, "dump_file", "") or ""
    from modules.tool_wrappers import pypykatz_parse
    result = pypykatz_parse(df)
    if result.get("error"):
        print(f"Error: {result['error']}")
    else:
        print(f"Logon sessions: {result.get('logon_sessions', '?')}")
        print(f"Credentials: {result.get('total_credentials', '?')}")
        print(f"Usernames: {', '.join(result.get('usernames', []))}")


# --- Chisel ---
def cmd_chisel(args):
    a = getattr(args, "chisel_action", "") or ""
    from modules.tool_wrappers import chisel_client, chisel_server
    if a == "client":
        server = getattr(args, "server", "") or ""
        rp = getattr(args, "remote_port", 8080) or 8080
        lp = getattr(args, "local_port", 1080) or 1080
        rev = getattr(args, "reverse", False)
        result = chisel_client(server, remote_port=rp, local_port=lp, reverse=rev)
    elif a == "server":
        port = getattr(args, "port", 8080) or 8080
        result = chisel_server(port=port, socks=not getattr(args, "no_socks", False))
    else:
        print("Specify client or server")
        return
    print(result.get("status", result.get("error", "Unknown")))


# --- Ligolo ---
def cmd_ligolo(args):
    a = getattr(args, "ligolo_action", "") or ""
    from modules.tool_wrappers import ligolo_agent, ligolo_proxy
    if a == "agent":
        server = getattr(args, "server", "") or ""
        port = getattr(args, "port", 11601) or 11601
        result = ligolo_agent(server, proxy_port=port)
    elif a == "proxy":
        port = getattr(args, "port", 11601) or 11601
        result = ligolo_proxy(listen_port=port)
    else:
        print("Specify agent or proxy")
        return
    print(result.get("status", result.get("error", "Unknown")))


# --- LinPEAS ---
def cmd_linpeas(args):
    th = getattr(args, "target_host", "") or ""
    tu = getattr(args, "target_user", "") or ""
    tp = getattr(args, "target_pass", "") or ""
    lp = getattr(args, "local_path", "") or ""
    from modules.tool_wrappers import linpeas_run
    result = linpeas_run(target_host=th, target_user=tu, target_pass=tp, local_path=lp)
    if result.get("error"):
        print(f"Error: {result['error']}")
    else:
        print("linpeas complete")
        print(f"Output: {result.get('output_file', '')}")


# --- Kerberos tools ---
def cmd_kerberos(args):
    a = getattr(args, "kerberos_cmd", "") or ""
    from modules.kerberos_tools import (time_sync, krb5_config, kinit_user,
                                         klist_tickets, kdestroy_all, setup_for_domain)
    if a == "time-sync":
        server = getattr(args, "server", "") or ""
        result = time_sync(server=server)
    elif a == "config":
        domain = getattr(args, "domain", "") or ""
        kdc = getattr(args, "kdc", "") or ""
        as_ = getattr(args, "admin_server", "") or ""
        out = getattr(args, "output", "") or ""
        result = krb5_config(domain, kdc, admin_server=as_, output_file=out)
    elif a == "kinit":
        principal = getattr(args, "principal", "") or ""
        pw = getattr(args, "password", "") or ""
        kt = getattr(args, "keytab", "") or ""
        realm = getattr(args, "realm", "") or ""
        lt = getattr(args, "lifetime", "24h") or "24h"
        result = kinit_user(principal, password=pw, keytab=kt, realm=realm, lifetime=lt)
    elif a == "klist":
        result = klist_tickets()
    elif a == "kdestroy":
        result = kdestroy_all()
    elif a == "setup":
        domain = getattr(args, "domain", "") or ""
        kdc = getattr(args, "kdc", "") or ""
        user = getattr(args, "username", "") or ""
        pw = getattr(args, "password", "") or ""
        skip = getattr(args, "skip_time_sync", False)
        result = setup_for_domain(domain, kdc, username=user, password=pw,
                                   skip_time_sync=skip)
    else:
        print(f"Unknown kerberos command: {a}")
        return
    if isinstance(result, dict) and result.get("error"):
        print(f"Error: {result['error']}")
    elif a == "klist":
        for t in result.get("tickets", []):
            print(f"  Principal: {t.get('principal', '?')}")
            print(f"  Cache: {t.get('cache', '?')}")
        print(result.get("raw", "")[:1000])
    elif a == "setup":
        print(f"Kerberos setup: {result.get('status', 'complete')}")
        for step, sr in result.get("steps", {}).items():
            status = "OK" if not sr.get("error") else f"FAIL: {sr['error'][:60]}"
            print(f"  {step}: {status}")
    else:
        print(result.get("status", result.get("stdout", str(result)[:500])))


# --- BloodHound.py ---
def cmd_bloodhound(args):
    domain = getattr(args, "domain", "") or ""
    username = getattr(args, "username", "") or ""
    password = getattr(args, "password", "") or ""
    dc_ip = getattr(args, "dc_ip", "") or ""
    dns = getattr(args, "dns_server", "") or ""
    method = getattr(args, "collection_method", "All") or "All"
    from modules.kerberos_tools import bloodhound_ingest as bh_ingest
    result = bh_ingest(domain, username, password, dc_ip=dc_ip,
                        dns_server=dns, collection_method=method)
    if result.get("error"):
        print(f"Error: {result['error']}")
    else:
        print(f"BloodHound collection complete (RC={result.get('rc', '?')})")
        if result.get("zip_file"):
            print(f"  ZIP: {result['zip_file']}")
        print(f"  Output: {result.get('output_dir', '')}")
        if result.get("stdout"):
            print(result["stdout"][:1000])


# --- Incident Response ---
def cmd_ir(args):
    a = getattr(args, "ir_action", "") or ""
    cid = getattr(args, "case_id", "") or ""
    from modules.case_manager import CaseManager
    cm = CaseManager()

    if a == "timeline":
        ta = getattr(args, "ir_timeline_action", "") or ""
        if ta == "add":
            ts = getattr(args, "timestamp", "") or ""
            ev = getattr(args, "event", "") or ""
            sev = getattr(args, "severity", "info") or "info"
            src = getattr(args, "source", "") or ""
            r = cm.ir_timeline_add(cid, timestamp=ts, event=ev, severity=sev, source=src)
            if r:
                print(f"Timeline event added: [{sev}] {ev[:60]}")
            else:
                print("Case not found")
        elif ta == "list":
            events = cm.ir_timeline_list(cid)
            if events:
                print(f"IR Timeline ({len(events)} events):")
                for e in events:
                    print(f"  [{e.get('severity','?')}] {e.get('timestamp','')} — {e.get('event','')[:80]}")
            else:
                print("No timeline events.")
    elif a == "ttp":
        ta = getattr(args, "ir_ttp_action", "") or ""
        if ta == "add":
            tactic = getattr(args, "tactic", "") or ""
            tech = getattr(args, "technique", "") or ""
            tid = getattr(args, "technique_id", "") or ""
            notes = getattr(args, "notes", "") or ""
            r = cm.ir_ttp_add(cid, tactic=tactic, technique=tech, technique_id=tid, notes=notes)
            if r:
                print(f"TTP logged: {tactic} / {tech}")
            else:
                print("Case not found")
        elif ta == "list":
            ttps = cm.ir_ttp_list(cid)
            if ttps:
                print(f"TTPs ({len(ttps)}):")
                for t in ttps:
                    print(f"  {t.get('technique_id','')} {t.get('tactic','')} — {t.get('technique','')}")
            else:
                print("No TTPs logged.")
    elif a == "containment":
        ta = getattr(args, "ir_containment_action", "") or ""
        if ta == "add":
            action = getattr(args, "action", "") or ""
            status = getattr(args, "status", "pending") or "pending"
            owner = getattr(args, "owner", "") or ""
            r = cm.ir_containment_add(cid, action=action, status=status, owner=owner)
            if r:
                print(f"Containment step: {r.get('id','?')} — {action[:60]}")
            else:
                print("Case not found")
        elif ta == "list":
            steps = cm.ir_containment_list(cid)
            if steps:
                print(f"Containment ({len(steps)}):")
                for s in steps:
                    print(f"  [{s.get('id','?')}] [{s.get('status','?')}] {s.get('action','')[:80]}")
            else:
                print("No containment steps.")
        elif ta == "update":
            cid2 = getattr(args, "containment_id", "") or ""
            status = getattr(args, "status", "") or ""
            r = cm.ir_containment_update(cid, cid2, status)
            if r:
                print(f"Containment {cid2} updated to {status}")
            else:
                print("Containment step not found.")
def cmd_watch(args):
    """Repeatedly run a playbook on a schedule."""
    target = getattr(args, "target", "") or ""
    playbook = getattr(args, "playbook", "") or ""
    interval = getattr(args, "interval", 3600) or 3600
    count = getattr(args, "count", 0) or 0
    case_id = getattr(args, "case_id", "") or ""
    verbose = getattr(args, "verbose", False)

    if not target or not playbook:
        print("Specify --target and --playbook")
        return

    pe = PlaybookEngine()
    iteration = 0
    while True:
        iteration += 1
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        # Stable per-target case dir: a timestamped default would create a new
        # case directory every iteration, growing CASES_DIR unboundedly.
        iter_case = case_id or f"watch_{target.replace('.','_')}"
        print(f"\n[{ts}] Watch iteration #{iteration} — running {playbook}")
        try:
            results = pe.run_file(playbook, [target], iter_case, {}, verbose)
            failed = sum(1 for r in results if r.get("rc", 0) != 0)
            print(f"  Iteration #{iteration} complete: {len(results)} steps, {failed} failed")
        except Exception as e:
            print(f"  Error: {e}")

        if count and iteration >= count:
            print("Watch iterations complete")
            break
        print(f"  Next run in {interval}s...")
        time.sleep(interval)


# --- Timeline ---
def cmd_timeline(args):
    case_id = getattr(args, "case_id", "") or ""
    case_dir = CASES_DIR / case_id
    if not case_dir.exists():
        print(f"Case '{case_id}' not found")
        return
    output = getattr(args, "output", "") or str(case_dir / "timeline.html")
    html = generate_timeline_html(case_dir)
    Path(output).write_text(html)
    print(f"Timeline written to {output}")


# ---------------------------------------------------------------------------
# Binary Exploitation (ai-bug-bounty)
# ---------------------------------------------------------------------------

_BIN_TOOL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ai-bug-bounty", "bin-tools.py")

def _bin_exists() -> bool:
    return os.path.isfile(_BIN_TOOL)

def _run_bin(args: list[str]) -> int:
    py = which("python3") or "python3"
    return subprocess.call([py, _BIN_TOOL] + args)

def cmd_binary(args):
    if not _bin_exists():
        print(f"Error: bin-tools.py not found at {_BIN_TOOL}")
        sys.exit(1)
    sys.exit(_run_bin(args.subargs))


# --- Bug bounty dashboard (HackerOne / Bugcrowd) ---
def cmd_bb(args):
    from modules.bugbounty_clients import BugBountyManager, format_program, format_programs
    a = getattr(args, "bb_action", "") or ""
    mgr = BugBountyManager()

    if a == "creds":
        ca = getattr(args, "bb_creds_action", "") or ""
        if ca == "set":
            platform = getattr(args, "platform", "") or ""
            try:
                result = mgr.set_credentials(
                    platform,
                    identifier=getattr(args, "identifier", "") or "",
                    token=getattr(args, "token", "") or "",
                    client_id=getattr(args, "client_id", "") or "",
                    client_secret=getattr(args, "client_secret", "") or "",
                    public_only=not getattr(args, "oauth", False),
                )
            except ValueError as e:
                print(f"Error: {e}")
                return
            print(json.dumps(result, indent=2))
        elif ca == "list":
            for p in mgr.configured_platforms():
                extra = "  [customer-only API]" if p.get("customer_only") else ""
                print(f"  {p['platform']:<10} configured={p['configured']!s:<5} "
                      f"public={p['public']!s}{extra}")
        elif ca == "clear":
            mgr.clear_credentials(getattr(args, "platform", "") or "")
            print("Credentials cleared.")
    elif a == "list":
        print(format_programs(mgr.list_programs(
            getattr(args, "platform", "") or "",
            getattr(args, "search", "") or "")))
    elif a == "get":
        platform = getattr(args, "platform", "") or ""
        slug = getattr(args, "slug", "") or ""
        if not platform or not slug:
            print("Specify --platform and --slug")
            return
        prog = mgr.get_program(platform, slug, refresh=getattr(args, "refresh", False))
        if not prog:
            print(f"Program '{platform}:{slug}' not in cache — run `cc bb sync-program` first.")
            return
        print(format_program(prog))
    elif a == "discover":
        try:
            found = mgr.discover("hackerone")
        except RuntimeError as e:
            print(f"Error: {e}")
            return
        limit = getattr(args, "limit", 100) or 100
        print(f"Discovered {len(found)} programs (minimal entries cached):")
        for p in found[:limit]:
            print(f"  [{p.get('platform','?'):<9}] {p.get('slug','?'):<28} {p.get('name','')}")
        if len(found) > limit:
            print(f"  ... {len(found) - limit} more")
    elif a == "sync":
        result = mgr.sync_all(
            platform=getattr(args, "platform", "") or "",
            limit=getattr(args, "limit", 0) or 0,
            refresh=not getattr(args, "no_refresh", False),
        )
        print(f"Synced {len(result.get('synced', []))} programs, "
              f"discovered {result.get('new_discovered', 0)} new.")
        for f in result.get("failed", []):
            print(f"  FAILED {f.get('program')}: {f.get('error')}")
    elif a == "sync-program":
        platform = getattr(args, "platform", "") or ""
        slug = getattr(args, "slug", "") or ""
        if not platform or not slug:
            print("Specify --platform and --slug")
            return
        try:
            prog = mgr.sync_program(platform, slug, refresh=True)
        except (RuntimeError, ValueError, PermissionError, FileNotFoundError) as e:
            print(f"Error: {e}")
            return
        print(format_program(prog))
    elif a == "import-case":
        platform = getattr(args, "platform", "") or ""
        slug = getattr(args, "slug", "") or ""
        if not platform or not slug:
            print("Specify --platform and --slug")
            return
        try:
            result = mgr.import_case(
                platform, slug,
                case_id=getattr(args, "case_id", "") or "",
                client=getattr(args, "client", "") or "",
                customer_id=getattr(args, "customer_id", "") or "",
                include_assets=not getattr(args, "no_assets", False),
            )
        except (RuntimeError, ValueError, PermissionError, FileNotFoundError) as e:
            print(f"Error: {e}")
            return
        print(json.dumps(result, indent=2))
    elif a == "reports":
        platform = (getattr(args, "platform", "") or "hackerone").lower()
        slugs = [s.strip() for s in (getattr(args, "programs", "") or "").split(",") if s.strip()]
        try:
            reports = mgr.get_reports(platform, limit=getattr(args, "limit", 20) or 20,
                                      program_slugs=slugs or None)
        except (RuntimeError, ValueError) as e:
            print(f"Error: {e}")
            return
        if not reports:
            print("No reports found.")
            return
        print(f"{platform} reports ({len(reports)}):")
        for r in reports:
            print(f"  #{r.get('id','?'):<8} [{r.get('state','?')}] "
                  f"{r.get('severity','') or 'n/a':<8} {r.get('title','')} "
                  f"-> {r.get('program','')}")
    else:
        print("Unknown bb action. Use: creds, list, get, discover, sync, sync-program, import-case, reports")


# ===========================================================================
# Main
# ===========================================================================
def main():
    ensure_dirs()
    p = argparse.ArgumentParser(
        prog="cc",
        description="CC Toolkit — Command Center CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = p.add_subparsers(dest="command")

    # =================================================================
    # QUICK COMMANDS — top-level, one level deep
    # =================================================================
    for name, h, f, extra in [
        ("start", "Launch JupyterLab", cmd_start, [("--jupyter-dir", {})]),
        ("stop", "Stop services", cmd_stop, []),
        ("monitor", "Resource snapshot", cmd_monitor, []),
        ("dashboard", "Dashboards (TUI / Web)", None, []),
        ("config", "View/edit config", cmd_config, [("--show", {"action": "store_true"}), ("key", {"nargs": "?"}), ("value", {"nargs": "?"})]),
        ("doctor", "System health checks", cmd_doctor, []),
        ("run", "Run any tool from PATH", cmd_run, [("tool", {}), ("tool_args", {"nargs": argparse.REMAINDER})]),
        ("route-scan", "Detect suspicious routing", cmd_route_scan, [("--target-range", {"default": "172.16.0.0/12"}), ("--workers", {"type": int, "default": 10})]),
        ("wsgidav", "Start WebDAV server for file sharing", cmd_wsgidav, [("--directory", {"required": True}), ("--host", {"default": "0.0.0.0"}), ("--port", {"type": int, "default": 8080}), ("--auth", {"action": "store_true"}), ("--username", {}), ("--password", {})]),
        ("swaks", "SMTP email testing", cmd_swaks, [("--to", {"required": True}), ("--server", {"required": True}), ("--from", {}), ("--subject", {"default": "Test"}), ("--body", {}), ("--port", {"type": int, "default": 25}), ("--tls", {"action": "store_true"}), ("--auth-user", {}), ("--auth-pass", {}), ("--attach", {}), ("--header", {})]),
        ("watch", "Repeat a playbook on a schedule", cmd_watch, [("--target", "-t", {"required": True}), ("--playbook", "-p", {"required": True}), ("--interval", "-i", {"type": int, "default": 3600}), ("--count", "-n", {"type": int, "default": 0}), ("--case-id", "-c", {"default": ""}), ("--verbose", "-v", {"action": "store_true"})]),
        ("prompts", "Manage AI prompt templates", cmd_prompts, [("--show", "-s", {}), ("--list", "-l", {"action": "store_true"}), ("--create", "-c", {"metavar": "NAME"})]),
        ("flashcards", "Flashcard decks (study/blast)", cmd_flashcards, [("--list", "-l", {"action": "store_true"}), ("--show", "-s", {}), ("--create", "-c", {"metavar": "NAME"}), ("--delete", "-d", {"metavar": "NAME"})]),
        ("papermill", "Execute Jupyter notebooks with papermill", None, []),
        ("wordlists", "Browse & search wordlists", None, []),
    ]:
        sp = sub.add_parser(name, help=h)
        for a in extra:
            sp.add_argument(*a[:-1] if len(a) == 3 else (a[0],), **a[-1])
        if name == "papermill":
            pms = sp.add_subparsers(dest="pm_action")
            for a2, h2 in [("list","List notebooks"),("info","Show details"),("run","Execute")]:
                pmsp = pms.add_parser(a2, help=h2)
                if a2 in ("info","run"):
                    pmsp.add_argument("notebook_name", choices=list(NOTEBOOK_PARAMS.keys()))
                if a2 == "run":
                    pmsp.add_argument("--param","-p", action="append", default=[])
                    pmsp.add_argument("--output","-o", default="")
                pmsp.set_defaults(func=cmd_papermill)
        elif name == "dashboard":
            ds = sp.add_subparsers(dest="dashboard_action")
            for a2, h2, fn, extra in [
                ("tui", "Live TUI dashboard", cmd_dashboard_tui, [("--interval", {"type": int, "default": 3})]),
                ("web", "Start Flask web dashboard", cmd_dashboard_web, [
                    ("--host", {"default": "0.0.0.0"}), ("--port", {"type": int, "default": 5000}),
                    ("--debug", {"action": "store_true"})]),
            ]:
                dsp = ds.add_parser(a2, help=h2)
                for arg in extra:
                    dsp.add_argument(*arg[:-1] if len(arg) == 3 else (arg[0],), **arg[-1])
                dsp.set_defaults(func=fn)
        elif name == "wordlists":
            ws2 = sp.add_subparsers(dest="wordlist_action")
            for a2, h2 in [("list","List all"),("search","Search by name"),("stats","Show stats"),("paths","Configured paths")]:
                wsp2 = ws2.add_parser(a2, help=h2)
                if a2 == "search":
                    wsp2.add_argument("keyword")
                wsp2.set_defaults(func=cmd_wordlists)
        else:
            sp.set_defaults(func=f)

    # =================================================================
    # CATEGORY NAMESPACES
    # =================================================================

    # -- recon: scanning, discovery, OSINT --
    sp = sub.add_parser("recon", help="Reconnaissance & discovery tools")
    rc = sp.add_subparsers(dest="recon_cmd")
    for a, h, f, extra in [
        ("scan", "Nmap port scan + whatweb fingerprint", cmd_scan_quick, [("--target", {"required": True})]),
        ("scan-full", "Full recon harness", cmd_scan_full, [("--target", {"required": True}), ("--dry-run", {"action": "store_true"}), ("--enable-zap", {"action": "store_true"})]),
        ("nuclei", "Template-based vulnerability scanner", cmd_nuclei, [("--target", {"required": True}), ("--template", {})]),
    ]:
        rsp = rc.add_parser(a, help=h)
        for arg in extra:
            rsp.add_argument(*arg[:-1] if len(arg) == 3 else (arg[0],), **arg[-1])
        rsp.set_defaults(func=f)

    # -- appsec: SBOM / SCA / secrets / SAST / OSV / CDN / existing SBOMs --
    sp = sub.add_parser("appsec", help="AppSec: SBOM, SCA vuln scans, secret scanning, SAST, OSV deps, CDN libs")
    ac2 = sp.add_subparsers(dest="appsec_action")
    for a, h, extra in [
        ("scan", "Full audit (SBOM+SCA+secrets+SAST+OSV+CDN+existing SBOMs)", [("--target", {"required": True}), ("--sca-tool", {"default": "grype", "choices": ["grype", "trivy"]}), ("--no-sbom", {"action": "store_true"}), ("--no-sca", {"action": "store_true"}), ("--no-secrets", {"action": "store_true"})]),
        ("sbom", "Generate SBOM", [("--target", {"required": True}), ("--format", {"default": "cyclonedx-json"}), ("--tool", {"default": "syft", "choices": ["syft", "trivy"]})]),
        ("grype", "Grype SCA scan", [("--target", {"required": True})]),
        ("trivy", "Trivy SCA scan", [("--target", {"required": True})]),
        ("secrets", "Gitleaks secret scan", [("--target", {"required": True})]),
        ("sast", "Pattern SAST scan", [("--target", {"required": True})]),
        ("osv", "OSV dep vuln check", [("--target", {"required": True})]),
        ("cdn", "CDN frontend lib scan", [("--target", {"required": True})]),
        ("sbom_existing", "Ingest pre-built SBOMs", [("--target", {"required": True})]),
    ]:
        asp2 = ac2.add_parser(a, help=h)
        for arg in extra:
            asp2.add_argument(*arg[:-1] if len(arg) == 3 else (arg[0],), **arg[-1])
        asp2.set_defaults(func=cmd_appsec)

    # -- dast: ZAP --
    sp = sub.add_parser("dast", help="DAST: OWASP ZAP scans")
    dc = sp.add_subparsers(dest="zap_action")
    for a, h, extra in [
        ("health", "Check ZAP API", []),
        ("start", "Auto-start ZAP daemon", []),
        ("scan", "Start scan", [("--target", {"required": True}), ("--mode", {"default": "active", "choices": ["active", "spider", "ajax"]})]),
        ("status", "Scan progress", [("--scan-id", {"default": ""}), ("--mode", {"default": "active", "choices": ["active", "spider", "ajax"]})]),
        ("issues", "List alerts", [("--risk", {"default": ""})]),
    ]:
        dsp = dc.add_parser(a, help=h)
        for arg in extra:
            dsp.add_argument(*arg[:-1] if len(arg) == 3 else (arg[0],), **arg[-1])
        dsp.set_defaults(func=cmd_zap)

    # -- bin-surface: compiled binary CLI mapping --
    sp = sub.add_parser("bin-surface", help="Map CLI surface of compiled binaries")
    sp.add_argument("--target", required=True)
    sp.add_argument("--max-depth", type=int, default=3)
    sp.add_argument("--no-strings", action="store_true")
    sp.set_defaults(func=cmd_bin_surface)

    # -- compiled-scan: security scan of compiled artifacts --
    sp = sub.add_parser("compiled-scan",
                        help="Security-scan compiled artifacts (ELF/PE/Mach-O/.NET/.class/.jar/.pyc)")
    sp.add_argument("--target", required=True)
    sp.add_argument("--max-depth", type=int, default=4)
    sp.add_argument("--yara", action="store_true",
                    help="also run bundled YARA rules over each binary")
    sp.add_argument("--min-severity", choices=["info", "warning", "error"],
                    default="info", help="only report findings at/above this level")
    sp.set_defaults(func=cmd_compiled_scan)

    # -- web: web application testing --
    sp = sub.add_parser("web", help="Web application testing tools")
    wc = sp.add_subparsers(dest="web_cmd")
    for a, h, f, extra in [
        ("nuclei", "Nuclei web templates", cmd_nuclei, [("--target", {"required": True}), ("--template", {"default": ""})]),
        ("graphw00f", "GraphQL endpoint fingerprint", cmd_graphw00f, [("--target", {"required": True})]),
        ("jwt-tool", "JWT attack toolkit", None, []),
        ("ffuf", "Directory/file fuzzing", cmd_ffuf, [("--url", {"required": True}), ("--wordlist", {"required": True}), ("--mode", {"default": "dir", "choices": ["dir","params","vhost"]}), ("--extensions", {"default": ""})]),
        ("gobuster", "Directory brute-force", cmd_gobuster, [("--url", {"required": True}), ("--wordlist", {"required": True}), ("--extensions", {"default": ""})]),
        ("burp-import", "Import Burp Suite XML", cmd_burp_import, [("--xml-file", {"required": True})]),
        ("caido-import", "Import Caido JSON", cmd_caido_import, [("--json-file", {"required": True})]),
    ]:
        wsp = wc.add_parser(a, help=h)
        if a == "jwt-tool":
            js = wsp.add_subparsers(dest="jwt_action")
            for a2, h2 in [("scan","Analyze JWT"),("attack","Exploit JWT")]:
                jsp = js.add_parser(a2, help=h2)
                jsp.add_argument("--token", required=True)
                if a2 == "attack":
                    jsp.add_argument("--attack-type", default="none", choices=["none","kid","alg","jku","x5u"])
                    jsp.add_argument("--payload-field"); jsp.add_argument("--payload-value")
                    jsp.add_argument("--key")
                jsp.set_defaults(func=cmd_jwt_tool)
        else:
            for arg in extra:
                wsp.add_argument(*arg[:-1] if len(arg) == 3 else (arg[0],), **arg[-1])
            wsp.set_defaults(func=f)

    # -- ad: Active Directory security testing --
    sp = sub.add_parser("ad", help="Active Directory security testing tools")
    ac = sp.add_subparsers(dest="ad_cmd")
    for a, h in [("bloodyad","AD ACL abuse / privilege escalation"),("certipy","AD CS exploitation (ESC1-8)"),
                  ("kerbrute","Kerberos user enumeration / brute-force"),
                  ("ldapnomnom","Anonymous LDAP enumeration"),
                  ("netexec-pre2k","Pre-created computer account check"),
                  ("responder","LLMNR/NBT-NS/mDNS poisoner"),
                  ("evil-winrm","WinRM shell for post-exploitation"),
                  ("impacket","Impacket AD tools (secretsdump, ticketer)")]:
        asp = ac.add_parser(a, help=h)
        if a == "bloodyad":
            bs = asp.add_subparsers(dest="bloodyad_action")
            for ba, bh in [("exec","Execute action"),("dump","Dump objects")]:
                bsp = bs.add_parser(ba, help=bh)
                bsp.add_argument("--server", required=True); bsp.add_argument("--username"); bsp.add_argument("--password")
                bsp.add_argument("--domain"); bsp.add_argument("--dn")
                if ba == "exec": bsp.add_argument("--action", required=True); bsp.add_argument("--filter")
                if ba == "dump": bsp.add_argument("--object-class", default="user")
                bsp.set_defaults(func=cmd_bloodyad)
        elif a == "certipy":
            cs2 = asp.add_subparsers(dest="certipy_action")
            for ca, ch in [("find","Enumerate misconfigs"),("req","Request certificate")]:
                csp2 = cs2.add_parser(ca, help=ch)
                csp2.add_argument("--domain", required=True); csp2.add_argument("--target", required=True)
                csp2.add_argument("--username"); csp2.add_argument("--password")
                if ca == "find": csp2.add_argument("--ca")
                if ca == "req": csp2.add_argument("--template", required=True); csp2.add_argument("--upn"); csp2.add_argument("--dns")
                csp2.set_defaults(func=cmd_certipy)
        elif a == "kerbrute":
            ks = asp.add_subparsers(dest="kerbrute_action")
            for ka, kh in [("userenum","Enumerate users"),("bruteforce","Password brute-force")]:
                ksp = ks.add_parser(ka, help=kh)
                ksp.add_argument("--domain", required=True); ksp.add_argument("--dc-ip")
                if ka == "userenum": ksp.add_argument("--wordlist", required=True)
                if ka == "bruteforce": ksp.add_argument("--user", required=True); ksp.add_argument("--wordlist", required=True)
                ksp.set_defaults(func=cmd_kerbrute)
        elif a == "ldapnomnom":
            asp.add_argument("--target", required=True); asp.add_argument("--base-dn")
            asp.set_defaults(func=cmd_ldapnomnom)
        elif a == "netexec-pre2k":
            asp.add_argument("--domain", required=True); asp.add_argument("--dc-ip", required=True)
            asp.add_argument("--wordlist", required=True)
            asp.set_defaults(func=cmd_netexec_pre2k)
        elif a == "responder":
            rs = asp.add_subparsers(dest="responder_action")
            for ra, rh in [("analyze","Analyze mode (no poisoning)"),("poison","Poison mode (capture hashes)")]:
                rsp = rs.add_parser(ra, help=rh)
                rsp.add_argument("--iface", default="eth0"); rsp.add_argument("--timeout", type=int, default=60)
                rsp.add_argument("--verbose", action="store_true")
                rsp.set_defaults(func=cmd_responder)
        elif a == "evil-winrm":
            esp = asp.add_subparsers(dest="evilwinrm_action")
            for ea, eh in [("connect","Connect to WinRM")]:
                eesp = esp.add_parser(ea, help=eh)
                eesp.add_argument("--ip", required=True); eesp.add_argument("--username"); eesp.add_argument("--password")
                eesp.add_argument("--hash"); eesp.add_argument("--command")
                eesp.set_defaults(func=cmd_evil_winrm)
        elif a == "impacket":
            is_ = asp.add_subparsers(dest="impacket_action")
            for ia, ih in [("secretsdump","Dump SAM/LSA/AD secrets"),
                           ("ticketer","Create golden/silver Kerberos ticket")]:
                isp = is_.add_parser(ia, help=ih)
                isp.add_argument("--target", required=True if ia == "secretsdump" else False)
                isp.add_argument("--username"); isp.add_argument("--password")
                isp.add_argument("--domain"); isp.add_argument("--hash")
                if ia == "secretsdump":
                    isp.add_argument("--just-dc", action="store_true")
                elif ia == "ticketer":
                    isp.add_argument("--ntlm-hash", required=True)
                    isp.add_argument("--domain-sid", required=True)
                    isp.add_argument("--krbtgt-hash")
                    isp.add_argument("--duration-hours", type=int, default=10)
                isp.set_defaults(func=cmd_impacket)

    # -- exploit: exploitation & payload delivery --
    sp = sub.add_parser("exploit", help="Exploitation & payload delivery tools")
    ec = sp.add_subparsers(dest="exploit_cmd")
    for a, h in [("searchsploit","Search Exploit-DB"),("trufflehog","Secret scanning"),
                  ("mitm","Start MITM proxy"),("hexstrike","Launch HexStrike"),
                  ("hydra","Brute-force login (multi-protocol)"),
                  ("john","John the Ripper hash cracking"),
                  ("metasploit","Metasploit module execution"),
                  ("sqlmap","SQL injection detection and exploitation"),
                  ("impacket","Impacket tools (wmiexec, psexec)"),
                  ("hashcat","GPU-accelerated hash cracking"),
                  ("pypykatz","LSASS dump credential parsing")]:
        esp = ec.add_parser(a, help=h)
        if a == "trufflehog":
            ts_ = esp.add_subparsers(dest="truffle_action")
            for ta, th in [("org","Scan GitHub org"),("local","Scan local dir")]:
                tsp2 = ts_.add_parser(ta, help=th)
                if ta == "org": tsp2.add_argument("--org", required=True)
                else: tsp2.add_argument("--path", required=True)
                tsp2.set_defaults(func=cmd_trufflehog)
        elif a == "mitm":
            esp.add_argument("--port", type=int, default=8080); esp.add_argument("--upstream")
            esp.set_defaults(func=cmd_mitm)
        elif a == "hexstrike":
            esp.add_argument("tool_args", nargs=argparse.REMAINDER)
            esp.set_defaults(func=cmd_hexstrike)
        elif a == "searchsploit":
            esp.add_argument("--search", required=True)
            esp.set_defaults(func=lambda a: subprocess.run(["searchsploit", a.search]))
        elif a == "hydra":
            esp.add_argument("--protocol", required=True); esp.add_argument("--target", required=True)
            esp.add_argument("--userlist", required=True); esp.add_argument("--passlist", required=True)
            esp.add_argument("--port", type=int); esp.add_argument("--service")
            esp.set_defaults(func=cmd_hydra)
        elif a == "john":
            esp.add_argument("--hash-file", required=True); esp.add_argument("--wordlist")
            esp.add_argument("--format"); esp.add_argument("--show", action="store_true")
            esp.set_defaults(func=cmd_john)
        elif a == "metasploit":
            msp = esp.add_subparsers(dest="metasploit_action")
            msf_cmds = [("module","Run module with payload"),("resource","Run .rc resource script")]
            for ma, mh in msf_cmds:
                msp2 = msp.add_parser(ma, help=mh)
                if ma == "module":
                    msp2.add_argument("--module", required=True); msp2.add_argument("--payload", required=True)
                    msp2.add_argument("--target", required=True); msp2.add_argument("--lhost"); msp2.add_argument("--lport", type=int, default=4444)
                    msp2.add_argument("--timeout", type=int, default=120)
                elif ma == "resource":
                    msp2.add_argument("--script", required=True); msp2.add_argument("--timeout", type=int, default=300)
                msp2.set_defaults(func=cmd_metasploit)
        elif a == "sqlmap":
            ssp = esp.add_subparsers(dest="sqlmap_action")
            for sa, sh in [("detect","Detect SQL injection"),("exploit","Exploit SQL injection")]:
                ssp2 = ssp.add_parser(sa, help=sh)
                ssp2.add_argument("--url", required=True); ssp2.add_argument("--data"); ssp2.add_argument("--cookie")
                ssp2.add_argument("--level", type=int, default=1); ssp2.add_argument("--risk", type=int, default=1)
                if sa == "exploit":
                    ssp2.add_argument("--os-shell", action="store_true"); ssp2.add_argument("--dump", action="store_true")
                    ssp2.add_argument("--db"); ssp2.add_argument("--table")
                ssp2.set_defaults(func=cmd_sqlmap)
        elif a == "impacket":
            eks = esp.add_subparsers(dest="exploit_impacket_action")
            for ea2, eh2 in [("wmiexec","WMI command execution"),
                             ("psexec","SMB psexec execution"),
                             ("smbexec","SMB exec (no service)")]:
                ekp = eks.add_parser(ea2, help=eh2)
                ekp.add_argument("--target", required=True); ekp.add_argument("--username"); ekp.add_argument("--password")
                ekp.add_argument("--domain"); ekp.add_argument("--hash"); ekp.add_argument("--command", default="whoami")
                ekp.set_defaults(func=cmd_exploit_impacket)
        elif a == "hashcat":
            esp.add_argument("--hash-file", required=True); esp.add_argument("--wordlist")
            esp.add_argument("--hash-mode", type=int, default=0)
            esp.set_defaults(func=cmd_hashcat)
        elif a == "pypykatz":
            esp.add_argument("--dump-file", required=True)
            esp.set_defaults(func=cmd_pypykatz)

    # -- wifi: wireless operations --
    sp = sub.add_parser("wifi", help="Wireless / WiFi operations")
    ws = sp.add_subparsers(dest="wifi_action")
    wifisubs = [("status","Interface status"),("monitor","Toggle monitor mode"),
                ("scan","Scan APs"),("handshake","Capture handshake"),
                ("deauth","Deauth attack"),("crack","Crack handshake"),
                ("heatmap","Heatmap"),("list","Commands"),
                ("eaphammer","Enterprise WiFi attack"),("wirelessgraph","WiFi client graph"),
                ("scan2","BetterCAP network scan"),
                ("handshake-capture","BetterCAP WPA handshake capture"),
                ("connect","Connect to WiFi network"),
                ("netscan","Scan network after connecting"),
                ("arp-spoof","ARP spoofing via BetterCAP"),
                ("proxy","Transparent HTTP proxy via BetterCAP"),
                ("rogue-ap","Rogue AP (airbase-ng/hostapd)"),
                ("sycophant","WPA handshake relay (wpa_sycophant)"),
                ("mitmproxy","Traffic interception (mitmproxy)"),
                ("evil-twin","Full evil twin + captive portal + proxy"),
                ("auto-attack","Auto: handshake → deauth → evil twin → relay")]
    for a, h in wifisubs:
        wsp = ws.add_parser(a, help=h)
        if a == "monitor": wsp.add_argument("state", choices=["on","off"])
        if a in ("handshake","deauth","heatmap","crack","status","monitor","scan",
                 "scan2","handshake-capture","connect","netscan","arp-spoof","proxy",
                 "rogue-ap","sycophant","mitmproxy","evil-twin","auto-attack"):
            wsp.add_argument("--iface")
        if a == "scan": wsp.add_argument("--output"); wsp.add_argument("--duration", type=int, default=15); wsp.add_argument("--band", default="abg", choices=["a","b","g","abg"])
        if a == "handshake": wsp.add_argument("--bssid", required=True); wsp.add_argument("--channel", default="1"); wsp.add_argument("--output")
        if a == "deauth": wsp.add_argument("--bssid", required=True); wsp.add_argument("--client", default="FF:FF:FF:FF:FF:FF"); wsp.add_argument("--count", type=int, default=1)
        if a == "crack": wsp.add_argument("--cap-file", required=True); wsp.add_argument("--wordlist", default="/usr/share/wordlists/rockyou.txt"); wsp.add_argument("--bssid")
        if a == "heatmap": wsp.add_argument("--pcap"); wsp.add_argument("--mac"); wsp.add_argument("--max-hosts", type=int, default=20)
        if a == "eaphammer": wsp.add_argument("--bssid", required=True); wsp.add_argument("--essid", required=True); wsp.add_argument("--iface", required=True); wsp.add_argument("--pmkid", action="store_true"); wsp.add_argument("--captive", action="store_true"); wsp.add_argument("--auth-type", default="WPA2-EAP", choices=["WPA-EAP","WPA2-EAP"])
        if a == "wirelessgraph": wsp.add_argument("--pcap"); wsp.add_argument("--iface")
        if a == "scan2": wsp.add_argument("--timeout", type=int, default=45)
        if a == "handshake-capture": wsp.add_argument("--bssid", required=True); wsp.add_argument("--channel", required=True); wsp.add_argument("--essid"); wsp.add_argument("--timeout", type=int, default=60)
        if a == "connect": wsp.add_argument("--ssid", required=True); wsp.add_argument("--password")
        if a == "netscan": wsp.add_argument("--subnet")
        if a == "arp-spoof": wsp.add_argument("--target", required=True); wsp.add_argument("--gateway")
        if a == "proxy": wsp.add_argument("--port", type=int, default=8080); wsp.add_argument("--sslstrip", nargs="?", const=True, default=True, type=lambda s: str(s).lower() in ("1", "true", "yes", "on"))
        if a == "rogue-ap": wsp.add_argument("--essid", required=True); wsp.add_argument("--channel", default="6"); wsp.add_argument("--bssid")
        if a == "sycophant": wsp.add_argument("--target-bssid"); wsp.add_argument("--target-essid")
        if a == "mitmproxy": wsp.add_argument("--port", type=int, default=8080); wsp.add_argument("--listen-addr", default="0.0.0.0"); wsp.add_argument("--mode", default="transparent", choices=["transparent","regular"])
        if a == "evil-twin": wsp.add_argument("--essid", required=True); wsp.add_argument("--channel", default="6"); wsp.add_argument("--bssid"); wsp.add_argument("--portal-dir"); wsp.add_argument("--proxy-port", type=int, default=8080)
        if a == "auto-attack": wsp.add_argument("--target-bssid", required=True); wsp.add_argument("--target-essid"); wsp.add_argument("--channel")
        wsp.set_defaults(func=cmd_wifi if a not in ("eaphammer","wirelessgraph") else (cmd_eaphammer if a=="eaphammer" else cmd_wireless))

    # -- forensics: DFIR tools --
    sp = sub.add_parser("forensics", help="Digital forensics & incident response")
    fc = sp.add_subparsers(dest="forensics_cmd")
    for a, h, f, extra in [
        ("yara", "YARA scan", cmd_yara, [("--rules", {"required": True}), ("--target", {"required": True})]),
        ("sigma", "Sigma rule converter", cmd_sigma, [("--input-file", {"required": True}), ("--format", {"default": "splunk"})]),
        ("kape", "Windows forensic collection", cmd_kape, [("--target", {"required": True}), ("--targets", {"default": "!BasicCollection"}), ("--module", {"default": ""})]),
        ("semgrep", "SAST scanner", cmd_semgrep, [("--config", {"default": "auto"}), ("--target", {"required": True})]),
    ]:
        fsp = fc.add_parser(a, help=h)
        for arg in extra:
            fsp.add_argument(*arg[:-1] if len(arg) == 3 else (arg[0],), **arg[-1])
        fsp.set_defaults(func=f)

    # -- case: case management --
    sp = sub.add_parser("case", help="Case management (forensics/pentest)")
    cs = sp.add_subparsers(dest="case_action")
    for a, h in [("list","List cases"),("create","Create case"),("info","Case info"),
                  ("close","Close case"),("evidence","Add evidence"),("note","Add note"),
                  ("verify","Verify evidence integrity"),
                  ("scope","Manage scope"),("task","Task checklist"),("goal","Manage analysis goals"),
                  ("strength","Manage strengths"),("weakness","Manage weaknesses"),
                  ("checklist","Checklist (init, list, status update)"),
                  ("export","Export findings (sarif, xccdf)"),
                  ("archive","Archive case"),("unarchive","Unarchive case"),
                  ("delete","Delete case")]:
        csp = cs.add_parser(a, help=h)
        if a != "list": csp.add_argument("--case-id", required=(a in ("info","close","evidence","note","verify","delete","goal","strength","weakness","archive","unarchive","export")))
        if a == "create":
            csp.add_argument("--client")
            csp.add_argument("--case-type", default="pentest",
                choices=["pentest","pentest_web","pentest_external","pentest_internal_ad","pentest_cloud","pentest_physical","ir","forensics","osint"])
            csp.add_argument("--description"); csp.add_argument("--targets"); csp.add_argument("--goals")
        if a == "evidence": csp.add_argument("--file",required=True); csp.add_argument("--category",default="evidence"); csp.add_argument("--description")
        if a == "note": csp.add_argument("--body",required=True)
        if a == "scope":
            ss = csp.add_subparsers(dest="scope_action")
            for sa, sh in [("list","List scope"),("add","Add target"),("remove","Remove target"),("check","Check target")]:
                ssp = ss.add_parser(sa, help=sh)
                if sa != "list": ssp.add_argument("--target",required=True)
                if sa == "add": ssp.add_argument("--out",action="store_true")
                ssp.set_defaults(func=cmd_case)
        if a == "task":
            ts = csp.add_subparsers(dest="task_action")
            for ta, th in [("list","List tasks"),("add","Add task"),("done","Mark done")]:
                tsp = ts.add_parser(ta, help=th)
                if ta == "list": tsp.add_argument("--all",action="store_true")
                if ta == "add": tsp.add_argument("--description",required=True); tsp.add_argument("--priority",default="medium", choices=["low","medium","high"])
                if ta == "done": tsp.add_argument("--task-id",required=True)
                tsp.set_defaults(func=cmd_case)
        if a == "goal":
            gs = csp.add_subparsers(dest="goal_action")
            for ga, gh in [("add","Add goal"),("list","List goals"),("remove","Remove goal")]:
                gsp = gs.add_parser(ga, help=gh)
                if ga == "add": gsp.add_argument("--goal", required=True)
                if ga == "remove": gsp.add_argument("--index", type=int, default=-1)
                gsp.set_defaults(func=cmd_case)
        if a == "strength":
            ss = csp.add_subparsers(dest="strength_action")
            for sa, sh in [("list","List strengths"),("add","Add strength"),("remove","Remove strength")]:
                ssp = ss.add_parser(sa, help=sh)
                if sa == "add": ssp.add_argument("--text", required=True)
                if sa == "remove": ssp.add_argument("--index", type=int, default=-1)
                ssp.set_defaults(func=cmd_case)
        if a == "weakness":
            ws = csp.add_subparsers(dest="weakness_action")
            for wa, wh in [("list","List weaknesses"),("add","Add weakness"),("remove","Remove weakness")]:
                wsp = ws.add_parser(wa, help=wh)
                if wa == "add": wsp.add_argument("--text", required=True)
                if wa == "remove": wsp.add_argument("--index", type=int, default=-1)
                wsp.set_defaults(func=cmd_case)
        if a == "checklist":
            hcs = csp.add_subparsers(dest="checklist_action")
            for hca, hch in [("init","Initialize from template"),("list","Show checklists"),
                             ("status","Update item status"),("delete","Delete instance"),
                             ("from-findings","Build checklist from findings")]:
                hsp = hcs.add_parser(hca, help=hch)
                if hca == "init":
                    hsp.add_argument("--template", default="")
                    hsp.add_argument("--replace", action="store_true")
                if hca == "status":
                    hsp.add_argument("--item-id", required=True)
                    hsp.add_argument("--status", required=True,
                                     choices=["not_started","in_progress","passed","failed","not_applicable"])
                    hsp.add_argument("--instance-id", default="")
                if hca == "delete":
                    hsp.add_argument("--instance-id", required=True)
                if hca == "from-findings":
                    hsp.add_argument("--title", default="")
                    hsp.add_argument("--replace", action="store_true")
                hsp.set_defaults(func=cmd_case)
        if a == "export":
            csp.add_argument("--format", default="sarif", choices=["sarif","xccdf"])
            csp.add_argument("--output", default="")
            csp.add_argument("--no-checklist", action="store_true",
                             help="xccdf only: skip checklist controls")
        csp.set_defaults(func=cmd_case)

    # -- ir: incident response workflow --
    sp = sub.add_parser("ir", help="Incident response workflow (timeline, TTPs, containment)")
    irs = sp.add_subparsers(dest="ir_action")
    for a, h in [("timeline","Manage IR timeline"),("ttp","Log MITRE ATT&CK TTPs"),
                  ("containment","Containment/remediation steps")]:
        irsp = irs.add_parser(a, help=h)
        irsp.add_argument("--case-id", required=True)
        if a == "timeline":
            its = irsp.add_subparsers(dest="ir_timeline_action")
            for ta, th in [("add","Add event"),("list","List events")]:
                tsp = its.add_parser(ta, help=th)
                if ta == "add":
                    tsp.add_argument("--timestamp", required=True); tsp.add_argument("--event", required=True)
                    tsp.add_argument("--severity", default="info", choices=["info","low","medium","high","critical"])
                    tsp.add_argument("--source")
                tsp.set_defaults(func=cmd_ir)
        elif a == "ttp":
            its = irsp.add_subparsers(dest="ir_ttp_action")
            for ta, th in [("add","Log TTP"),("list","List TTPs")]:
                tsp = its.add_parser(ta, help=th)
                if ta == "add":
                    tsp.add_argument("--tactic", required=True); tsp.add_argument("--technique", required=True)
                    tsp.add_argument("--technique-id"); tsp.add_argument("--notes")
                tsp.set_defaults(func=cmd_ir)
        elif a == "containment":
            cs_ = irsp.add_subparsers(dest="ir_containment_action")
            for ca, ch in [("add","Add step"),("list","List steps"),("update","Update status")]:
                csp2 = cs_.add_parser(ca, help=ch)
                if ca == "add":
                    csp2.add_argument("--action", required=True); csp2.add_argument("--status", default="pending")
                    csp2.add_argument("--owner")
                if ca == "update":
                    csp2.add_argument("--containment-id", required=True); csp2.add_argument("--status", required=True)
                csp2.set_defaults(func=cmd_ir)

    # -- playbook: runbook engine --
    sp = sub.add_parser("playbook", help="Run YAML playbooks / runbooks")
    pls = sp.add_subparsers(dest="playbook_action")
    for a, h in [("list","List playbooks"),("show","Show playbook YAML"),("run","Run playbook")]:
        plsp = pls.add_parser(a, help=h)
        if a in ("show","run"): plsp.add_argument("--playbook","-p",required=True)
        if a == "run":
            plsp.add_argument("--target","-t",required=True); plsp.add_argument("--case-id","-c",default="")
            plsp.add_argument("--vars","-V",default=""); plsp.add_argument("--verbose","-v",action="store_true")
        plsp.set_defaults(func=cmd_playbook)

    # -- report: output & reporting --
    sp = sub.add_parser("report", help="Reporting & output generation")
    rp = sp.add_subparsers(dest="report_cmd")
    for a, h in [("nmap","From nmap XML"),("nuclei","From nuclei JSON"),
                  ("engagement","HTML + Markdown engagement report"),
                  ("obsidian-report","Obsidian template-matching report"),
                  ("timeline","Case timeline HTML"),
                  ("obsidian","Obsidian vault bridge")]:
        rsp = rp.add_parser(a, help=h)
        if a == "obsidian":
            obs = rsp.add_subparsers(dest="obsidian_action")
            for oa, oh in [("status","Vault status"),("note","Write note"),("list","List notes")]:
                osp = obs.add_parser(oa, help=oh)
                if oa == "note": osp.add_argument("--title",required=True); osp.add_argument("--content",required=True); osp.add_argument("--tags")
                osp.set_defaults(func=cmd_obsidian)
        else:
            rsp.add_argument("--case-id", required=(a in ("engagement","timeline","obsidian-report")))
            if a == "obsidian-report":
                rsp.add_argument("--formats", default="md,html,docx,pdf",
                                 help="Comma-separated output formats (md,html,docx,pdf)")
            if a == "nmap": rsp.add_argument("--xml", required=True)
            if a == "nuclei": rsp.add_argument("--json", required=True)
            if a == "timeline": rsp.add_argument("--output","-o",default="")
            rsp.set_defaults(func=cmd_report)

    # -- findings: structured findings --
    sp = sub.add_parser("findings", help="Structured findings per case")
    fs = sp.add_subparsers(dest="findings_action")
    for a, h in [("list","List findings"),("add","Add finding"),("show","Show finding"),
                  ("close","Close finding"),("import-nuclei","Import from nuclei JSON"),
                  ("link-evidence","Link evidence file to finding"),
                  ("unlink-evidence","Unlink evidence from finding")]:
        fsp = fs.add_parser(a, help=h)
        fsp.add_argument("--case-id",required=True)
        if a == "list": fsp.add_argument("--severity"); fsp.add_argument("--status")
        if a == "add":
            fsp.add_argument("--title",required=True); fsp.add_argument("--severity",default="medium", choices=["info","low","medium","high","critical"])
            fsp.add_argument("--description","-d",default=""); fsp.add_argument("--remediation",default=""); fsp.add_argument("--source",default="manual")
        if a in ("show","close"): fsp.add_argument("--finding-id","-f",required=True)
        if a == "import-nuclei": fsp.add_argument("--path",required=True)
        if a in ("link-evidence","unlink-evidence"):
            fsp.add_argument("--finding-id","-f",required=True)
            fsp.add_argument("--evidence", nargs="+", required=True,
                help="Evidence filename(s) to link/unlink")
        fsp.set_defaults(func=cmd_findings)

    # -- tools: tool index & launcher --
    sp = sub.add_parser("tools", help="Tool discovery & launcher")
    ts = sp.add_subparsers(dest="tools_action")
    for a, h in [("list","Summary"),("list-system","By category"),("list-custom","/share/tools"),
                  ("list-forensic","Forensic tools"),("list-pentest","Pentest tools"),
                  ("list-wifi","WiFi tools"),("search","Search"),("info","Show info"),("run","Run tool")]:
        tsp = ts.add_parser(a, help=h)
        if a in ("search",): tsp.add_argument("keyword")
        if a in ("info","run"): tsp.add_argument("tool_name")
        if a == "run": tsp.add_argument("tool_args", nargs=argparse.REMAINDER)
        tsp.set_defaults(func=cmd_tools)

    # -- features: MCP lightweight feature-group toggles --
    sp = sub.add_parser("features", help="MCP feature-group toggles (lightweight MCP)")
    fs = sp.add_subparsers(dest="features_action")
    for a, h in [("list", "Show groups & enabled state"),
                 ("enable", "Enable one or more groups"),
                 ("disable", "Disable one or more groups"),
                 ("on", "Enable all groups"),
                 ("off", "Disable all groups"),
                 ("tool-add", "Per-tool override: force a tool prefix on"),
                 ("tool-rm", "Per-tool override: force a tool prefix off"),
                 ("allowlist", "Show effective MCP allowlist"),
                 ("manifest", "Write MCP_FEATURES.md pre-startup manifest"),
                 ("index", "Refresh tool-name index from cc_mcp_server")]:
        fsp = fs.add_parser(a, help=h)
        fsp.add_argument("names", nargs="*", help="Group names or tool prefixes")
        fsp.set_defaults(func=cmd_features)
    sp.set_defaults(func=cmd_features)

    # -- infra: infrastructure management --
    sp = sub.add_parser("infra", help="Infrastructure management")
    ic = sp.add_subparsers(dest="infra_cmd")
    for a, h in [("vm","VM management"),("arsenal","Arsenal tool mgmt"),
                  ("profile","Environment profiles"),("notify","Webhook notifications"),
                  ("remote","SSH remote execution"),
                  ("hexstrike","HexStrike AI agent management"),
                  ("ai-setup","AI infra: SSH tunnel + ollama + opencode config"),
                  ("chisel","Chisel tunnel client/server"),
                  ("ligolo","Ligolo tunnel/proxy"),
                  ("linpeas","LinPEAS privilege escalation check")]:
        isp = ic.add_parser(a, help=h)
        if a == "vm":
            vs = isp.add_subparsers(dest="vm_action")
            for va, vh in [("list","List VMs"),("create-vbox","Create VirtualBox VM"),("create-kvm","Create KVM VM")]:
                vsp = vs.add_parser(va, help=vh)
                if va == "create-vbox": vsp.add_argument("--name",default="kali"); vsp.add_argument("--memory",type=int,default=2048); vsp.add_argument("--vram",type=int,default=128); vsp.add_argument("--disk",type=int,default=80000); vsp.add_argument("--iso"); vsp.add_argument("--rdp-port",type=int); vsp.add_argument("--vnc-password"); vsp.add_argument("--no-start",action="store_true")
                if va == "create-kvm": vsp.add_argument("--hostname",default="ubuntu"); vsp.add_argument("--domain",default="private"); vsp.add_argument("--url"); vsp.add_argument("--os-variant",default="ubuntu-stable-latest"); vsp.add_argument("--size",default="40G"); vsp.add_argument("--ram",type=int,default=2048); vsp.add_argument("--uid"); vsp.add_argument("--ssh-key")
                vsp.set_defaults(func=cmd_vm_create_vbox if va=="create-vbox" else (cmd_vm_create_kvm if va=="create-kvm" else cmd_vm_list))
        elif a == "arsenal":
            ars = isp.add_subparsers(dest="action")
            for aa, ah in [("list","List"),("filter","Filter"),("case","Set case type"),("setup","Auto-detect path"),("run","Run tool"),("vault","Scan Obsidian vault for tool references")]:
                asp = ars.add_parser(aa, help=ah)
                if aa == "list": asp.add_argument("--filter-by-tag")
                if aa == "filter": asp.add_argument("keyword",nargs="?"); asp.add_argument("--tag")
                if aa == "case": asp.add_argument("case_type",nargs="?",default="web_application")
                if aa == "run": asp.add_argument("--tool-name","-t",required=True); asp.add_argument("tool_args",nargs=argparse.REMAINDER)
                if aa == "vault":
                    asp.set_defaults(vault_action="list")
                    vas = asp.add_subparsers(dest="vault_action")
                    for va, vh in [("list","List vault tool references"),("generate","Generate arsenal cheat files from vault"),("info","Show commands for a vault tool")]:
                        vsp = vas.add_parser(va, help=vh)
                        if va == "info": vsp.add_argument("tool_name",help="Tool name to look up")
                        vsp.set_defaults(func=cmd_arsenal)
                asp.set_defaults(func=cmd_arsenal)
        elif a == "profile":
            ps_ = isp.add_subparsers(dest="profile_action")
            for pa, ph in [("list","List"),("show","Show"),("apply","Apply")]:
                psp = ps_.add_parser(pa, help=ph)
                if pa != "list": psp.add_argument("profile_name",nargs="?",default="default")
                psp.set_defaults(func=cmd_profile)
        elif a == "notify":
            ns = isp.add_subparsers(dest="notify_action")
            for na, nh in [("show","Show config"),("set","Set webhook URL"),("test","Send test")]:
                nsp = ns.add_parser(na, help=nh)
                if na == "set": nsp.add_argument("key", choices=["slack_webhook","discord_webhook","telegram_token","telegram_chat_id"]); nsp.add_argument("value")
                if na == "test": nsp.add_argument("--message","-m",default="Test notification"); nsp.add_argument("--targets","-t")
                nsp.set_defaults(func=cmd_notify_config)
        elif a == "remote":
            rs_ = isp.add_subparsers(dest="remote_action")
            for ra, rh in [("exec","Run command"),("tool","Run tool")]:
                rsp = rs_.add_parser(ra, help=rh)
                rsp.add_argument("--host",required=True); rsp.add_argument("--user",default="root")
                rsp.add_argument("--port",type=int,default=22); rsp.add_argument("--key",default=""); rsp.add_argument("--timeout",type=int,default=60)
                if ra == "exec": rsp.add_argument("--command","-c",required=True)
                if ra == "tool": rsp.add_argument("--tool","-t",required=True); rsp.add_argument("tool_args",nargs=argparse.REMAINDER)
                rsp.set_defaults(func=cmd_remote)
        elif a == "hexstrike":
            hxs = isp.add_subparsers(dest="hexstrike_action")
            for ha, hh in [("start","Start HexStrike server in tmux"),("stop","Stop HexStrike server"),
                            ("status","Check if HexStrike is running"),
                            ("opencode","Launch opencode (connects via MCP)")]:
                hsp = hxs.add_parser(ha, help=hh)
                if ha == "start": hsp.add_argument("--port",type=int,default=8989)
                hsp.set_defaults(func=cmd_hexstrike)
        elif a == "chisel":
            css = isp.add_subparsers(dest="chisel_action")
            for ca, ch in [("client","Start client tunnel"),("server","Start server")]:
                csp = css.add_parser(ca, help=ch)
                if ca == "client":
                    csp.add_argument("--server", required=True); csp.add_argument("--remote-port", type=int, default=8080)
                    csp.add_argument("--local-port", type=int, default=1080); csp.add_argument("--reverse", action="store_true")
                elif ca == "server":
                    csp.add_argument("--port", type=int, default=8080)
                    csp.add_argument("--no-socks", action="store_true")
                csp.set_defaults(func=cmd_chisel)
        elif a == "ligolo":
            lgs = isp.add_subparsers(dest="ligolo_action")
            for la, lh in [("agent","Start agent connection"),("proxy","Start proxy listener")]:
                lgp = lgs.add_parser(la, help=lh)
                if la == "agent": lgp.add_argument("--server", required=True); lgp.add_argument("--port", type=int, default=11601)
                if la == "proxy": lgp.add_argument("--port", type=int, default=11601)
                lgp.set_defaults(func=cmd_ligolo)
        elif a == "linpeas":
            isp.add_argument("--target-host"); isp.add_argument("--target-user"); isp.add_argument("--target-pass")
            isp.add_argument("--local-path")
            isp.set_defaults(func=cmd_linpeas)
        elif a == "ai-setup":
            ais = isp.add_subparsers(dest="ai_action")
            for aa, ah in [("up","Start AI tunnel + ollama + config"),
                           ("down","Stop AI tunnel"),
                           ("status","Check AI tunnel status"),
                           ("check-gpu","Check GPU availability on remote")]:
                asp = ais.add_parser(aa, help=ah)
                if aa in ("up", "check-gpu"):
                    asp.add_argument("--jump-host", default="automation")
                    asp.add_argument("--jump-user", default="jeff")
                    asp.add_argument("--target-host", default="10.42.0.21")
                    asp.add_argument("--target-user", default="jeff")
                    asp.add_argument("--model", default="qwen2.5:3b")
                    asp.add_argument("--gpu-layers", type=int, default=10,
                        help="GPU layers to offload (0=auto/remove override, N=force N layers on GPU, rest on CPU+RAM)")
                    asp.add_argument("--local-port", type=int, default=11434)
                    asp.add_argument("--ollama-port", type=int, default=11434)
                asp.set_defaults(func=cmd_infra_ai_setup)

    # -- kerberos: time sync, krb5 config, ticket management --
    sp = sub.add_parser("kerberos", help="Kerberos configuration & ticket management")
    ks = sp.add_subparsers(dest="kerberos_cmd")
    for a, h in [("time-sync","Sync clock with KDC/NTP server"),
                 ("config","Generate krb5.conf for a domain"),
                 ("kinit","Obtain TGT"),
                 ("klist","List ticket cache"),
                 ("kdestroy","Destroy all tickets"),
                 ("setup","Full setup: time sync → config → kinit")]:
        ksp = ks.add_parser(a, help=h)
        if a in ("time-sync",):
            ksp.add_argument("--server", default="")
        elif a == "config":
            ksp.add_argument("--domain", required=True); ksp.add_argument("--kdc", required=True)
            ksp.add_argument("--admin-server"); ksp.add_argument("--output")
        elif a == "kinit":
            ksp.add_argument("--principal", required=True); ksp.add_argument("--password")
            ksp.add_argument("--keytab"); ksp.add_argument("--realm"); ksp.add_argument("--lifetime", default="24h")
        elif a == "setup":
            ksp.add_argument("--domain", required=True); ksp.add_argument("--kdc", required=True)
            ksp.add_argument("--username"); ksp.add_argument("--password")
            ksp.add_argument("--skip-time-sync", action="store_true")
        ksp.set_defaults(func=cmd_kerberos)

    # -- bloodhound: AD relationship ingestor --
    sp = sub.add_parser("bloodhound", help="BloodHound.py AD relationship ingestor")
    sp.add_argument("--domain", required=True); sp.add_argument("--username", required=True)
    sp.add_argument("--password", required=True); sp.add_argument("--dc-ip")
    sp.add_argument("--dns-server"); sp.add_argument("--collection-method", default="All")
    sp.set_defaults(func=cmd_bloodhound)

    # -- nmap: structured scanning pipeline --
    sp = sub.add_parser("nmap", help="Structured Nmap scanning pipeline")
    ns = sp.add_subparsers(dest="nmap_cmd")
    for a, h in [("init-tcp","Initial TCP top-ports SYN scan"),
                 ("init-udp","Initial UDP top-ports scan"),
                 ("full-tcp","Full TCP port scan 1-65535"),
                 ("full-ack","Full TCP ACK scan (firewall mapping)"),
                 ("service-version","Service/version detection on open ports"),
                 ("versions-tcp","Intense TCP version detection"),
                 ("versions-udp","Intense UDP version detection"),
                 ("vuln","Vulnerability script scan"),
                 ("pipeline","Full nmaptest.sh pipeline"),
                 ("parse","Parse all .nmap output files"),
                 ("custom","Run nmap with custom args")]:
        nsp = ns.add_parser(a, help=h)
        nsp.add_argument("--target", required=True)
        nsp.add_argument("--output-dir")
        nsp.add_argument("--case-id", help="Case ID to link scan results (saves to case scans/ + evidence)")
        if a == "init-tcp": nsp.add_argument("--top-ports", type=int, default=1000)
        if a == "init-udp": nsp.add_argument("--top-ports", type=int, default=1000)
        if a == "service-version": nsp.add_argument("--ports")
        if a == "versions-tcp": nsp.add_argument("--ports")
        if a == "versions-udp": nsp.add_argument("--ports")
        if a == "vuln": nsp.add_argument("--ports")
        if a == "custom": nsp.add_argument("--args", required=True); nsp.add_argument("--log-name", default="custom")
        if a == "pipeline": nsp.add_argument("--skip-full", action="store_true")
        nsp.set_defaults(func=cmd_nmap)

    # -- browser: LevelDB/IndexedDB forensics --
    sp = sub.add_parser("browser", help="Browser database forensics (LevelDB/IndexedDB)")
    bs = sp.add_subparsers(dest="browser_cmd")
    for a, h in [("leveldb","Analyze LevelDB directory"),
                 ("chrome-profile","Analyze full Chrome/Chromium profile"),
                 ("extract-sensitive","Extract credentials/tokens/JWTs from LevelDB")]:
        bsp = bs.add_parser(a, help=h)
        bsp.add_argument("--path", required=True)
        bsp.set_defaults(func=cmd_browser)

    # -- dns: resolution & monitoring --
    sp = sub.add_parser("dns", help="DNS resolution & monitoring")
    dsp = sp.add_subparsers(dest="dns_action")
    for a, h in [("resolve","One-shot resolution"),("monitor","Start monitoring"),
                  ("list","List active monitors"),("history","Show resolution history"),
                  ("remove","Stop & remove monitor"),("track","Quick alias for monitor")]:
        dp = dsp.add_parser(a, help=h)
        if a in ("resolve","monitor","track","history","remove"):
            dp.add_argument("domain", help="Domain name")
        if a in ("resolve","monitor","track"):
            dp.add_argument("--types", default="", help="Comma-separated record types (default: all)")
        if a in ("monitor","track"):
            dp.add_argument("--interval", type=int, default=300, help="Check interval in seconds")
            dp.add_argument("--duration", type=int, default=0, help="Total duration in seconds (0=unlimited)")
        if a == "history":
            dp.add_argument("--limit", type=int, default=50, help="Max entries to show")
        dp.set_defaults(func=cmd_dns)

    # -- ref: reference data --
    sp = sub.add_parser("ref", help="Reference data (LDAP filters, event IDs, CVEs)")
    rs2 = sp.add_subparsers(dest="ref_action")
    for a, h in [("ldap-filters","LDAP query filters for AD"),("event-ids","Windows Event ID reference"),("cve-list","Curated CVE reference")]:
        rsp2 = rs2.add_parser(a, help=h)
        rsp2.add_argument("keyword", nargs="?", default="")
        rsp2.set_defaults(func=cmd_ref)

    # -- binary: binary exploitation analysis --
    sp = sub.add_parser("binary", help="Binary exploitation analysis (ai-bug-bounty)")
    bc = sp.add_subparsers(dest="binary_action")
    for a, h in [("check","Check available RE/exploit tools"),
                 ("analyze","Full binary analysis"),
                 ("summary","Concise AI-friendly summary"),
                 ("vulns","Vulnerability scan"),
                 ("checksec","Security mitigation check"),
                 ("gadgets","Find ROP gadgets"),
                 ("exploit","Exploit strategy generation"),
                 ("fmtstr","Format string analysis"),
                 ("heap","Heap analysis"),
                 ("net","Network service analysis"),
                 ("angr","Symbolic execution (angr)"),
                 ("fuzz","Generate fuzzing harness"),
                 ("strings","Extract strings"),
                 ("funcs","List functions"),
                 ("cyclic","Generate cyclic pattern"),
                 ("pattern","Find offset in pattern")]:
        csp = bc.add_parser(a, help=h)
        csp.add_argument("subargs", nargs=argparse.REMAINDER)
        csp.set_defaults(func=cmd_binary)

    # -- history: command audit log --
    sp = sub.add_parser("history", help="Command audit log")
    hs = sp.add_subparsers(dest="history_action")
    for a, h in [("recent","Recent commands"),("search","Search history"),("summary","History stats")]:
        hsp = hs.add_parser(a, help=h)
        if a == "recent": hsp.add_argument("--limit",type=int,default=25)
        if a == "search": hsp.add_argument("query")
        hsp.set_defaults(func=cmd_history)

    # -- bb: bug bounty dashboard (HackerOne / Bugcrowd) --
    sp = sub.add_parser("bb", help="Bug bounty dashboard (HackerOne / Bugcrowd)")
    bs = sp.add_subparsers(dest="bb_action")
    for a, h in [("list","List cached programs"),
                 ("get","Show a cached program with scope"),
                 ("discover","Discover public HackerOne programs"),
                 ("sync","Refresh all cached programs"),
                 ("sync-program","Fetch + cache one program"),
                 ("import-case","Import a program as a case + assets"),
                 ("reports","List my reports (HackerOne, or YesWeHack with --programs)")]:
        bsp = bs.add_parser(a, help=h)
        bsp.add_argument("--platform", default="", help="hackerone/bugcrowd/yeswehack/intigriti/immunefi")
        bsp.add_argument("--slug", default="", help="program handle/code")
        if a == "list":
            bsp.add_argument("--search", default="")
        if a in ("get",):
            bsp.add_argument("--refresh", action="store_true")
        if a in ("discover",):
            bsp.add_argument("--limit", type=int, default=100)
        if a == "reports":
            bsp.add_argument("--limit", type=int, default=20)
            bsp.add_argument("--programs", default="",
                             help="comma-separated program slugs (required for yeswehack)")
        if a in ("sync",):
            bsp.add_argument("--limit", type=int, default=0)
            bsp.add_argument("--no-refresh", action="store_true")
        if a == "import-case":
            bsp.add_argument("--case-id", default="")
            bsp.add_argument("--client", default="")
            bsp.add_argument("--customer-id", default="")
            bsp.add_argument("--no-assets", action="store_true")
        bsp.set_defaults(func=cmd_bb)
    bsc = bs.add_parser("creds", help="Manage platform API credentials")
    bscs = bsc.add_subparsers(dest="bb_creds_action")
    for ca, ch in [("set","Store encrypted credentials"),("list","Show credential status"),("clear","Remove credentials")]:
        csp = bscs.add_parser(ca, help=ch)
        csp.add_argument("--platform", default="", help="hackerone/bugcrowd/yeswehack/intigriti/immunefi")
        if ca == "set":
            csp.add_argument("--identifier", default="", help="HackerOne API token identifier (name)")
            csp.add_argument("--token", default="", help="HackerOne API token value")
            csp.add_argument("--client-id", default="", help="Bugcrowd OAuth2 client ID")
            csp.add_argument("--client-secret", default="", help="Bugcrowd OAuth2 client secret")
            csp.add_argument("--oauth", action="store_true",
                             help="Store Bugcrowd OAuth2 client_id/client_secret (customer-only API)")
        csp.set_defaults(func=cmd_bb)

    args = p.parse_args()
    if not getattr(args, "func", None):
        p.print_help()
        sys.exit(1)
    cmd = getattr(args, "command", "?")
    if cmd not in ("dashboard", "monitor", "help"):
        hl = HistoryLogger()
        try:
            hl.log(command=cmd, args=vars(args),
                   case_id=getattr(args, "case_id", ""),
                   target=getattr(args, "target", ""))
        except Exception:
            pass
    args.func(args)


if __name__ == "__main__":
    main()
