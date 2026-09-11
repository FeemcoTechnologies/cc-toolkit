"""MCP server exposing Kali Command Center tools as MCP-callable functions.

Register in opencode.json alongside hexstrike, configure timeout via env:
{
  "mcp": {
    "cc-toolkit": {
      "type": "local",
      "command": ["python3", "/path/to/cc_mcp_server.py"],
      "environment": { "CC_MCP_TIMEOUT": "600" },
      "enabled": true
    }
  }
}

Optional env vars:
  CC_MCP_TIMEOUT   timeout in seconds for thread-pool and subprocess calls (default: 300)
  CC_MCP_TOOLS     comma-separated tool-name prefixes to expose (default: all).
                   e.g. "bb,case,rules,web" keeps only tools whose names start
                   with bb/case/rules/web; "*" or empty keeps everything.

Feature toggles (lightweight MCP):
  By default the exposed tool set is taken from the "features" block in
  config.json (~/.config/kali-command-center/config.json), so it can be
  managed with `cc features` or the web dashboard (System -> Features) without
  editing opencode.json. Env CC_MCP_TOOLS always overrides the config.

  Manage from the CLI:
    cc features                 # list groups + state
    cc features disable ad      # turn a group off
    cc features tool-add caido  # per-tool override: force a prefix on
    cc features tool-rm burp    # per-tool override: force a prefix off

  `doctor_run` (capability/health check) is always exposed.
  The full tool-name index is written to cc_tool_index.json at startup.
"""

import asyncio
import datetime
import json
import os
import subprocess
import sys
import uuid
import threading
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from mcp.server.fastmcp import FastMCP
from modules.config import TOOLS_DIR, SCRIPTS_DIR, CASES_DIR, CC_DIR
from modules.case_manager import CaseManager
from modules.findings_db import FindingsDB
from modules.checklist_manager import list_templates as list_checklist_templates, get_template_source

mcp = FastMCP("CC Toolkit")

_TIMEOUT = int(os.environ.get("CC_MCP_TIMEOUT", "300"))

_TOOLS_DIR = os.environ.get("CC_TOOLS_DIR", str(TOOLS_DIR))


def _run(fn, *args, **kwargs):
    """Run a function directly (no thread pool — fast MCP startup)."""
    return fn(*args, **kwargs)


async def _run_async(fn, *args, **kwargs):
    """Run a blocking function in a worker thread so the MCP event loop stays responsive.

    Use this instead of _run() for tools that can take minutes (scans, attacks,
    monitoring). FastMCP runs async tool functions with await, so the loop keeps
    servicing other requests while the blocking call runs in a thread.
    """
    return await asyncio.to_thread(fn, *args, **kwargs)


def _path_is_inside(child: Path, parent: Path) -> bool:
    """Check if child path is inside parent directory (cross-platform)."""
    try:
        child = child.resolve()
        parent = parent.resolve()
        return os.path.commonpath([str(child), str(parent)]) == str(parent)
    except (ValueError, OSError):
        return False


def _require(val: str, name: str = "value") -> None:
    """Validate that a string argument is non-empty. Raises ValueError if not."""
    if not val or not val.strip():
        raise ValueError(f"'{name}' must not be empty")


def _case_dir(case_id: str) -> Path:
    """Resolve a validated case directory under CASES_DIR. Raises ValueError on traversal."""
    import re as _re
    if not _re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", case_id or ""):
        raise ValueError(f"Invalid case_id: {case_id!r}")
    return CASES_DIR / case_id


# ---------------------------------------------------------------------------
# AD Security
# ---------------------------------------------------------------------------
@mcp.tool()
def ad_certipy_find(domain: str, target: str, username: str = "",
                    password: str = "", ca: str = "") -> str:
    """
    Enumerate AD Certificate Services misconfigurations (ESC1-ESC8) on a domain controller.
    Phase: Active Directory Security
    Related: ad_certipy_request, ad_bloodyad_exec, ad_bloodyad_dump, ad_kerbrute_userenum, ad_ldapnomnom_enum, ad_netexec_pre2k, ad_kerbrute_bruteforce
    """
    from modules.tool_wrappers import certipy_find
    return _fmt(_run(certipy_find, domain, target, username=username, password=password, ca=ca))


@mcp.tool()
def ad_certipy_request(domain: str, target: str, template: str,
                       username: str = "", password: str = "",
                       upn: str = "", dns: str = "") -> str:
    """
    Request a certificate via Certipy (ESC1/ESC3 attack).
    Phase: Active Directory Security
    Related: ad_certipy_find, ad_bloodyad_exec, ad_bloodyad_dump, ad_kerbrute_userenum, ad_ldapnomnom_enum, ad_netexec_pre2k, ad_kerbrute_bruteforce
    """
    from modules.tool_wrappers import certipy_request
    return _fmt(_run(certipy_request, domain, target, template, username=username,
                     password=password, upn=upn, dns=dns))


@mcp.tool()
def ad_bloodyad_exec(server: str, action: str, username: str = "",
                     password: str = "", domain: str = "",
                     target_dn: str = "", ldap_filter: str = "",
                     attribute: str = "", value: str = "") -> str:
    """
    Execute a BloodyAD action (add/remove ACL, modify object, etc) against an AD server.
    Phase: Active Directory Security
    Related: ad_certipy_find, ad_certipy_request, ad_bloodyad_dump, ad_kerbrute_userenum, ad_ldapnomnom_enum, ad_netexec_pre2k, ad_kerbrute_bruteforce
    """
    from modules.tool_wrappers import bloodyad_exec
    return _fmt(_run(bloodyad_exec, server, action, username=username, password=password,
                     domain=domain, target_dn=target_dn, ldap_filter=ldap_filter,
                     attribute=attribute, value=value))


@mcp.tool()
def ad_bloodyad_dump(server: str, username: str = "", password: str = "",
                     domain: str = "", object_class: str = "user") -> str:
    """
    Dump AD objects (users, computers, groups) via BloodyAD.
    Phase: Active Directory Security
    Related: ad_certipy_find, ad_certipy_request, ad_bloodyad_exec, ad_kerbrute_userenum, ad_ldapnomnom_enum, ad_netexec_pre2k, ad_kerbrute_bruteforce
    """
    from modules.tool_wrappers import bloodyad_dump
    return _fmt(_run(bloodyad_dump, server, username=username, password=password,
                     domain=domain, object_class=object_class))


@mcp.tool()
def ad_kerbrute_userenum(domain: str, wordlist: str,
                         dc_ip: str = "") -> str:
    """
    Enumerate valid AD usernames via Kerberos pre-authentication.
    Phase: Active Directory Security
    Related: ad_certipy_find, ad_certipy_request, ad_bloodyad_exec, ad_bloodyad_dump, ad_ldapnomnom_enum, ad_netexec_pre2k, ad_kerbrute_bruteforce
    """
    from modules.tool_wrappers import kerbrute_userenum
    return _fmt(_run(kerbrute_userenum, domain, wordlist, dc_ip=dc_ip))


@mcp.tool()
def ad_ldapnomnom_enum(target: str, base_dn: str = "") -> str:
    """
    Perform anonymous LDAP enumeration against a domain controller.
    Phase: Active Directory Security
    Related: ad_certipy_find, ad_certipy_request, ad_bloodyad_exec, ad_bloodyad_dump, ad_kerbrute_userenum, ad_netexec_pre2k, ad_kerbrute_bruteforce
    """
    from modules.tool_wrappers import ldapnomnom_enum
    return _fmt(_run(ldapnomnom_enum, target, base_dn=base_dn))


@mcp.tool()
def ad_netexec_pre2k(domain: str, dc_ip: str, wordlist: str) -> str:
    """
    Check for pre-created computer accounts via NetExec (pre2k attack).
    Phase: Active Directory Security
    Related: ad_certipy_find, ad_certipy_request, ad_bloodyad_exec, ad_bloodyad_dump, ad_kerbrute_userenum, ad_ldapnomnom_enum, ad_kerbrute_bruteforce
    """
    from modules.tool_wrappers import netexec_pre2k
    return _fmt(_run(netexec_pre2k, domain, dc_ip, wordlist))


@mcp.tool()
def ad_kerbrute_bruteforce(domain: str, user: str, wordlist: str) -> str:
    """
    Brute-force password for a single AD user via Kerberos.
    Phase: Active Directory Security
    Related: ad_certipy_find, ad_certipy_request, ad_bloodyad_exec, ad_bloodyad_dump, ad_kerbrute_userenum, ad_ldapnomnom_enum, ad_netexec_pre2k
    """
    from modules.tool_wrappers import kerbrute_bruteforce
    return _fmt(_run(kerbrute_bruteforce, domain, user, wordlist))


# ---------------------------------------------------------------------------
# Web Application
# ---------------------------------------------------------------------------
@mcp.tool()
def web_jwt_scan(token: str) -> str:
    """
    Analyze a JWT token for vulnerabilities (alg none, weak signing, etc).
    Phase: Web Application Testing
    Related: web_jwt_attack, web_graphw00f_scan, web_nuclei_scan
    """
    from modules.tool_wrappers import jwt_tool_scan
    return _fmt(_run(jwt_tool_scan, token))


@mcp.tool()
def web_jwt_attack(token: str, attack: str = "none",
                   payload_field: str = "", payload_value: str = "",
                   signing_key: str = "") -> str:
    """
    Exploit a JWT with a specific attack (none, kid, alg confusion, etc).
    Phase: Web Application Testing
    Related: web_jwt_scan, web_graphw00f_scan, web_nuclei_scan
    """
    from modules.tool_wrappers import jwt_tool_attack
    return _fmt(_run(jwt_tool_attack, token, attack, payload_field=payload_field,
                     payload_value=payload_value, signing_key=signing_key))


@mcp.tool()
def web_graphw00f_scan(target: str) -> str:
    """
    Fingerprint a GraphQL endpoint to identify engine and version.
    Phase: Web Application Testing
    Related: web_jwt_scan, web_jwt_attack, web_nuclei_scan
    """
    from modules.tool_wrappers import graphw00f_scan
    return _fmt(_run(graphw00f_scan, target))


@mcp.tool()
def web_nuclei_scan(target: str, template: str = "") -> str:
    """
    Run Nuclei vulnerability scanner against a target with optional template filter.
    Phase: Web Application Testing
    Related: web_jwt_scan, web_jwt_attack, web_graphw00f_scan
    """
    from modules.tool_wrappers import nuclei_scan
    return _fmt(_run(nuclei_scan, target, template=template), fmt="nuclei")


# ---------------------------------------------------------------------------
# WiFi / Wireless
# ---------------------------------------------------------------------------
@mcp.tool()
async def wifi_eaphammer_attack(bssid: str, essid: str, iface: str,
                                auth_type: str = "WPA2-EAP",
                                pmkid: bool = False,
                                captive: bool = False) -> str:
    """
    Execute EAPHammer enterprise WiFi attack (PMKID capture, captive portal, downgrade).
    Phase: Wireless Pentesting
    Related: wifi_scan, wifi_deauth, wifi_handshake_capture, wifi_connect, wifi_network_scan, wifi_arp_spoof, wifi_proxy, wifi_rogue_ap, wifi_sycophant_relay, wifi_mitmproxy, wifi_evil_twin, wifi_auto_attack
    """
    from modules.tool_wrappers import eaphammer_attack
    return _fmt(await _run_async(eaphammer_attack, bssid, essid, iface, auth_type=auth_type,
                                 pmkid=pmkid, captive=captive))


@mcp.tool()
async def wifi_scan(iface: str = "wlan0", timeout: int = 45) -> str:
    """
    Scan for nearby WiFi networks. Returns list of APs with BSSID, channel, signal, encryption, ESSID.
    Phase: Wireless Pentesting
    Related: wifi_eaphammer_attack, wifi_deauth, wifi_handshake_capture, wifi_connect, wifi_network_scan, wifi_arp_spoof, wifi_proxy, wifi_rogue_ap, wifi_sycophant_relay, wifi_mitmproxy, wifi_evil_twin, wifi_auto_attack
    """
    from modules.wifi_wrapper import wifi_scan as _scan
    result = await _run_async(_scan, iface=iface, timeout=timeout)
    if result.get("error"):
        return f"Error: {result['error']}"
    aps = result.get("aps", [])
    if not aps:
        return "No access points found."
    lines = [f"Found {len(aps)} AP(s) (source: {result.get('source', '?')}):",
             "  BSSID              CH  Signal  Encryption  ESSID"]
    for ap in sorted(aps, key=lambda x: int(x.get("channel", 0))):
        lines.append(f"  {ap.get('bssid','?'):<18} {ap.get('channel','?'):<4} "
                     f"{ap.get('signal','?'):<7} {ap.get('encryption','?'):<12} "
                     f"{ap.get('essid','?')}")
    return "\n".join(lines)


@mcp.tool()
async def wifi_deauth(bssid: str, iface: str = "wlan0",
                      station: str = "", count: int = 5) -> str:
    """
    Send deauthentication frames to a BSSID (optionally target a specific station).
    Phase: Wireless Pentesting
    Related: wifi_eaphammer_attack, wifi_scan, wifi_handshake_capture, wifi_connect, wifi_network_scan, wifi_arp_spoof, wifi_proxy, wifi_rogue_ap, wifi_sycophant_relay, wifi_mitmproxy, wifi_evil_twin, wifi_auto_attack
    """
    from modules.wifi_wrapper import wifi_deauth as _deauth
    result = await _run_async(_deauth, bssid, iface=iface, station=station, count=count)
    if result.get("error"):
        return f"Error: {result['error']}"
    return result.get("status", "Deauth sent")


@mcp.tool()
async def wifi_handshake_capture(bssid: str, channel: str, iface: str = "wlan0",
                                 essid: str = "", timeout: int = 60) -> str:
    """
    Capture WPA 4-way handshake. Returns path to capture file if successful.
    Phase: Wireless Pentesting
    Related: wifi_eaphammer_attack, wifi_scan, wifi_deauth, wifi_connect, wifi_network_scan, wifi_arp_spoof, wifi_proxy, wifi_rogue_ap, wifi_sycophant_relay, wifi_mitmproxy, wifi_evil_twin, wifi_auto_attack
    """
    from modules.wifi_wrapper import wifi_handshake_capture as _hs
    result = await _run_async(_hs, bssid, channel, iface=iface, essid=essid, timeout=timeout)
    if result.get("error"):
        return f"Error: {result['error']}"
    if result.get("capture"):
        return f"Handshake captured: {result['capture']} ({result.get('size', 0)} bytes)"
    return result.get("status", "No handshake captured")


@mcp.tool()
async def wifi_connect(ssid: str, password: str = "", iface: str = "wlan0") -> str:
    """
    Connect to a WiFi network. For open networks omit password.
    Phase: Wireless Pentesting
    Related: wifi_eaphammer_attack, wifi_scan, wifi_deauth, wifi_handshake_capture, wifi_network_scan, wifi_arp_spoof, wifi_proxy, wifi_rogue_ap, wifi_sycophant_relay, wifi_mitmproxy, wifi_evil_twin, wifi_auto_attack
    """
    from modules.wifi_wrapper import wifi_connect as _conn
    result = await _run_async(_conn, ssid, password=password, iface=iface)
    if result.get("error"):
        return f"Error: {result['error']}"
    return result.get("status", f"Connected to {ssid}")


@mcp.tool()
async def wifi_network_scan(iface: str = "wlan0", subnet: str = "") -> str:
    """
    Scan the local network for hosts (ARP scan / ping sweep) after connecting.
    Phase: Wireless Pentesting
    Related: wifi_eaphammer_attack, wifi_scan, wifi_deauth, wifi_handshake_capture, wifi_connect, wifi_arp_spoof, wifi_proxy, wifi_rogue_ap, wifi_sycophant_relay, wifi_mitmproxy, wifi_evil_twin, wifi_auto_attack
    """
    from modules.wifi_wrapper import wifi_network_scan as _netscan
    result = await _run_async(_netscan, iface=iface, subnet=subnet)
    if result.get("error"):
        return f"Error: {result['error']}"
    hosts = result.get("hosts", [])
    if not hosts:
        return f"No hosts found on {result.get('subnet', '?')}"
    lines = [f"Found {len(hosts)} host(s) on {result.get('subnet', '?')}:",
             "  IP              Status"]
    for h in hosts:
        lines.append(f"  {h.get('ip','?'):<16} {h.get('status','?')}")
    return "\n".join(lines)


@mcp.tool()
async def wifi_arp_spoof(target: str, gateway: str = "", iface: str = "wlan0") -> str:
    """
    Start ARP spoofing between target and gateway to intercept traffic.
    Phase: Wireless Pentesting
    Related: wifi_eaphammer_attack, wifi_scan, wifi_deauth, wifi_handshake_capture, wifi_connect, wifi_network_scan, wifi_proxy, wifi_rogue_ap, wifi_sycophant_relay, wifi_mitmproxy, wifi_evil_twin, wifi_auto_attack
    """
    from modules.wifi_wrapper import wifi_arp_spoof as _arp
    result = await _run_async(_arp, target, gateway=gateway, iface=iface)
    if result.get("error"):
        return f"Error: {result['error']}"
    return result.get("status", "ARP spoofing started")


@mcp.tool()
async def wifi_proxy(port: int = 8080, iface: str = "wlan0",
                     sslstrip: bool = True) -> str:
    """
    Start BetterCAP transparent HTTP proxy with optional SSL stripping.
    Phase: Wireless Pentesting
    Related: wifi_eaphammer_attack, wifi_scan, wifi_deauth, wifi_handshake_capture, wifi_connect, wifi_network_scan, wifi_arp_spoof, wifi_rogue_ap, wifi_sycophant_relay, wifi_mitmproxy, wifi_evil_twin, wifi_auto_attack
    """
    from modules.wifi_wrapper import wifi_proxy as _proxy
    result = await _run_async(_proxy, port=port, iface=iface, sslstrip=sslstrip)
    if result.get("error"):
        return f"Error: {result['error']}"
    return result.get("status", f"Proxy started on :{port}")


@mcp.tool()
async def wifi_rogue_ap(essid: str, iface: str = "wlan0", channel: str = "6",
                        bssid: str = "") -> str:
    """
    Create a rogue access point with the given ESSID using airbase-ng (or hostapd).
    Phase: Wireless Pentesting
    Related: wifi_eaphammer_attack, wifi_scan, wifi_deauth, wifi_handshake_capture, wifi_connect, wifi_network_scan, wifi_arp_spoof, wifi_proxy, wifi_sycophant_relay, wifi_mitmproxy, wifi_evil_twin, wifi_auto_attack
    """
    from modules.wifi_wrapper import airbase_rogue_ap
    result = await _run_async(airbase_rogue_ap, essid, iface=iface, channel=channel, bssid=bssid)
    if result.get("error"):
        return f"Error: {result['error']}"
    return result.get("status", f"Rogue AP '{essid}' started")


@mcp.tool()
async def wifi_sycophant_relay(iface: str = "wlan0", target_bssid: str = "",
                               target_essid: str = "") -> str:
    """
    Relay WPA 4-way handshake using wpa_sycophant (MITM without password cracking).
    Phase: Wireless Pentesting
    Related: wifi_eaphammer_attack, wifi_scan, wifi_deauth, wifi_handshake_capture, wifi_connect, wifi_network_scan, wifi_arp_spoof, wifi_proxy, wifi_rogue_ap, wifi_mitmproxy, wifi_evil_twin, wifi_auto_attack
    """
    from modules.wifi_wrapper import wpa_sycophant_relay
    result = await _run_async(wpa_sycophant_relay, iface=iface, target_bssid=target_bssid,
                              target_essid=target_essid)
    if result.get("error"):
        return f"Error: {result['error']}"
    return result.get("status", "wpa_sycophant relay started")


@mcp.tool()
async def wifi_mitmproxy(port: int = 8080, listen_addr: str = "0.0.0.0",
                         mode: str = "transparent") -> str:
    """
    Start mitmproxy in transparent or regular mode for traffic interception.
    Phase: Wireless Pentesting
    Related: wifi_eaphammer_attack, wifi_scan, wifi_deauth, wifi_handshake_capture, wifi_connect, wifi_network_scan, wifi_arp_spoof, wifi_proxy, wifi_rogue_ap, wifi_sycophant_relay, wifi_evil_twin, wifi_auto_attack
    """
    from modules.wifi_wrapper import mitmproxy_intercept
    result = await _run_async(mitmproxy_intercept, port=port, listen_addr=listen_addr, mode=mode)
    if result.get("error"):
        return f"Error: {result['error']}"
    return result.get("status", f"mitmproxy started on :{port}")


@mcp.tool()
async def wifi_evil_twin(essid: str, iface: str = "wlan0", channel: str = "6",
                         bssid: str = "", portal_dir: str = "",
                         proxy_port: int = 8080) -> str:
    """Full evil twin: rogue AP + captive portal on :80 + transparent proxy.

    Victims connect to the rogue AP, get a captive portal login page,
    entered credentials are logged, and all HTTP traffic is proxied.
    Phase: Wireless Pentesting
    Related: wifi_eaphammer_attack, wifi_scan, wifi_deauth, wifi_handshake_capture, wifi_connect, wifi_network_scan, wifi_arp_spoof, wifi_proxy, wifi_rogue_ap, wifi_sycophant_relay, wifi_mitmproxy, wifi_auto_attack
    """
    from modules.wifi_wrapper import evil_twin_full
    result = await _run_async(evil_twin_full, essid, iface=iface, channel=channel, bssid=bssid,
                              portal_dir=portal_dir, proxy_port=proxy_port)
    if result.get("error"):
        return f"Error: {result['error']}"
    return result.get("status", f"Evil twin '{essid}' running")


@mcp.tool()
async def wifi_auto_attack(iface: str = "wlan0", target_bssid: str = "",
                           target_essid: str = "", channel: str = "") -> str:
    """
    Automatically try multiple attack vectors: handshake capture, deauth, evil twin, relay.
    Phase: Wireless Pentesting
    Related: wifi_eaphammer_attack, wifi_scan, wifi_deauth, wifi_handshake_capture, wifi_connect, wifi_network_scan, wifi_arp_spoof, wifi_proxy, wifi_rogue_ap, wifi_sycophant_relay, wifi_mitmproxy, wifi_evil_twin
    """
    from modules.wifi_wrapper import wifi_auto_attack
    result = await _run_async(wifi_auto_attack, iface=iface, target_bssid=target_bssid,
                              target_essid=target_essid, channel=channel)
    attacks = result.get("attacks", {})
    lines = [f"Auto-attack against {result.get('target', '?')}:"]
    for name, res in attacks.items():
        status = res.get("status", res.get("capture", res.get("error", "done")))
        lines.append(f"  {name}: {status[:80]}")
    return "\n".join(lines)


@mcp.tool()
async def wifi_wireless_graph(pcap: str = "", iface: str = "") -> str:
    """
    Parse wireless PCAP or live capture and generate an HTML signal graph.
    Phase: Wireless Pentesting
    Related: wifi_eaphammer_attack, wifi_scan, wifi_deauth, wifi_handshake_capture, wifi_connect, wifi_network_scan, wifi_arp_spoof, wifi_proxy, wifi_rogue_ap, wifi_sycophant_relay, wifi_mitmproxy, wifi_evil_twin
    """
    from modules.tool_wrappers import wireless_graph
    return _fmt(await _run_async(wireless_graph, pcap=pcap, iface=iface))


@mcp.tool()
async def forensics_yara_scan(rule_path: str, target: str) -> str:
    """
    Scan files with YARA rules (rule file/dir vs target file/dir).
    Phase: Digital Forensics
    Related: forensics_kape_collect, forensics_semgrep_scan
    """
    from modules.tool_wrappers import yara_scan
    return _fmt(await _run_async(yara_scan, rule_path, target), fmt="yara")


@mcp.tool()
async def forensics_kape_collect(target: str, targets: str = "!BasicCollection",
                                 module: str = "", binary_path: str = "kape") -> str:
    """
    Run KAPE Windows forensic artifact collection against a target drive or image.
    Phase: Digital Forensics
    Related: forensics_yara_scan, forensics_semgrep_scan
    """
    from modules.tool_wrappers import kape_collect
    return _fmt(await _run_async(kape_collect, target, targets=targets, module=module, binary_path=binary_path))


@mcp.tool()
async def forensics_semgrep_scan(config: str, target: str) -> str:
    """
    Run Semgrep SAST scanner against source code.
    Phase: Digital Forensics
    Related: forensics_yara_scan, forensics_kape_collect
    """
    from modules.tool_wrappers import semgrep_scan
    return _fmt(await _run_async(semgrep_scan, config, target))


# ---------------------------------------------------------------------------
# Utility servers
# ---------------------------------------------------------------------------
@mcp.tool()
def util_swaks_send(to: str, server: str, from_addr: str = "",
                    subject: str = "Test", body: str = "",
                    port: int = 25, tls: bool = False,
                    auth_user: str = "", auth_pass: str = "",
                    attach: str = "", header: str = "") -> str:
    """
    Send a test email via SMTP (useful for phishing simulation or mail server testing).
    Phase: Utility / Infrastructure
    Related: util_wsgidav_serve, util_mitm_start, util_route_scan, util_sigma_convert
    """
    from modules.tool_wrappers import swaks_send
    return _fmt(_run(swaks_send, to, server, from_addr=from_addr, subject=subject,
                     body=body, port=port, tls=tls, auth_user=auth_user,
                     auth_pass=auth_pass, attach=attach, header=header))


@mcp.tool()
def util_wsgidav_serve(directory: str, host: str = "0.0.0.0",
                       port: int = 8080, auth: bool = True,
                       username: str = "", password: str = "") -> str:
    """
    Start a WebDAV server for file sharing (background process).
    Phase: Utility / Infrastructure
    Related: util_swaks_send, util_mitm_start, util_route_scan, util_sigma_convert
    """
    from modules.tool_wrappers import wsgidav_serve
    fn = lambda: wsgidav_serve(directory, host=host, port=port,
                                auth=auth, username=username, password=password)
    proc = _run(fn)
    if isinstance(proc, dict) and proc.get("error"):
        return proc["error"]
    return f"WebDAV server started on http://{host}:{port} serving {directory} (PID: {proc.pid})"


@mcp.tool()
def util_mitm_start(port: int = 8080, upstream: str = "") -> str:
    """
    Start a MITM proxy server for traffic interception.
    Phase: Utility / Infrastructure
    Related: util_swaks_send, util_wsgidav_serve, util_route_scan, util_sigma_convert
    """
    from modules.tool_wrappers import mitm_start
    r = _run(mitm_start, port=port, upstream=upstream)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    return f"MITM proxy started on port {port}" + (f" (upstream: {upstream})" if upstream else "")


@mcp.tool()
async def util_route_scan(target_range: str = "172.16.0.0/12",
                          max_workers: int = 10, arp_only: bool = False) -> str:
    """
    Trace routes to IPs in a range and report suspicious private IPs in transit.
    Phase: Utility / Infrastructure
    Related: util_swaks_send, util_wsgidav_serve, util_mitm_start, util_sigma_convert
    """
    from modules.tool_wrappers import route_scan
    r = await _run_async(route_scan, target_range=target_range,
                         max_workers=max_workers, arp_only=arp_only)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    lines = [f"Route scan of {target_range}:"]
    for k, v in r.items() if isinstance(r, dict) else {}:
        lines.append(f"  {k}: {v}")
    return "\n".join(lines) if len(lines) > 1 else str(r)[:2000]


@mcp.tool()
def util_sigma_convert(input_file: str, target_format: str = "siem",
                       output: str = "") -> str:
    """
    Convert Sigma rules to other formats (splunk, elk, qradar, etc.).
    Phase: Utility / Infrastructure
    Related: util_swaks_send, util_wsgidav_serve, util_mitm_start, util_route_scan
    """
    from modules.tool_wrappers import sigma_convert
    r = _run(sigma_convert, input_file=input_file,
             target_format=target_format, output=output)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    return f"Sigma conversion: {r}"[:2000]


# ---------------------------------------------------------------------------
# References
# ---------------------------------------------------------------------------
@mcp.tool()
def ref_ldap_filters(keyword: str = "") -> str:
    """
    Search LDAP query filters for AD enumeration (AS-REP roastable, Kerberoastable, delegation, etc).
    Phase: Reference Data Lookup
    Related: ref_event_ids, ref_cves
    """
    from modules.references import search_ldap
    results = search_ldap(keyword)
    if not results:
        return "No matching LDAP filters found."
    return "\n".join(f"  {r['name']:<30} {r['filter']}\n  {'':30} {r['desc']}" for r in results)


@mcp.tool()
def ref_event_ids(keyword: str = "") -> str:
    """
    Search Windows Event IDs (security, sysmon, PowerShell). Keyword can be ID, log, or description.
    Phase: Reference Data Lookup
    Related: ref_ldap_filters, ref_cves
    """
    from modules.references import search_event_ids
    results = search_event_ids(keyword)
    if not results:
        return "No matching event IDs found."
    return "\n".join(f"{e['id']:<8} {e['log']:<20} {e['desc']}" for e in results)


@mcp.tool()
def ref_cves(keyword: str = "") -> str:
    """
    Search curated CVE database for high-value exploits (PrintNightmare, ZeroLogon, Log4Shell, etc).
    Phase: Reference Data Lookup
    Related: ref_ldap_filters, ref_event_ids
    """
    from modules.references import search_cves
    results = search_cves(keyword)
    if not results:
        return "No matching CVEs found."
    return "\n".join(f"{c['id']:<20} {c['name']:<30} [{c['category']}]\n{'':20} {c['desc']}" for c in results)


# ---------------------------------------------------------------------------
# Runbooks / Playbooks — async bridge for AI orchestration
# ---------------------------------------------------------------------------

_playbook_jobs: dict = {}
_PB_LOCK = threading.Lock()
_PB_MAX_JOBS = 100


def _pb_prune():
    """Cap _playbook_jobs size so a long-running server doesn't leak memory.

    Completed/failed entries are only history, so those are dropped first
    (oldest first); running jobs fall back to oldest-insertion-order drops.
    """
    with _PB_LOCK:
        if len(_playbook_jobs) <= _PB_MAX_JOBS:
            return
        excess = len(_playbook_jobs) - _PB_MAX_JOBS
        terminal = [k for k, v in _playbook_jobs.items()
                    if v.get("status") in ("completed", "failed")]
        for k in terminal[:excess]:
            del _playbook_jobs[k]
        if len(_playbook_jobs) > _PB_MAX_JOBS:
            for k in list(_playbook_jobs)[:len(_playbook_jobs) - _PB_MAX_JOBS]:
                del _playbook_jobs[k]


def _pb_run_background(name: str, target: str, case_id: str, job_id: str, vars_override: dict = None):
    """Run a playbook in background and store results."""
    from modules.playbook_engine import RunbookEngine
    try:
        engine = RunbookEngine()
        cm = CaseManager()
        with _PB_LOCK:
            _playbook_jobs[job_id] = {"status": "running", "progress": 0,
                                      "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        results = engine.run_file(
            name, targets=[target] if target else [],
            case_id=case_id, vars_override=vars_override or {}, verbose=False,
        )
        # Save to case as note
        try:
            runlog_path = cm._case_path(case_id) / "runbook-log.json"
            if runlog_path.exists():
                import json as _json
                runlog = _json.loads(runlog_path.read_text())
                steps = runlog.get("step_outputs", {})
                lines = [f"## {name} Results"]
                for sid, out in steps.items():
                    rc = out.get("rc", "?")
                    status = "OK" if rc == 0 else f"FAIL (rc={rc})"
                    lines.append(f"- {sid}: {status}")
                cm.add_note(case_id, "\n".join(lines), tags=["runbook", "mcp"])
        except Exception as _e:
            _log(f"Failed to save runbook log: {_e}")
        with _PB_LOCK:
            _playbook_jobs[job_id] = {
                "status": "completed",
                "progress": 100,
                "step_count": len(results) if results else 0,
                "case_id": case_id,
                "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
        _pb_prune()
    except Exception as e:
        with _PB_LOCK:
            _playbook_jobs[job_id] = {
                "status": "failed",
                "error": str(e),
                "case_id": case_id,
                "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
        _pb_prune()


@mcp.tool()
def playbook_list() -> str:
    """List all available YAML playbooks/runbooks for automated pentest workflows."""
    import yaml
    from modules.playbook_engine import RunbookEngine
    engine = RunbookEngine()
    books = engine.list_runbooks()
    if not books:
        return "No playbooks found."
    lines = [f"{'Name':<30} Description"]
    lines.append("-" * 80)
    for b in sorted(books, key=lambda x: x.name):
        try:
            data = yaml.safe_load(b.read_text()) or {}
            desc = (data.get("description") or "")[:60]
        except Exception:
            desc = ""
        lines.append(f"{b.name:<30} {desc}")
    return "\n".join(lines)


@mcp.tool()
def playbook_launch(name: str, target: str = "", case_id: str = "", vars_json: str = "") -> str:
    """Launch a playbook asynchronously. Returns a job_id for status polling.
    Phase: Runbook Orchestration
    Related: playbook_list, playbook_status, playbook_log
    Use playbook_status(job_id) to check progress, playbook_log(case_id) to get results."""
    import json as _json
    vars_override = _json.loads(vars_json) if vars_json else {}
    job_id = uuid.uuid4().hex[:8]
    resolved_case_id = case_id or f"mcp-{name.replace('.yaml','')}-{datetime.datetime.now(datetime.timezone.utc):%Y%m%d_%H%M%S}"

    # Create case upfront
    try:
        cm = CaseManager()
        cm.create(resolved_case_id,
                  description=f"MCP-runbook: {name} against {target or '(no target)'}",
                  targets=[target] if target else [])
    except Exception as _e:
        _log(f"Case may already exist (expected): {_e}")

    with _PB_LOCK:
        _playbook_jobs[job_id] = {"status": "queued", "progress": 0,
                                  "case_id": resolved_case_id,
                                  "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        _pb_prune()
    t = threading.Thread(target=_pb_run_background,
                         args=(name, target, resolved_case_id, job_id, vars_override), daemon=True)
    t.start()
    return f"Launched playbook '{name}' as job {job_id} in case {resolved_case_id}"


@mcp.tool()
def playbook_status(job_id: str) -> str:
    """
    Check the status of an async playbook launch. Returns JSON with status, progress, and result.
    Phase: Runbook Orchestration
    Related: playbook_list, playbook_launch, playbook_log
    """
    with _PB_LOCK:
        job = _playbook_jobs.get(job_id)
    if not job:
        return f"Error: job '{job_id}' not found"
    import json as _json
    return _json.dumps(job, indent=2, default=str)


@mcp.tool()
def playbook_log(case_id: str) -> str:
    """
    Get the runbook execution log for a case. Returns JSON with step outputs.
    Phase: Runbook Orchestration
    Related: playbook_list, playbook_launch, playbook_status
    """
    cm = CaseManager()
    log_path = cm._case_path(case_id) / "runbook-log.json"
    if not log_path.exists():
        return f"Error: no runbook log found for case '{case_id}'"
    try:
        return log_path.read_text()
    except Exception as e:
        return f"Error reading log: {e}"


@mcp.tool()
def runbook_list(search: str = "") -> str:
    """
    List all available runbook templates with step counts and descriptions.
    Phase: Runbook Orchestration
    Related: runbook_get_steps, runbook_get, runbook_set, playbook_list, playbook_launch
    """
    from modules.playbook_engine import RunbookEngine
    engine = RunbookEngine()
    books = engine.list_runbooks()
    if search:
        books = [b for b in books if search.lower() in b.name.lower()]
    if not books:
        return "No runbooks found."
    lines = [f"{'Name':<35} {'Steps':>5}  Description"]
    lines.append("-" * 90)
    for b in sorted(books, key=lambda x: x.name):
        try:
            import yaml
            data = yaml.safe_load(b.read_text()) or {}
            steps = len(data.get("steps", []))
            desc = (data.get("description") or "")[:55]
        except Exception:
            steps = 0
            desc = ""
        lines.append(f"{b.name:<35} {steps:>5}  {desc}")
    return "\n".join(lines)


@mcp.tool()
def runbook_get_steps(name: str) -> str:
    """
    Get the detailed steps for a named runbook template.
    Phase: Runbook Orchestration
    Related: runbook_list, runbook_get, runbook_set, playbook_launch
    """
    from modules.playbook_engine import RunbookEngine
    engine = RunbookEngine()
    books = engine.list_runbooks()
    matches = [b for b in books if b.name == name]
    if not matches:
        return f"Error: runbook '{name}' not found. Use runbook_list() to see available runbooks."
    import yaml
    data = yaml.safe_load(matches[0].read_text()) or {}
    import json as _json
    return _json.dumps(data, indent=2, default=str)


@mcp.tool()
def runbook_get(case_id: str) -> str:
    """
    Get the current runbook/playbook configuration for a specific case.
    Phase: Runbook Orchestration
    Related: runbook_set, runbook_list, runbook_get_steps, playbook_log
    """
    cm = CaseManager()
    runbook_path = cm._case_path(case_id) / "playbook.json"
    if not runbook_path.exists():
        return f"Error: no runbook defined for case '{case_id}'"
    import json as _json
    return _json.dumps(_json.loads(runbook_path.read_text()), indent=2)


@mcp.tool()
def runbook_set(case_id: str, steps_json: str) -> str:
    """
    Set/replace the runbook for a case with new steps.
    Phase: Runbook Orchestration
    Related: runbook_get, runbook_list, runbook_get_steps
    """
    import json as _json
    cm = CaseManager()
    runbook_path = cm._case_path(case_id) / "playbook.json"
    try:
        steps = _json.loads(steps_json)
        if isinstance(steps, list):
            data = {"steps": steps}
        elif isinstance(steps, dict):
            data = steps
        else:
            return "Error: steps_json must be a JSON array of steps or a dict with steps key"
    except json.JSONDecodeError as e:
        return f"Error: invalid JSON - {e}"
    runbook_path.write_text(_json.dumps(data, indent=2, default=str))
    return f"Runbook updated for case '{case_id}' with {len(data.get('steps', []))} step(s)"


# ---------------------------------------------------------------------------
# Burp Suite Pro — built-in REST API (Burp 2025+)
# Format: http://<host>:<port>/<API-KEY>/v0.1/<endpoint>
# ---------------------------------------------------------------------------

@mcp.tool()
def burp_health() -> str:
    """Check Burp Suite REST API connectivity and version.
    Phase: Burp Integration
    Related: burp_scan_start, burp_scan_status, burp_issues_list
    Use this first to verify Burp is reachable."""
    from modules.burp_client import BurpClient
from modules.config import BURP_API_URL, BURP_API_KEY
    bc = BurpClient(api_url=BURP_API_URL, api_key=BURP_API_KEY)
    h = bc.health()
    v = bc.versions()
    return f"Health: {h.get('status')}\nVersions: {v}" if v.get("burpVersion") else f"Health: {h}"


@mcp.tool()
def burp_scan_start(urls: str) -> str:
    """Start a new Burp Suite scan. Returns scan ID for status polling.
    Phase: Burp Integration
    Related: burp_scan_status, burp_issues_list
    """
    from modules.burp_client import BurpClient
from modules.config import BURP_API_URL, BURP_API_KEY
    bc = BurpClient(api_url=BURP_API_URL, api_key=BURP_API_KEY)
    url_list = [u.strip() for u in urls.split(",") if u.strip()]
    r = bc.scan_start(url_list)
    if "error" in r:
        return f"Error: {r['error']}"
    return f"Scan started. ID: {r.get('scan_id')}"


@mcp.tool()
def burp_scan_status(scan_id: str) -> str:
    """Get the status and progress of a Burp scan.
    Phase: Burp Integration
    Related: burp_scan_start, burp_issues_list
    """
    from modules.burp_client import BurpClient
from modules.config import BURP_API_URL, BURP_API_KEY
    bc = BurpClient(api_url=BURP_API_URL, api_key=BURP_API_KEY)
    r = bc.scan_status(scan_id)
    import json as _json
    return _json.dumps(r, indent=2, default=str)


@mcp.tool()
def burp_issues_list(scan_id: str, severity: str = "") -> str:
    """List security issues found by a Burp scan.
    Phase: Burp Integration
    Related: burp_scan_start, burp_scan_status
    """
    from modules.burp_client import BurpClient
from modules.config import BURP_API_URL, BURP_API_KEY
    bc = BurpClient(api_url=BURP_API_URL, api_key=BURP_API_KEY)
    issues = bc.issues_list(scan_id, severity=severity)
    if not issues:
        return "No issues found."
    if isinstance(issues, list) and len(issues) > 0 and "error" in issues[0]:
        return f"Error: {issues[0]['error']}"
    lines = [f"{'Severity':<10} {'Name':<50} {'Host':<30}"]
    lines.append("-" * 92)
    for i in issues:
        if not isinstance(i, dict):
            continue
        sev = i.get("severity", i.get("severity_name", "?"))
        name = i.get("name", i.get("issue_name", i.get("title", "")))[:50]
        host = i.get("host", i.get("url", ""))[:30]
        lines.append(f"{sev:<10} {name:<50} {host:<30}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# ZAP DAST — OWASP ZAP REST/JSON API with daemon auto-start
# ---------------------------------------------------------------------------

@mcp.tool()
def zap_health(api_url: str = "") -> str:
    """Check ZAP API connectivity and version. Optionally point at a custom URL.
    Phase: DAST
    Related: zap_scan_start, zap_scan_status, zap_issues_list
    Use this first to verify ZAP is reachable."""
    from modules.zap_client import ZapClient
    api_url = api_url or _zap_cfg().get("url", "http://127.0.0.1:8080")
    h = ZapClient(api_url=api_url, api_key=_zap_cfg().get("api_key", "")).health()
    return f"ZAP: {h.get('status')} v{h.get('version', '?')}" if h.get("status") == "ok" else f"ZAP: {h}"


@mcp.tool()
def zap_scan_start(url: str, mode: str = "active", api_url: str = "",
                   recurse: bool = True, policy: str = "", auto_start: bool = True) -> str:
    """Start a ZAP scan of a URL. mode: 'active' (default), 'spider', or 'ajax'.
    If ZAP isn't running it can be auto-started as a daemon (auto_start).
    Phase: DAST
    Related: zap_scan_status, zap_issues_list, zap_health
    """
    from modules.zap_client import ZapClient
    cfg = _zap_cfg()
    api_url = api_url or cfg.get("url", "http://127.0.0.1:8080")
    zc = ZapClient(api_url=api_url, api_key=cfg.get("api_key", ""))
    if auto_start:
        st = zc.ensure_running(zap_bin=cfg.get("bin", "zaproxy"))
        if st.get("status") != "ok":
            return f"Error: ZAP unreachable and could not auto-start: {st.get('error')}"
    mode = (mode or "active").lower()
    if mode not in ("active", "spider", "ajax"):
        return (f"Error: unknown mode '{mode}' (expected 'active', 'spider' or 'ajax'). "
                f"No scan was started.")
    if mode == "spider":
        r = zc.spider_start(url, recurse=recurse)
        if "error" in r:
            return f"Error: {r['error']}"
        return f"Spider started. scan_id={r['scan_id']} (type=spider)"
    if mode == "ajax":
        r = zc.ajax_spider_start(url)
        if "error" in r:
            return f"Error: {r['error']}"
        return "AJAX spider started (no scan_id; check status with zap_scan_status)."
    r = zc.active_scan_start(url, recurse=recurse, policy=policy)
    if "error" in r:
        return f"Error: {r['error']}"
    return f"Active scan started. scan_id={r['scan_id']} (type=active)"


@mcp.tool()
def zap_scan_status(scan_id: str = "", mode: str = "active", api_url: str = "") -> str:
    """Check ZAP scan progress. mode: active (default), spider, or ajax.
    Returns a percentage (0-100) for active/spider; status text for ajax.
    Phase: DAST
    Related: zap_scan_start, zap_issues_list, zap_health
    """
    from modules.zap_client import ZapClient
    cfg = _zap_cfg()
    zc = ZapClient(api_url=api_url or cfg.get("url", "http://127.0.0.1:8080"),
                   api_key=cfg.get("api_key", ""))
    mode = (mode or "active").lower()
    if mode == "ajax":
        r = zc.ajax_spider_status()
        return f"AJAX spider: {r.get('status', 'stopped')}"
    if mode == "spider":
        r = zc.spider_status(scan_id)
        return f"Spider {scan_id}: {r.get('status', '?')}% complete"
    r = zc.active_scan_status(scan_id)
    return f"Active scan {scan_id}: {r.get('status', '?')}% complete"


@mcp.tool()
def zap_issues_list(api_url: str = "", risk: str = "", baseurl: str = "",
                    count: int = 200) -> str:
    """List security issues/alerts found by ZAP. Filter by risk
    (High/Medium/Low/Informational).
    Phase: DAST
    Related: zap_scan_start, zap_scan_status, zap_health
    """
    from modules.zap_client import ZapClient
    cfg = _zap_cfg()
    zc = ZapClient(api_url=api_url or cfg.get("url", "http://127.0.0.1:8080"),
                   api_key=cfg.get("api_key", ""))
    alerts = zc.alerts(baseurl=baseurl, risk=risk, count=count)
    if not alerts:
        return "No alerts found."
    if isinstance(alerts, list) and alerts and "error" in alerts[0]:
        return f"Error: {alerts[0]['error']}"
    lines = [f"{'Risk':<14} {'Name':<48} {'URL':<40}", "-" * 102]
    for a in alerts:
        sev = a.get("risk", "?")
        name = (a.get("name") or "")[:48]
        url = (a.get("url") or "")[:40]
        lines.append(f"{sev:<14} {name:<48} {url:<40}")
    lines.append("")
    lines.append("Use case_finding_add with the alert details to log findings.")
    return "\n".join(lines)


def _zap_cfg() -> dict:
from modules.config import load_config
    cfg = load_config()
    return cfg.get("zap", {})


# ---------------------------------------------------------------------------
# Rules — Semgrep / Sigma / YARA / Suricata / Nuclei
# ---------------------------------------------------------------------------

@mcp.tool()
def rules_list(rule_format: str = "", severity: str = "",
               search: str = "", category: str = "") -> str:
    """
    List security rules across all formats (semgrep, sigma, yara, suricata, nuclei). Optionally filter by format, severity (comma-separated), text search, or category/family.
    Phase: Rule Management
    Related: rules_get, rules_create, rules_save, rules_delete, rules_stats, rules_template, rules_bulk_delete, rules_export, rules_import, rules_scan_target, rules_scan_all
    """
    from modules.rules_manager import RuleManager
    rm = RuleManager()
    results = rm.list_rules(rule_format=rule_format, severity=severity,
                            search=search, category=category)
    if not results:
        return "No rules found matching the given filters."
    fmt = rule_format or "all"
    lines = [f"Rules ({fmt}, {len(results)} found):"]
    for r in results:
        sev = r.get("severity", "?")
        rid = r.get("id", r.get("rule_id", "?"))
        title = r.get("title", rid)
        lines.append(f"  [{sev:<7}] {rid:<30} {title}")
    return "\n".join(lines)


@mcp.tool()
def rules_get(rule_format: str, rule_id: str) -> str:
    """
    Get full details for a single rule by format (semgrep/sigma/yara/suricata/nuclei) and rule ID. Returns parsed metadata + raw source.
    Phase: Rule Management
    Related: rules_list, rules_create, rules_save, rules_delete, rules_stats, rules_template, rules_bulk_delete, rules_export, rules_import, rules_scan_target, rules_scan_all
    """
    from modules.rules_manager import RuleManager
    rm = RuleManager()
    result = rm.get_rule(rule_format, rule_id)
    if not result:
        return f"Rule '{rule_format}/{rule_id}' not found."
    parsed = result.get("parsed", {})
    raw = result.get("raw", "")
    lines = [f"Rule: {rule_format}/{rule_id}",
             f"  Title:       {parsed.get('title', 'N/A')}",
             f"  Severity:    {parsed.get('severity', 'N/A')}",
             f"  Description: {parsed.get('description', '')}",
             f"  File:        {result.get('filepath', '')}",
             f"  Author:      {parsed.get('author', 'N/A')}"]
    extra = parsed.get("extra_fields", {})
    for k, v in extra.items():
        if v:
            lines.append(f"  {k.replace('_', ' ').title():12} {v}")
    lines.append(f"\n--- Raw source ({result.get('format', '?')}) ---")
    lines.append((raw[:3000] + "\n...(truncated)") if len(raw) > 3000 else raw)
    return "\n".join(lines)


@mcp.tool()
def rules_create(rule_format: str, content: str) -> str:
    """
    Create a new rule file. Format is one of: semgrep, sigma, yara, suricata, nuclei. Content must be valid for the format.
    Phase: Rule Management
    Related: rules_list, rules_get, rules_save, rules_delete, rules_stats, rules_template, rules_bulk_delete, rules_export, rules_import, rules_scan_target, rules_scan_all
    """
    from modules.rules_manager import RuleManager
    rm = RuleManager()
    try:
        result = rm.create_rule(rule_format, content)
        return f"Rule created: {result['filename']} ({result['filepath']})"
    except ValueError as e:
        return f"Error: {e}"


@mcp.tool()
def rules_save(rule_format: str, rule_id: str, content: str) -> str:
    """
    Save/update an existing rule's content. Validates format-specific syntax before writing.
    Phase: Rule Management
    Related: rules_list, rules_get, rules_create, rules_delete, rules_stats, rules_template, rules_bulk_delete, rules_export, rules_import, rules_scan_target, rules_scan_all
    """
    from modules.rules_manager import RuleManager
    rm = RuleManager()
    try:
        result = rm.save_rule(rule_format, rule_id, content)
        return f"Rule saved: {rule_format}/{rule_id} → {result['filepath']}"
    except ValueError as e:
        return f"Validation error: {e}"
    except FileNotFoundError as e:
        return f"Error: {e}"


@mcp.tool()
def rules_delete(rule_format: str, rule_id: str) -> str:
    """
    Delete a rule file by format and rule ID.
    Phase: Rule Management
    Related: rules_list, rules_get, rules_create, rules_save, rules_stats, rules_template, rules_bulk_delete, rules_export, rules_import, rules_scan_target, rules_scan_all
    """
    from modules.rules_manager import RuleManager
    rm = RuleManager()
    try:
        result = rm.delete_rule(rule_format, rule_id)
        return f"Rule deleted: {result['filepath']}"
    except FileNotFoundError as e:
        return f"Error: {e}"


@mcp.tool()
def rules_stats() -> str:
    """Get rule count statistics per format (semgrep/sigma/yara/suricata/nuclei) with severity breakdown."""
    from modules.rules_manager import RuleManager
    rm = RuleManager()
    stats = rm.get_format_stats()
    lines = ["Rule statistics by format:"]
    for fmt, s in stats.items():
        lines.append(f"\n  {s.get('label', fmt)} ({s.get('total', 0)} rules)")
        by_sev = s.get("by_severity", {})
        if by_sev:
            sev_str = ", ".join(f"{k}={v}" for k, v in sorted(by_sev.items()))
            lines.append(f"    Severity: {sev_str}")
        roots = s.get("roots", [])
        if roots:
            for root in roots:
                lines.append(f"    Dir: {root}")
    return "\n".join(lines)


@mcp.tool()
def rules_template(rule_format: str) -> str:
    """
    Get a starter template for creating a new rule in the given format (semgrep/sigma/yara/suricata/nuclei).
    Phase: Rule Management
    Related: rules_list, rules_get, rules_create, rules_save, rules_delete, rules_stats, rules_bulk_delete, rules_export, rules_import, rules_scan_target, rules_scan_all
    """
    from modules.rules_manager import RuleManager
    rm = RuleManager()
    try:
        return rm.get_format_template(rule_format)
    except ValueError as e:
        return f"Error: {e}"


@mcp.tool()
def rules_bulk_delete(rule_format: str, rule_ids: str) -> str:
    """
    Delete multiple rules at once. Provide rule_format and a comma-separated list of rule IDs. Returns summary of deleted vs errors.
    Phase: Rule Management
    Related: rules_list, rules_get, rules_create, rules_save, rules_delete, rules_stats, rules_template, rules_export, rules_import, rules_scan_target, rules_scan_all
    """
    from modules.rules_manager import RuleManager
    rm = RuleManager()
    ids = [rid.strip() for rid in rule_ids.split(",") if rid.strip()]
    if not ids:
        return "Error: provide at least one rule_id (comma-separated)."
    result = rm.bulk_delete(rule_format, ids)
    msg = f"Deleted {result['deleted']} rule(s)."
    if result['errors']:
        msg += f" {result['errors']} error(s): {result['error_details']}"
    return msg


@mcp.tool()
def rules_export(rule_format: str, rule_ids: str = "") -> str:
    """
    Export rules as a ZIP archive. Provide rule_format and optional comma-separated rule_ids. If rule_ids is empty, exports all rules of the format. Returns file path to the exported ZIP on disk.
    Phase: Rule Management
    Related: rules_list, rules_get, rules_create, rules_save, rules_delete, rules_stats, rules_template, rules_bulk_delete, rules_import, rules_scan_target, rules_scan_all
    """
    from modules.rules_manager import RuleManager
    rm = RuleManager()
    ids = [rid.strip() for rid in rule_ids.split(",") if rid.strip()] or None
    try:
        zip_bytes = rm.export_rules(rule_format, rule_ids=ids)
        out_dir = Path.home() / ".cc_exports"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"rules-{rule_format}-export-{datetime.datetime.now(datetime.timezone.utc):%Y%m%d_%H%M%S}.zip"
        out_path.write_bytes(zip_bytes)
        return f"Exported {len(ids) if ids else 'all'} {rule_format} rules to {out_path}"
    except ValueError as e:
        return f"Error: {e}"


@mcp.tool()
def rules_import(rule_format: str, content: str, target_dir: str = "") -> str:
    """
    Import rules from raw text content. Attempts to split multi-rule bundles into individual files. Provide format and the full rule text content.
    Phase: Rule Management
    Related: rules_list, rules_get, rules_create, rules_save, rules_delete, rules_stats, rules_template, rules_bulk_delete, rules_export, rules_scan_target, rules_scan_all
    """
    from modules.rules_manager import RuleManager
    rm = RuleManager()
    try:
        result = rm.import_rules(rule_format, content, target_dir=target_dir)
        return f"Imported {result['created']}/{result['total']} rules." + (f" Errors: {result['error_details']}" if result['errors'] else "")
    except ValueError as e:
        return f"Error: {e}"


@mcp.tool()
async def rules_scan_target(rule_format: str, rule_id: str, target: str, language: str = "") -> str:
    """
    Scan a target with a specific rule (nuclei/yara/semgrep/codeql). For nuclei provide a URL, for yara provide a file/directory path, for semgrep/codeql provide a source code directory.
    Phase: Rule Management
    Related: rules_list, rules_get, rules_create, rules_save, rules_delete, rules_stats, rules_template, rules_bulk_delete, rules_export, rules_import, rules_scan_all
    """
    from modules.rules_manager import RuleManager
    rm = RuleManager()
    rule = rm.get_rule(rule_format, rule_id)
    if not rule:
        return f"Rule '{rule_format}/{rule_id}' not found."
    filepath = rule.get("filepath", "")
    if not filepath:
        return "Error: Rule filepath not found."

    if rule_format == "nuclei":
        from modules.tool_wrappers import nuclei_scan
        result = await _run_async(nuclei_scan, target, template=filepath)
    elif rule_format == "yara":
        from modules.tool_wrappers import yara_scan
        result = await _run_async(yara_scan, filepath, target)
    elif rule_format == "semgrep":
        from modules.tool_wrappers import semgrep_scan
        result = await _run_async(semgrep_scan, filepath, target)
    elif rule_format == "codeql":
        from modules.tool_wrappers import codeql_scan
        result = await _run_async(codeql_scan, filepath, target, language=language)
    else:
        return f"Scan not supported for format: {rule_format}"

    return _fmt(result, fmt=rule_format)


@mcp.tool()
async def rules_scan_all(rule_format: str, target: str) -> str:
    """
    Scan a target with ALL rules of a given format (nuclei/yara/semgrep). For codeql, use rules_scan_target per-query.
    Phase: Rule Management
    Related: rules_list, rules_get, rules_create, rules_save, rules_delete, rules_stats, rules_template, rules_bulk_delete, rules_export, rules_import, rules_scan_target
    """
    from modules.rules_manager import get_scan_roots

    if rule_format == "nuclei":
        roots = get_scan_roots("nuclei")
        if not roots:
            return "Nuclei rules directory not found"
        from modules.tool_wrappers import nuclei_scan
        result = await _run_async(nuclei_scan, target,
                                  templates_dir=[str(r) for r in roots])
        return _fmt(result, fmt="nuclei")
    elif rule_format == "yara":
        roots = get_scan_roots("yara")
        if not roots:
            return "YARA rules directory not found"
        from modules.tool_wrappers import yara_scan
        result = await _run_async(yara_scan, [str(r) for r in roots], target)
        return _fmt(result, fmt="yara")
    elif rule_format == "semgrep":
        roots = get_scan_roots("semgrep")
        if not roots:
            return "Semgrep rules directory not found"
        from modules.tool_wrappers import semgrep_scan
        result = await _run_async(semgrep_scan, [str(r) for r in roots], target)
        return _fmt(result, fmt="semgrep")
    elif rule_format == "codeql":
        return "CodeQL batch scan not supported. Use rules_scan_target for single-query scanning."
    else:
        return f"Scan not supported for format: {rule_format}"


# ---------------------------------------------------------------------------
# Papermill notebooks
# ---------------------------------------------------------------------------
@mcp.tool()
def papermill_list() -> str:
    """List available Jupyter notebooks that can be executed via papermill."""
    nbs = list((SCRIPTS_DIR / "automation-tools").glob("*.ipynb"))
    return "\n".join(f"  {nb.stem:<25} {nb.name}" for nb in nbs) or "No notebooks found."


@mcp.tool()
def papermill_run(notebook: str, params: str = "") -> str:
    """
    Execute a Jupyter notebook with papermill. Format params as 'key=value,key=value'.
    Phase: Notebook Execution
    Related: papermill_list
    """
    import papermill as pm
    nb_dir = SCRIPTS_DIR / "automation-tools"
    nb_path = nb_dir / f"{notebook}.ipynb"
    if not nb_path.exists():
        nb_path = nb_dir / notebook
    if not nb_path.exists():
        return f"Notebook not found: {notebook}"
    param_dict = {}
    for p in params.split(","):
        if "=" in p:
            k, v = p.split("=", 1)
            param_dict[k.strip()] = v.strip()
    out_path = Path.cwd() / f"{nb_path.stem}_output.ipynb"
    _run(pm.execute_notebook, str(nb_path), str(out_path),
         parameters=param_dict if param_dict else None, kernel_name="python3")
    return f"Notebook executed: {out_path}"


# ---------------------------------------------------------------------------
# DNS / Network
# ---------------------------------------------------------------------------
@mcp.tool()
async def dns_track_domain(domain: str, interval: int = 300, duration: int = 0) -> str:
    """
    Track DNS resolutions for a domain over time (detect load balancers, CDN, fast-flux).
    Phase: DNS / Network
    """
    from modules.tool_wrappers import dns_track
    history = await _run_async(dns_track, domain, interval=interval, duration=duration)
    records = history.get(domain, [])
    return f"Tracked {len(records)} DNS resolutions for {domain}"


# ---------------------------------------------------------------------------
# Case Management
# ---------------------------------------------------------------------------
@mcp.tool()
def case_list() -> str:
    """List all pentest/forensic cases with status and creation date."""
    cases = _run(CaseManager().list_cases)
    if not cases:
        return "No cases found."
    return "\n".join(f"  {c['case_id']:<30} {c.get('status','?'):<10} {c.get('created','')[:10]}" for c in cases)


@mcp.tool()
def case_create(case_id: str, client: str = "", case_type: str = "pentest",
                description: str = "", targets: str = "",
                goals: str = "") -> str:
    """Create a new case with optional client, description, targets, and goals.

    Valid case types: pentest, pentest_web, pentest_external, pentest_internal_ad,
    pentest_cloud, pentest_physical, ir, forensics, osint.
    Goals are pipe-separated for multiple (e.g. 'goal1|goal2|goal3').
    Phase: Case Management
    Related: case_list, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done, case_task_list
    """
    target_list = [t.strip() for t in targets.split(",") if t.strip()] if targets else []
    goal_list = [g.strip() for g in goals.split("|") if g.strip()] if goals else []
    try:
        _run(CaseManager().create, case_id, client=client, case_type=case_type,
             description=description, targets=target_list, goals=goal_list)
        return f"Case '{case_id}' created (type: {case_type}, goals: {len(goal_list)})"
    except ValueError as e:
        return f"Error: {e}"


@mcp.tool()
def case_goal_add(case_id: str, goal: str) -> str:
    """
    Add an analysis goal to a case. Required for all case types.
    Phase: Case Management
    Related: case_list, case_create, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done, case_task_list
    """
    r = _run(CaseManager().goal_add, case_id, goal)
    if r is None:
        return "Case not found"
    return f"Goal added: {goal}\nAll goals: {r.get('goals', [])}"


@mcp.tool()
def case_goal_list(case_id: str) -> str:
    """
    List all analysis goals for a case.
    Phase: Case Management
    Related: case_list, case_create, case_goal_add, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done, case_task_list
    """
    result = _run(CaseManager().goal_list, case_id)
    if isinstance(result, dict) and "error" in result:
        return result["error"]
    if isinstance(result, dict):
        result = result.get("goals", [])
    if not result:
        return "No goals defined for this case."
    return "\n".join(f"  [{i}] {g}" for i, g in enumerate(result))


# ---------------------------------------------------------------------------
# Incident Response tools
# ---------------------------------------------------------------------------
@mcp.tool()
def ir_timeline_add(case_id: str, timestamp: str, event: str,
                    severity: str = "info", source: str = "") -> str:
    """
    Add a timestamped event to the IR timeline.
    Phase: Incident Response
    Related: ir_timeline_list, ir_ttp_add, ir_ttp_list, ir_containment_add, ir_containment_list, ir_summary
    """
    r = _run(CaseManager().ir_timeline_add, case_id, timestamp=timestamp,
             event=event, severity=severity, source=source)
    if r is None:
        return "Case not found"
    return f"Timeline event added: [{severity}] {event}"


@mcp.tool()
def ir_timeline_list(case_id: str) -> str:
    """
    List all IR timeline events for a case.
    Phase: Incident Response
    Related: ir_timeline_add, ir_ttp_add, ir_ttp_list, ir_containment_add, ir_containment_list, ir_summary
    """
    events = _run(CaseManager().ir_timeline_list, case_id)
    if not events:
        return "No timeline events."
    lines = [f"IR Timeline ({len(events)} events):"]
    for e in events:
        lines.append(f"  [{e.get('severity','?')}] {e.get('timestamp','')} — {e.get('event','')[:80]}")
    return "\n".join(lines)


@mcp.tool()
def ir_ttp_add(case_id: str, tactic: str, technique: str,
               technique_id: str = "", notes: str = "") -> str:
    """
    Log a MITRE ATT&CK TTP observed during incident response.
    Phase: Incident Response
    Related: ir_timeline_add, ir_timeline_list, ir_ttp_list, ir_containment_add, ir_containment_list, ir_summary
    """
    r = _run(CaseManager().ir_ttp_add, case_id, tactic=tactic,
             technique=technique, technique_id=technique_id, notes=notes)
    if r is None:
        return "Case not found"
    return f"TTP logged: {tactic} / {technique} ({technique_id})"


@mcp.tool()
def ir_ttp_list(case_id: str) -> str:
    """
    List all logged MITRE ATT&CK TTPs.
    Phase: Incident Response
    Related: ir_timeline_add, ir_timeline_list, ir_ttp_add, ir_containment_add, ir_containment_list, ir_summary
    """
    ttps = _run(CaseManager().ir_ttp_list, case_id)
    if not ttps:
        return "No TTPs logged."
    lines = [f"TTPs ({len(ttps)}):"]
    for t in ttps:
        lines.append(f"  {t.get('technique_id','')} {t.get('tactic','')} — {t.get('technique','')}")
    return "\n".join(lines)


@mcp.tool()
def ir_containment_add(case_id: str, action: str,
                       status: str = "pending", owner: str = "") -> str:
    """
    Document a containment/remediation step.
    Phase: Incident Response
    Related: ir_timeline_add, ir_timeline_list, ir_ttp_add, ir_ttp_list, ir_containment_list, ir_summary
    """
    r = _run(CaseManager().ir_containment_add, case_id, action=action,
             status=status, owner=owner)
    if r is None:
        return "Case not found"
    return f"Containment step: {r.get('id','?')} — {action[:60]}"


@mcp.tool()
def ir_containment_list(case_id: str) -> str:
    """
    List all containment steps.
    Phase: Incident Response
    Related: ir_timeline_add, ir_timeline_list, ir_ttp_add, ir_ttp_list, ir_containment_add, ir_summary
    """
    steps = _run(CaseManager().ir_containment_list, case_id)
    if not steps:
        return "No containment steps."
    lines = [f"Containment ({len(steps)}):"]
    for s in steps:
        lines.append(f"  [{s.get('id','?')}] [{s.get('status','?')}] {s.get('action','')[:80]}")
    return "\n".join(lines)


@mcp.tool()
def ir_summary(case_id: str) -> str:
    """
    Get a summary of all IR data for a case.
    Phase: Incident Response
    Related: ir_timeline_add, ir_timeline_list, ir_ttp_add, ir_ttp_list, ir_containment_add, ir_containment_list
    """
    s = _run(CaseManager().ir_summary, case_id)
    if s.get("error"):
        return f"Error: {s['error']}"
    return (f"IR Summary — {case_id}\n"
            f"  Timeline events: {s.get('timeline_events', 0)}\n"
            f"  TTPs: {s.get('ttps', 0)}\n"
            f"  Containment: {s.get('containment_steps', 0)} ({s.get('containment_done', 0)} done)\n"
            f"  Severity: {s.get('severity_counts', {})}")


@mcp.tool()
def case_info(case_id: str) -> str:
    """
    Get detailed case information including evidence count, findings, tasks, and scope.
    Phase: Case Management
    Related: case_list, case_create, case_goal_add, case_goal_list, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done, case_task_list
    """
    info = _run(CaseManager().info, case_id)
    if not info:
        return f"Case '{case_id}' not found."
    lines = [
        f"Case: {info.get('case_id', '?')}",
        f"  Client:     {info.get('client', 'N/A')}",
        f"  Type:       {info.get('type', '?')}",
        f"  Status:     {info.get('status', '?')}",
        f"  Created:    {info.get('created', '?')[:19]}",
        f"  Evidence:   {info.get('_evidence_count', 0)} items",
        f"  Findings:   {info.get('_findings_total', 0)} total",
    ]
    by_sev = info.get('_findings_by_severity', {})
    if by_sev:
        lines.append(f"  By severity: {', '.join(f'{k}={v}' for k, v in by_sev.items())}")
    lines.append(f"  Scope:      {info.get('_scope_count', 0)} targets")
    lines.append(f"  Tasks:      {info.get('_tasks_done', 0)}/{info.get('_tasks_total', 0)} done")
    return "\n".join(lines)


@mcp.tool()
def case_close(case_id: str) -> str:
    """
    Close a case by ID.
    Phase: Case Management
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done, case_task_list
    """
    _run(CaseManager().update_status, case_id, "closed")
    return f"Case '{case_id}' closed."


@mcp.tool()
def case_archive(case_id: str) -> str:
    """
    Compress a closed case to a tar.gz archive and remove the live directory.
    Phase: Case Management
    Related: case_unarchive, case_delete, case_list, case_create, case_info, case_close
    """
    result = _run(CaseManager().archive_case, case_id)
    return (f"Case '{case_id}' archived: {result['archived_size']} bytes "
            f"(was {result['original_size']}, saved {result['savings_pct']}%)")


@mcp.tool()
def case_unarchive(case_id: str) -> str:
    """
    Extract a tar.gz archive back to a live case directory.
    Phase: Case Management
    Related: case_archive, case_delete, case_list, case_create, case_info, case_close
    """
    _run(CaseManager().unarchive_case, case_id)
    return f"Case '{case_id}' unarchived successfully."


@mcp.tool()
def case_delete(case_id: str) -> str:
    """
    Permanently delete a case directory and all its data.
    Phase: Case Management
    Related: case_archive, case_unarchive, case_list, case_create, case_info, case_close
    """
    success = _run(CaseManager().delete, case_id)
    if success:
        return f"Case '{case_id}' permanently deleted."
    return f"Error: Case '{case_id}' not found."


@mcp.tool()
def case_evidence_add(case_id: str, filepath: str, category: str = "evidence",
                      description: str = "") -> str:
    """
    Add an evidence file to a case with SHA256/MD5 hashing for chain of custody.
    Phase: Case Management
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done, case_task_list
    """
    _require(case_id, "case_id")
    _require(filepath, "filepath")
    src = Path(filepath)
    if not src.exists():
        return f"File not found: {filepath}"
    max_size = 100 * 1024 * 1024
    if src.stat().st_size > max_size:
        return f"File too large: {src.stat().st_size:,} bytes (max {max_size:,})"
    blocked = {".exe", ".dll", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".msi", ".jar"}
    if src.suffix.lower() in blocked:
        return f"File type '{src.suffix}' not allowed as evidence"
    record = _run(CaseManager().add_evidence, case_id, filepath,
                  category=category, description=description)
    if not record:
        return f"Failed to add evidence (case '{case_id}' not found or file missing)"
    return (f"Evidence added: {record['filename']} ({record['size']:,} bytes)\n"
            f"  SHA256: {record['sha256']}\n  MD5:    {record['md5']}")


@mcp.tool()
def case_evidence_verify(case_id: str) -> str:
    """
    Verify all evidence files in a case by re-computing hashes and comparing to manifest.
    Phase: Case Management
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_scope_add, case_scope_check, case_task_add, case_task_done, case_task_list
    """
    results = _run(CaseManager().verify_evidence, case_id)
    if not results:
        return f"No evidence found for case '{case_id}'"
    lines = []
    for r in results:
        status_icon = "VALID" if r.get("status") == "valid" else r.get("status", "?")
        lines.append(f"  {r.get('filename', '?'):<30} {status_icon}")
    return "\n".join(lines)


@mcp.tool()
def case_scope_add(case_id: str, target: str, in_scope: bool = True) -> str:
    """
    Add a target to case scope (in-scope or out-of-scope).
    Phase: Case Management
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_check, case_task_add, case_task_done, case_task_list
    """
    _run(CaseManager().scope_add, case_id, target, in_scope=in_scope)
    return f"Target '{target}' added to {'in' if in_scope else 'out of'}-scope for '{case_id}'"


@mcp.tool()
def case_scope_check(case_id: str, target: str) -> str:
    """
    Check if a target is in scope for a case. Returns in_scope status and reason.
    Phase: Case Management
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_task_add, case_task_done, case_task_list
    """
    result = _run(CaseManager().scope_check, case_id, target)
    return f"Target '{target}': {'IN SCOPE' if result['in_scope'] else 'OUT OF SCOPE'} — {result['reason']}"


@mcp.tool()
def case_scope_remove(case_id: str, target: str) -> str:
    """
    Remove a target from case scope (in-scope or out-of-scope).
    Phase: Case Management
    Related: case_scope_add, case_scope_check, case_scope_list, case_info, case_list, case_create
    """
    _run(CaseManager().scope_remove, case_id, target)
    return f"Target '{target}' removed from scope for '{case_id}'"


@mcp.tool()
def case_scope_list(case_id: str) -> str:
    """
    List all in-scope and out-of-scope targets for a case.
    Phase: Case Management
    Related: case_scope_add, case_scope_check, case_scope_remove, case_info, case_list, case_create
    """
    scope = _run(CaseManager().scope_list, case_id)
    lines = [f"Scope for '{case_id}':"]
    in_scope = scope.get("in_scope", [])
    out_scope = scope.get("out_of_scope", [])
    if in_scope:
        lines.append("  In scope:")
        for t in in_scope:
            lines.append(f"    {t}")
    if out_scope:
        lines.append("  Out of scope:")
        for t in out_scope:
            lines.append(f"    {t}")
    if not in_scope and not out_scope:
        lines.append("  (no scope restrictions defined)")
    return "\n".join(lines)


@mcp.tool()
def case_task_add(case_id: str, description: str, priority: str = "medium") -> str:
    """
    Add a task to the case checklist.
    Phase: Case Management
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_done, case_task_list
    """
    task = _run(CaseManager().task_add, case_id, description, priority=priority)
    return f"Task {task['id']} added to '{case_id}': {task['description']} [{task['priority']}]"


@mcp.tool()
def case_task_done(case_id: str, task_id: str) -> str:
    """
    Mark a task as completed in the case checklist.
    Phase: Case Management
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_list
    """
    task = _run(CaseManager().task_done, case_id, task_id)
    if not task:
        return f"Task '{task_id}' not found in case '{case_id}'"
    return f"Task {task_id} marked done: {task['description']}"


@mcp.tool()
def case_task_list(case_id: str, show_done: bool = False) -> str:
    """
    List pending (or all) tasks for a case.
    Phase: Case Management
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done
    """
    tasks = _run(CaseManager().task_list, case_id, show_done=show_done)
    if not tasks:
        return "No tasks found."
    return "\n".join(
        f"  {t['id']:<8} {'[x]' if t.get('done') else '[ ]'} {t['description']:<50} [{t.get('priority','?')}]"
        for t in tasks
    )


# ---------------------------------------------------------------------------
# Checklist
# ---------------------------------------------------------------------------
@mcp.tool()
def case_checklist_templates() -> str:
    """
    List all available checklist templates with item counts.
    Phase: Case Management
    Related: case_checklist_init, case_checklist_list, case_checklist_template_get
    """
    
    templates = _run(list_checklist_templates)
    if not templates:
        return "No checklist templates found."
    return "\n".join(
        f"  {t['id']:<45} {t['title']:<50} {t['item_count']:3d} items"
        for t in templates
    )


@mcp.tool()
def case_checklist_template_get(template_id: str) -> str:
    """
    Get the full YAML source and parsed metadata of a checklist template.
    Phase: Case Management
    Related: case_checklist_templates, case_checklist_init
    """
    templates = _run(list_checklist_templates)
    match = [t for t in templates if t["id"] == template_id]
    if not match:
        return f"Template '{template_id}' not found."
    source = _run(get_template_source, template_id)
    return json.dumps({"metadata": match[0], "source": source}, indent=2)


@mcp.tool()
def case_checklist_init(case_id: str, template_id: str,
                        replace: bool = False) -> str:
    """
    Initialize a new checklist instance in a case from a template.
    Phase: Case Management
    Related: case_checklist_templates, case_checklist_list, case_checklist_update, case_checklist_delete
    """
    _require(case_id, "case_id")
    _require(template_id, "template_id")
    from modules.checklist_manager import ChecklistInstance
    cl = ChecklistInstance(_case_dir(case_id))
    result = _run(cl.initialize, template_id, replace=replace)
    if "error" in result:
        return f"Error: {result['error']}"
    iid = result.get("instance_id", "?")[:8]
    count = len(result.get("items", {}))
    return f"Checklist '{template_id}' initialized (id={iid}, {count} items) — {'replaced' if replace else 'appended'}"


@mcp.tool()
def case_checklist_list(case_id: str) -> str:
    """
    List checklist instances for a case with progress summary.
    Phase: Case Management
    Related: case_checklist_init, case_checklist_update, case_checklist_delete, case_checklist_items
    """
    _require(case_id, "case_id")
    from modules.checklist_manager import ChecklistInstance
    cl = ChecklistInstance(_case_dir(case_id))
    instances = _run(cl.get)
    if not instances:
        return f"No checklists for '{case_id}'. Use case_checklist_init to create one."
    lines = []
    for inst in instances:
        iid = inst.get("instance_id", "?")
        title = inst.get("title", "Untitled")
        items = inst.get("items", {})
        total = len(items)
        passed = sum(1 for v in items.values() if v.get("status") == "passed")
        failed = sum(1 for v in items.values() if v.get("status") == "failed")
        na = sum(1 for v in items.values() if v.get("status") == "not_applicable")
        ip = sum(1 for v in items.values() if v.get("status") == "in_progress")
        ns = sum(1 for v in items.values() if v.get("status") == "not_started")
        pct = round((passed + na) / total * 100) if total else 0
        lines.append(f"  [{iid[:8]}] {title}  ({pct}% — {passed} passed, {failed} failed, {ip} in_progress, {ns} not_started, {na} n/a)")
    return "\n".join(lines)


@mcp.tool()
def case_checklist_update(case_id: str, item_id: str, status: str,
                          notes: str = "", instance_id: str = "") -> str:
    """
    Update a checklist item's status (not_started, in_progress, passed, failed, not_applicable).
    Phase: Case Management
    Related: case_checklist_list, case_checklist_items, case_checklist_init
    """
    _require(case_id, "case_id")
    _require(item_id, "item_id")
    _require(status, "status")
    from modules.checklist_manager import ChecklistInstance
    cl = ChecklistInstance(_case_dir(case_id))
    result = _run(cl.update_item, item_id, status=status,
                  notes=notes or None, instance_id=instance_id)
    if result:
        return f"  {item_id} -> {status}"
    return f"Item '{item_id}' not found"


@mcp.tool()
def case_checklist_delete(case_id: str, instance_id: str) -> str:
    """
    Delete a checklist instance from a case.
    Phase: Case Management
    Related: case_checklist_list, case_checklist_init
    """
    _require(case_id, "case_id")
    _require(instance_id, "instance_id")
    from modules.checklist_manager import ChecklistInstance
    cl = ChecklistInstance(_case_dir(case_id))
    ok = _run(cl.delete_instance, instance_id)
    return "Deleted." if ok else "Instance not found."


@mcp.tool()
def case_checklist_items(case_id: str, instance_id: str = "",
                         status_filter: str = "") -> str:
    """
    Get checklist items grouped by category with current status.
    Phase: Case Management
    Related: case_checklist_list, case_checklist_update, case_checklist_init
    """
    _require(case_id, "case_id")
    from modules.checklist_manager import ChecklistInstance
    cl = ChecklistInstance(_case_dir(case_id))
    cats = _run(cl.items_by_category, instance_id=instance_id)
    if not cats:
        return f"No checklist items for '{case_id}'."
    lines = []
    for cat in cats:
        if status_filter:
            cat["items"] = [i for i in cat.get("items", [])
                            if i.get("status") == status_filter]
            cat["total"] = len(cat["items"])
        if not cat.get("items"):
            continue
        label = f"{cat.get('instance_title', cat.get('name',''))} — {cat['name']}"
        lines.append(f"\n{'='*60}")
        lines.append(f"  {label}  ({cat.get('passed',0)} passed, {cat.get('failed',0)} failed)")
        lines.append(f"{'='*60}")
        for item in cat.get("items", []):
            st = item.get("status", "not_started")
            icons = {"passed": "\u2713", "failed": "\u2717",
                     "in_progress": "\u25D8", "not_started": "\u25CB",
                     "not_applicable": "\u2014"}
            icon = icons.get(st, "\u25CB")
            finding = f" [{item.get('finding_id','')}]" if item.get("finding_id") else ""
            notes = f" — {item['notes'][:60]}" if item.get("notes") else ""
            lines.append(f"    {icon} {item['id']:<12} {item['description']:<55} {st:<14}{finding}{notes}")
    return "\n".join(lines)


@mcp.tool()
def case_checklist_progress(case_id: str, instance_id: str = "") -> str:
    """
    Get progress summary for a checklist instance.
    Phase: Case Management
    Related: case_checklist_list, case_checklist_items, case_checklist_update
    """
    _require(case_id, "case_id")
    from modules.checklist_manager import ChecklistInstance
    cl = ChecklistInstance(_case_dir(case_id))
    prog = _run(cl.get_progress, instance_id=instance_id)
    return json.dumps(prog, indent=2)


@mcp.tool()
def case_checklist_finding(case_id: str, item_id: str, finding_id: str,
                           instance_id: str = "") -> str:
    """
    Link a finding to a checklist item (associate a proven finding with a checklist item).
    Phase: Case Management
    Related: case_checklist_update, case_checklist_items, case_finding_add
    """
    _require(case_id, "case_id")
    _require(item_id, "item_id")
    _require(finding_id, "finding_id")
    from modules.checklist_manager import ChecklistInstance
    cl = ChecklistInstance(_case_dir(case_id))
    result = _run(cl.set_finding, item_id, finding_id, instance_id=instance_id)
    if result:
        return f"Finding {finding_id} linked to {item_id}"
    return f"Item '{item_id}' not found"


@mcp.tool()
def case_checklist_from_findings(case_id: str, title: str = "",
                                 replace: bool = False) -> str:
    """
    Build a checklist instance directly from a case's findings (grouped by severity).
    Each finding becomes an item pre-linked via finding_id.
    Phase: Case Management
    Related: case_checklist_init, case_checklist_list, case_checklist_update, case_finding_add
    """
    _require(case_id, "case_id")
    from modules.checklist_manager import ChecklistInstance
    cl = ChecklistInstance(_case_dir(case_id))
    db = FindingsDB(_case_dir(case_id))
    findings = _run(db.list)
    if not findings:
        return "No findings to build a checklist from."
    result = _run(cl.from_findings, findings, title=title, replace=replace)
    if "error" in result:
        return f"Error: {result['error']}"
    iid = result.get("instance_id", "?")[:8]
    return (f"Checklist built from {len(findings)} findings (id={iid}, "
            f"{len(result.get('items', {}))} items) — {'replaced' if replace else 'appended'}")


@mcp.tool()
def case_export(case_id: str, fmt: str = "sarif", output: str = "",
                include_checklist: bool = True) -> str:
    """
    Export a case's findings in an interoperable format.
    fmt: sarif (SARIF 2.1.0) or xccdf (XCCDF 1.2 SCAP results).
    include_checklist (xccdf only): also emit checklist controls as scored rules.
    Writes to cases/<case_id>/exports/ unless output is given.
    Phase: Case Management
    Related: case_finding_add, case_checklist_list, case_report_engagement
    """
    _require(case_id, "case_id")
    from modules.compliance_export import export_case as _export
    result = _run(_export, case_id, fmt=fmt, output=output,
                  include_checklist=include_checklist)
    if "error" in result:
        return result["error"]
    parts = [f"Exported {result.get('format', '?')} -> {result.get('path', '')}"]
    for k in ("findings", "checklist_items", "total_rules", "passed", "score"):
        if k in result:
            parts.append(f"  {k}: {result[k]}")
    if result.get("validate_hint"):
        parts.append(f"  Validate: {result['validate_hint']}")
    return "\n".join(parts)


@mcp.tool()
def case_checklist_status(case_id: str, status: str = "",
                          instance_id: str = "") -> str:
    """
    List checklist items filtered by status.
    Phase: Case Management
    Related: case_checklist_items, case_checklist_update, case_checklist_list
    """
    _require(case_id, "case_id")
    from modules.checklist_manager import ChecklistInstance
    cl = ChecklistInstance(_case_dir(case_id))
    items = _run(cl.items_by_status, status=status, instance_id=instance_id)
    if not items:
        return f"No items with status '{status or 'any'}'."
    lines = []
    for tmpl, meta, cat in items:
        st = meta.get("status", "not_started")
        icons = {"passed": "\u2713", "failed": "\u2717",
                 "in_progress": "\u25D8", "not_started": "\u25CB",
                 "not_applicable": "\u2014"}
        icon = icons.get(st, "\u25CB")
        finding = f" [{meta.get('finding_id','')}]" if meta.get("finding_id") else ""
        lines.append(f"    {icon} {tmpl['id']:<12} {cat:<25} {tmpl['description']:<55} {st:<14}{finding}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Retest
# ---------------------------------------------------------------------------
@mcp.tool()
def case_finding_retests(case_id: str, finding_id: str) -> str:
    """
    List all retest entries for a finding.
    Phase: Case Management
    Related: case_finding_retest_add, case_finding_retest_delete
    """
    _require(case_id, "case_id")
    _require(finding_id, "finding_id")
    db = FindingsDB(_case_dir(case_id))
    retests = _run(db.get_retests, finding_id)
    if not retests:
        return f"No retests for finding '{finding_id}'."
    return json.dumps(retests, indent=2)


@mcp.tool()
def case_finding_retest_add(case_id: str, finding_id: str, status: str,
                            notes: str = "", tester: str = "") -> str:
    """
    Add a retest entry to a finding. Status: resolved, not_resolved, partial.
    Phase: Case Management
    Related: case_finding_retests, case_finding_retest_delete, case_finding_add
    """
    _require(case_id, "case_id")
    _require(finding_id, "finding_id")
    _require(status, "status")
    db = FindingsDB(_case_dir(case_id))
    result = _run(db.add_retest, finding_id, status, notes=notes, tester=tester)
    if result:
        return f"Retest {result['id']} added to {finding_id}: {result['status']}"
    return f"Finding '{finding_id}' not found or invalid status"


@mcp.tool()
def case_finding_retest_delete(case_id: str, finding_id: str,
                               retest_id: str) -> str:
    """
    Delete a retest entry from a finding.
    Phase: Case Management
    Related: case_finding_retests, case_finding_retest_add
    """
    _require(case_id, "case_id")
    _require(finding_id, "finding_id")
    _require(retest_id, "retest_id")
    db = FindingsDB(_case_dir(case_id))
    ok = _run(db.delete_retest, finding_id, retest_id)
    return "Deleted." if ok else "Retest not found."


@mcp.tool()
def case_retests_summary(case_id: str) -> str:
    """
    List all findings across a case that have retest data.
    Phase: Case Management
    Related: case_finding_retests, case_finding_retest_add
    """
    _require(case_id, "case_id")
    db = FindingsDB(_case_dir(case_id))
    findings = _run(db.list)
    result = []
    for f in findings:
        retests = f.get("retests", [])
        if retests:
            result.append({
                "finding_id": f["id"],
                "title": f["title"],
                "severity": f["severity"],
                "retest_count": len(retests),
                "last_retest": retests[-1],
            })
    if not result:
        return "No findings with retest data."
    return json.dumps(result, indent=2)


@mcp.tool()
def case_finding_add(case_id: str, title: str, severity: str = "medium",
                     description: str = "", remediation: str = "",
                     source: str = "", cve: str = "", cwe: str = "",
                     impact: str = "", poc: str = "",
                     references: str = "",
                     command_output: str = "",
                     cvss_score: float = None, cvss_vector: str = "",
                     tags: str = "", cpe: str = "") -> str:
    """Add a structured finding to a case (severity: info/low/medium/high/critical).

    Supports optional CVE/CWE references, impact description, PoC, CVSS score/vector,
    tag labels (comma-separated, e.g. 'cwe:79,mitre-attack:T1078.001'), comma-separated
    reference URLs, and a CPE 2.3 identifier (e.g. 'cpe:2.3:a:mitmproxy:mitmproxy:10.2.4:*:*:*:*:*:*:*')
    for the affected component.
    Phase: Case Management
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done
    """
    ref_list = [r.strip() for r in references.split(",") if r.strip()] if references else []
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
    db = FindingsDB(_case_dir(case_id))
    finding = _run(db.add, title, severity=severity, description=description,
                   remediation=remediation, source=source,
                   cve=cve, cwe=cwe, impact=impact, poc=poc,
                   references=ref_list,
                   command_output=command_output,
                   cvss_score=cvss_score, cvss_vector=cvss_vector,
                   tags=tag_list, cpe=cpe)
    parts = [f"Finding {finding['id']} added: {finding['title']} [{finding['severity']}]"]
    if finding.get('cve'):
        parts.append(f"  CVE: {finding['cve']}")
    if finding.get('cwe'):
        parts.append(f"  CWE: {finding['cwe']}")
    if finding.get('cpe'):
        parts.append(f"  CPE: {finding['cpe']}")
    if finding.get('cvss_score') is not None:
        parts.append(f"  CVSS: {finding['cvss_score']} ({finding.get('cvss_vector', '')})")
    if finding.get('tags'):
        parts.append(f"  Tags: {', '.join(finding['tags'])}")
    return "\n".join(parts)


@mcp.tool()
def case_finding_update(case_id: str, finding_id: str,
                        severity: str = "", status: str = "",
                        description: str = "", remediation: str = "",
                        cve: str = "", cwe: str = "", impact: str = "",
                        poc: str = "",
                        command_output: str = "",
                        cvss_score: float = None, cvss_vector: str = "",
                        tags: str = "", cpe: str = "") -> str:
    """
    Update an existing finding's fields. Empty strings are skipped.
    Supports CVSS score/vector, tag labels, and a CPE 2.3 component identifier.
    Phase: Case Management
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done
    """
    db = FindingsDB(_case_dir(case_id))
    kwargs = {}
    for k, v in [("severity", severity), ("status", status),
                 ("description", description), ("remediation", remediation),
                 ("cve", cve), ("cwe", cwe), ("impact", impact), ("poc", poc),
                 ("command_output", command_output),
                 ("cvss_score", cvss_score), ("cvss_vector", cvss_vector),
                 ("cpe", cpe)]:
        if v is not None and v != "":
            kwargs[k] = v
    if tags:
        kwargs["tags"] = [t.strip() for t in tags.split(",") if t.strip()]
    result = _run(db.update, finding_id, **kwargs)
    if not result:
        return f"Finding '{finding_id}' not found in case '{case_id}'"
    return f"Finding {finding_id} updated"


@mcp.tool()
def case_finding_add_tag(case_id: str, finding_id: str, tag: str) -> str:
    """Add a tag (e.g. 'cwe:79', 'mitre-attack:T1078.001') to a finding.
    Phase: Case Management
    Related: case_finding_remove_tag, case_finding_update, findings_list
    """
    db = FindingsDB(_case_dir(case_id))
    result = _run(db.add_tag, finding_id, tag)
    if not result:
        return f"Finding '{finding_id}' not found in case '{case_id}'"
    return f"Tag '{tag}' added to {finding_id}"


@mcp.tool()
def case_finding_remove_tag(case_id: str, finding_id: str, tag: str) -> str:
    """Remove a tag from a finding.
    Phase: Case Management
    Related: case_finding_add_tag, case_finding_update, findings_list
    """
    db = FindingsDB(_case_dir(case_id))
    result = _run(db.remove_tag, finding_id, tag)
    if not result:
        return f"Finding '{finding_id}' not found in case '{case_id}'"
    return f"Tag '{tag}' removed from {finding_id}"


@mcp.tool()
def case_tags_list(case_id: str) -> str:
    """List all tags used across findings in a case with usage counts.
    Phase: Case Management
    Related: findings_list, case_finding_add_tag, case_finding_detail
    """
    db = FindingsDB(_case_dir(case_id))
    tags = _run(db.tags)
    if not tags:
        return "No tags found in this case."
    parts = [f"Tags in {case_id}:"]
    for t, c in sorted(tags.items(), key=lambda x: -x[1]):
        parts.append(f"  {t} ({c}x)")
    return "\n".join(parts)


@mcp.tool()
def tags_search(query: str, namespace: str = "") -> str:
    """Search the built-in tag reference database (CWE, MITRE ATT&CK, OWASP, CAPEC, D3FEND).
    Phase: Reference Data Lookup
    Related: tags_resolve, case_finding_add_tag
    """
    from modules.tag_refs import search as _search
    results = _search(query, namespace)
    if not results:
        return f"No tags found matching '{query}'"
    parts = [f"Tags matching '{query}' ({len(results)}):"]
    for r in results:
        parts.append(f"  {r['tag']} — {r['title']} ({r['display']})")
    return "\n".join(parts)


@mcp.tool()
def tags_resolve(tag: str) -> str:
    """Resolve a single tag string (like 'cwe:79') to its human-readable name and namespace.
    Phase: Reference Data Lookup
    Related: tags_search, case_finding_add_tag
    """
    from modules.tag_refs import resolve as _resolve
    r = _resolve(tag)
    if r.get("namespace") == "custom":
        return f"'{tag}' — not found in reference data (treated as custom)"
    return f"{r['tag']} — {r['title']} ({r['display']})"


@mcp.tool()
def case_finding_link_evidence(case_id: str, finding_id: str,
                               evidence: str) -> str:
    """
    Link evidence file(s) to a finding (comma-separated filenames).
    Phase: Case Management
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done
    """
    db = _run(FindingsDB, _case_dir(case_id))
    f = _run(db.get, finding_id)
    if not f:
        return f"Finding '{finding_id}' not found"
    files = [e.strip() for e in evidence.split(",") if e.strip()]
    existing = set(f.get("evidence_refs", []))
    added = [e for e in files if e not in existing]
    if not added:
        return f"All evidence already linked to {finding_id}"
    _run(db.update, finding_id, evidence_refs=sorted(existing | set(added)))
    return f"Linked {len(added)} evidence file(s) to {finding_id}: {', '.join(added)}"


@mcp.tool()
def case_finding_unlink_evidence(case_id: str, finding_id: str,
                                 evidence: str) -> str:
    """
    Unlink evidence file(s) from a finding (comma-separated filenames).
    Phase: Case Management
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done
    """
    db = _run(FindingsDB, _case_dir(case_id))
    f = _run(db.get, finding_id)
    if not f:
        return f"Finding '{finding_id}' not found"
    files = [e.strip() for e in evidence.split(",") if e.strip()]
    existing = set(f.get("evidence_refs", []))
    removed = [e for e in files if e in existing]
    if not removed:
        return f"None of the specified evidence is linked to {finding_id}"
    _run(db.update, finding_id, evidence_refs=sorted(existing - set(removed)))
    return f"Unlinked {len(removed)} evidence file(s) from {finding_id}: {', '.join(removed)}"


@mcp.tool()
def evidence_list(case_id: str) -> str:
    """
    List all evidence files for a case.
    Phase: Case Management
    Related: evidence_upload, evidence_download_url, evidence_delete, case_finding_link_evidence
    """
    cm = CaseManager()
    info = _run(cm.info, case_id)
    if not info:
        return "Case not found"
    ev = _run(cm.get_evidence, case_id)
    if not ev:
        return "No evidence files."
    lines = [f"Evidence ({len(ev)}):"]
    for e in ev:
        lines.append(f"  {e.get('filename','?'):<40} {e.get('category','?'):<15} {e.get('sha256',''):<20} {e.get('size',0):>8}B  {e.get('timestamp','')[:19]}")
    return "\n".join(lines)


@mcp.tool()
def evidence_upload(case_id: str, filepath: str,
                    category: str = "evidence",
                    description: str = "") -> str:
    """
    Upload a file from disk as evidence for a case. File is copied into the case directory and hashed.
    Phase: Case Management
    Related: evidence_list, evidence_download_url, evidence_delete, case_finding_link_evidence
    """
    from pathlib import Path
    p = Path(filepath)
    if not p.is_file():
        return f"File not found: {filepath}"
    cm = CaseManager()
    rec = _run(cm.add_evidence, case_id, str(p), category, description)
    if not rec:
        return f"Failed to add evidence (check case '{case_id}' exists)"
    return (f"Evidence added: {rec.get('filename','')}\n"
            f"  SHA256: {rec.get('sha256','')}\n"
            f"  Size: {rec.get('size',0)}B\n"
            f"  Category: {rec.get('category','')}\n"
            f"  URL: /case/{case_id}/{rec.get('category','evidence')}/{rec.get('filename','')}")


@mcp.tool()
def evidence_download_url(case_id: str, filename: str) -> str:
    """
    Get the download URL for an evidence file.
    Phase: Case Management
    Related: evidence_list, evidence_upload, evidence_delete
    """
    cm = CaseManager()
    ev = _run(cm.get_evidence, case_id)
    if not ev:
        return "No evidence found"
    match = [e for e in ev if e.get("filename") == filename]
    if not match:
        return f"Evidence '{filename}' not found in case {case_id}"
    e = match[0]
    return (f"Evidence: {e.get('filename','')}\n"
            f"  Download URL: /case/{case_id}/{e.get('category','evidence')}/{e.get('filename','')}\n"
            f"  SHA256: {e.get('sha256','')}\n"
            f"  Size: {e.get('size',0)}B\n"
            f"  Category: {e.get('category','')}\n"
            f"  Timestamp: {e.get('timestamp','')}")


@mcp.tool()
def evidence_delete(case_id: str, filename: str) -> str:
    """
    Delete an evidence record from a case manifest by filename.
    Phase: Case Management
    Related: evidence_list, evidence_upload, evidence_download_url
    """
    cm = CaseManager()
    info = _run(cm.info, case_id)
    if not info:
        return "Case not found"
    deleted = _run(cm.delete_evidence, case_id, filename)
    if deleted:
        return f"Evidence '{filename}' deleted from case {case_id}"
    return f"Evidence '{filename}' not found"


@mcp.tool()
def case_update_meta(case_id: str, client: str = "",
                     description: str = "", assessment_dates: str = "",
                     executive_summary: str = "", key_observations: str = "",
                     recommendations: str = "", methodology_tools: str = "",
                     contacts: str = "") -> str:
    """Update case metadata fields used in report generation.

    Set assessment_dates to something like '2026-05-01 to 2026-05-15'.
    contacts can be a Markdown table or free text.
    methodology_tools is a comma-separated list of tools used.
    Phase: Case Management
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done
    """
    kwargs = {}
    for k, v in [("client", client), ("description", description),
                 ("assessment_dates", assessment_dates),
                 ("executive_summary", executive_summary),
                 ("key_observations", key_observations),
                 ("recommendations", recommendations),
                 ("methodology_tools", methodology_tools),
                 ("contacts", contacts)]:
        if v:
            kwargs[k] = v
    manifest = _run(CaseManager().set_meta, case_id, **kwargs)
    if not manifest:
        return f"Case '{case_id}' not found"
    return f"Case '{case_id}' metadata updated ({len(kwargs)} fields)"


@mcp.tool()
def case_strength_add(case_id: str, text: str) -> str:
    """
    Add an identified strength/positive finding to a case.
    Phase: Case Management
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done
    """
    result = _run(CaseManager().add_strength, case_id, text)
    if not result:
        return f"Case '{case_id}' not found"
    return f"Strength added to '{case_id}' ({len(result['strengths'])} total)"


@mcp.tool()
def case_strength_list(case_id: str) -> str:
    """
    List identified strengths for a case.
    Phase: Case Management
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done
    """
    strengths = _run(CaseManager().list_strengths, case_id)
    if not strengths:
        return "No strengths documented."
    return "\n".join(f"  {i+1}. {s}" for i, s in enumerate(strengths))


@mcp.tool()
def case_weakness_add(case_id: str, text: str) -> str:
    """
    Add an identified weakness/vulnerability observation to a case.
    Phase: Case Management
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done
    """
    result = _run(CaseManager().add_weakness, case_id, text)
    if not result:
        return f"Case '{case_id}' not found"
    return f"Weakness added to '{case_id}' ({len(result['weaknesses'])} total)"


@mcp.tool()
def case_weakness_list(case_id: str) -> str:
    """
    List identified weaknesses for a case.
    Phase: Case Management
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done
    """
    weaknesses = _run(CaseManager().list_weaknesses, case_id)
    if not weaknesses:
        return "No weaknesses documented."
    return "\n".join(f"  {i+1}. {s}" for i, s in enumerate(weaknesses))


@mcp.tool()
def case_report_engagement(case_id: str) -> str:
    """
    Generate an HTML + Markdown engagement report from case data, findings, and evidence.
    Phase: Case Management
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done
    """
    from modules.report_generator import generate_engagement_report
    case_dir = _case_dir(case_id)
    if not case_dir.exists():
        return f"Case '{case_id}' not found"
    result = _run(generate_engagement_report, case_dir)
    return f"Engagement report generated: {result}"


@mcp.tool()
def case_report_obsidian(case_id: str, write_sections: bool = False,
                         formats: str = "md,html,docx,pdf") -> str:
    """Generate an Obsidian-compatible pentest report matching the standard template structure.

    Outputs to Obsidian vault Pentests/c-reports/{case_id}/. Formats: comma-separated
    list (md,html,docx,pdf). Produces ![[...]] embedded Markdown plus flat Markdown,
    and converts to HTML, DOCX, and PDF if converters are available.
    Phase: Case Management
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done
    """
    from modules.report_generator import generate_obsidian_report
    case_dir = _case_dir(case_id)
    if not case_dir.exists():
        return f"Case '{case_id}' not found"
    fmt_list = [f.strip() for f in formats.split(",") if f.strip()]
    results = _run(generate_obsidian_report, case_dir, write_sections=write_sections,
                   formats=fmt_list)
    lines = [f"Obsidian report generated for case '{case_id}':"]
    for ext, path in results.items():
        lines.append(f"  .{ext} → {path}")
    return "\n".join(lines)


@mcp.tool()
def case_report_generate(case_id: str, formats: str = "md") -> str:
    """
    Generate a report for a case in the given format(s). Uses Obsidian report generator.
    Phase: Case Management
    Related: case_report_engagement, case_report_obsidian, case_info, case_list, case_create
    """
    from modules.report_generator import generate_obsidian_report
    case_dir = _case_dir(case_id)
    if not case_dir.exists():
        return f"Case '{case_id}' not found"
    fmt_list = [f.strip() for f in formats.split(",") if f.strip()]
    try:
        results = _run(generate_obsidian_report, case_dir, write_sections=True,
                       formats=fmt_list)
        lines = [f"Report generated for case '{case_id}':"]
        for ext, path in results.items():
            if path:
                lines.append(f"  .{ext} → {path}")
        return "\n".join(lines) if len(lines) > 1 else "Report generated (no output paths returned)"
    except Exception as e:
        return f"Error generating report: {str(e)}"


@mcp.tool()
def case_timeline(case_id: str) -> str:
    """
    Generate an HTML timeline visualization from case activity (evidence, findings, runbooks).
    Phase: Case Management
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done
    """
    from modules.report_generator import generate_timeline_html
    case_dir = _case_dir(case_id)
    if not case_dir.exists():
        return f"Case '{case_id}' not found"
    html = _run(generate_timeline_html, case_dir)
    out_path = case_dir / "reports" / "timeline.html"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html)
    return f"Timeline generated: {out_path}"


# ---------------------------------------------------------------------------
# Doctor / Health
# ---------------------------------------------------------------------------
@mcp.tool()
def doctor_run() -> str:
    """Run system health checks: verify installed tools, wordlists, services, and config paths."""
    from modules.doctor import Doctor
    d = Doctor()
    _run(d.run_all)
    return d.summary()


# ---------------------------------------------------------------------------
# Tools directory enumeration
# ---------------------------------------------------------------------------
@mcp.tool()
def tools_discover(filter: str = "") -> str:
    """
    Scan /share/tools/ and list available tools, optionally filtered by keyword.
    Phase: Tool Discovery
    Related: tools_search, tools_run_in_dir
    """
    td = Path(_TOOLS_DIR)
    if not td.is_dir():
        return f"Tools directory not found: {_TOOLS_DIR}"
    dirs, exes, scripts, others = [], [], [], []
    for e in td.iterdir():
        name = e.name
        if filter and filter.lower() not in name.lower():
            continue
        if e.is_dir():
            dirs.append(name)
        elif e.suffix in (".py", ".sh", ".ps1"):
            scripts.append(name)
        elif e.suffix in ("", ".exe") and not name.startswith("."):
            exes.append(name)
        else:
            others.append(name)
    lines = [f"Tools in {_TOOLS_DIR} (filter: '{filter or 'all'}'):"]
    lines.append(f"\n  [{len(dirs)} directories]")
    for d in sorted(dirs)[:50]:
        lines.append(f"    {d}/")
    lines.append(f"\n  [{len(exes)} executables]")
    for e in sorted(exes)[:30]:
        lines.append(f"    {e}")
    lines.append(f"\n  [{len(scripts)} scripts]")
    for s in sorted(scripts)[:20]:
        lines.append(f"    {s}")
    if len(dirs)+len(exes)+len(scripts) > 100:
        lines.append(f"\n  ... and {len(others)} other files")
    return "\n".join(lines)


@mcp.tool()
def tools_search(name: str) -> str:
    """
    Search for a tool by name in /share/tools/, return full path and type.
    Phase: Tool Discovery
    Related: tools_discover, tools_run_in_dir
    """
    td = Path(_TOOLS_DIR)
    if not td.is_dir():
        return f"Tools directory not found: {_TOOLS_DIR}"
    results = []
    for e in td.iterdir():
        if name.lower() in e.name.lower():
            kind = "dir" if e.is_dir() else "file"
            size = "" if e.is_dir() else f" ({e.stat().st_size:,} bytes)"
            results.append(f"  {kind:5} {e.name}{size}")
    if not results:
        return f"No tools matching '{name}' found in {_TOOLS_DIR}"
    return f"Found {len(results)} match(es):\n" + "\n".join(sorted(results))


@mcp.tool()
def tools_run_in_dir(tool_name: str, args: str = "",
                     workdir_subpath: str = "") -> str:
    """
    Run a tool from /share/tools/ in its directory (cd, run, restore).
    Phase: Tool Discovery
    Related: tools_discover, tools_search
    """
    td = Path(_TOOLS_DIR)
    tool_path = td / tool_name
    if not tool_path.exists():
        return f"Tool not found: {tool_name} in {_TOOLS_DIR}"
    workdir = tool_path if tool_path.is_dir() else tool_path.parent
    if workdir_subpath:
        workdir = workdir / workdir_subpath
    if not workdir.is_dir():
        return f"Working directory not found: {workdir}"
    entry = tool_path / tool_path.name if tool_path.is_dir() else tool_path
    cmd_list = [str(entry)] + (args.split() if args else [])
    try:
        r = subprocess.run(cmd_list, cwd=str(workdir), capture_output=True,
                           text=True, timeout=_TIMEOUT)
        out = r.stdout[-2000:] + "\n...(truncated)" if len(r.stdout) > 2000 else r.stdout
        err = r.stderr[-1000:] + "\n...(truncated)" if len(r.stderr) > 1000 else r.stderr
        result = f"Exit code: {r.returncode}"
        if out:
            result += f"\n--- stdout ---\n{out}"
        if err:
            result += f"\n--- stderr ---\n{err}"
        return result
    except subprocess.TimeoutExpired:
        return f"Error: timed out after {_TIMEOUT}s"
    except Exception as e:
        return f"Error running {tool_name}: {e}"


@mcp.tool()
def daemon_list() -> str:
    """
    List background processes started by this server (chisel/ligolo/etc.) with
    PID, command and liveness. Dead processes are pruned from the registry.
    Phase: Utility / Infrastructure
    """
    rows = _daemons_snapshot()
    if not rows:
        return "No tracked daemons."
    lines = [f"{'Name':<18} {'PID':<8} Alive  Started (UTC)  Command"]
    for d in rows:
        lines.append(f"{d['name']:<18} {d['pid']:<8} {str(d['alive']):<5}  "
                     f"{d['started'][:19]}  {d['cmd'][:60]}")
    return "\n".join(lines)


_DAEMONS: dict = {}
_DAEMON_PROCS: dict = {}
_DAEMONS_LOCK = threading.Lock()


def _register_daemon(name: str, proc) -> str:
    """Track a spawned background process so it can be listed/cleaned up."""
    with _DAEMONS_LOCK:
        _DAEMON_PROCS[name] = proc
        _DAEMONS[name] = {
            "name": name,
            "pid": proc.pid,
            "cmd": " ".join(getattr(proc, "args", [])) or "?",
            "started": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
    return proc.pid


def _daemons_snapshot() -> list:
    """Return live daemon metadata, pruning dead entries from the registry."""
    with _DAEMONS_LOCK:
        out = []
        for name, d in list(_DAEMONS.items()):
            proc = _DAEMON_PROCS.get(name)
            if proc is not None and proc.poll() is None:
                row = dict(d)
                row["alive"] = True
                out.append(row)
            else:
                _DAEMONS.pop(name, None)
                _DAEMON_PROCS.pop(name, None)
        return out


@mcp.tool()
def tool_ligolo_proxy(lport: int = 11601, laddr: str = "0.0.0.0",
                      self_cert_dir: str = "") -> str:
    """
    Start ligolo-ng proxy (receive reverse connections from agents).
    Phase: Tool Execution
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect, tool_hydra_bruteforce
    """
    proxy = Path(_TOOLS_DIR) / "ligo-proxy"
    if not proxy.exists():
        return f"ligo-proxy not found at {proxy}. Build or download it first."
    cmd = [str(proxy), "-laddr", f"{laddr}:{lport}"]
    if self_cert_dir:
        cert_dir = Path(self_cert_dir)
        cmd += ["-autocert", "false", "-certfile", str(cert_dir/"ligolo_cert"),
                "-keyfile", str(cert_dir/"ligolo_key")]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _register_daemon("ligolo-proxy", proc)
        return f"ligolo-ng proxy started on {laddr}:{lport} (PID: {proc.pid})"
    except Exception as e:
        return f"Error starting ligolo proxy: {e}"


@mcp.tool()
def tool_ligolo_agent(proxy_addr: str, proxy_port: int = 11601,
                      tun_iface: str = "ligolo") -> str:
    """
    Start ligolo-ng agent connecting back to the proxy.
    Phase: Tool Execution
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect, tool_hydra_bruteforce
    """
    agent = Path(_TOOLS_DIR) / "ligo-agent"
    if not agent.exists():
        return f"ligo-agent not found at {agent}."
    cmd = [str(agent), "-connect", f"{proxy_addr}:{proxy_port}",
           "-tun", tun_iface]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _register_daemon("ligolo-agent", proc)
        return f"ligolo-ng agent started → {proxy_addr}:{proxy_port} (PID: {proc.pid})"
    except Exception as e:
        return f"Error starting ligolo agent: {e}"


@mcp.tool()
def tool_windapsearch_enum(domain: str, server: str = "",
                           username: str = "", password: str = "",
                           ldap_filter: str = "",
                           attrs: str = "", all_attrs: bool = False) -> str:
    """
    Enumerate AD via windapsearch (users, groups, computers, DACLs).
    Phase: Tool Execution
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect, tool_hydra_bruteforce
    """
    binary = Path(_TOOLS_DIR) / "windapsearch-linux-amd64"
    if not binary.exists():
        binary = Path(_TOOLS_DIR) / "windapsearch" / "windapsearch-linux-amd64"
    if not binary.exists():
        return "windapsearch binary not found in /share/tools/"
    cmd = [str(binary), "-d", domain]
    if server:
        cmd += ["-s", server]
    if username:
        cmd += ["-u", username, "-p", password]
    if ldap_filter:
        cmd += ["--filter", ldap_filter]
    if attrs:
        cmd += ["--attrs", attrs]
    if all_attrs:
        cmd += ["--all"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=_TIMEOUT)
        out = r.stdout[-3000:] + "\n...(truncated)" if len(r.stdout) > 3000 else r.stdout
        return f"Exit: {r.returncode}\n{out}"
    except subprocess.TimeoutExpired:
        return f"Timed out after {_TIMEOUT}s"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def tool_pspy_monitor(pspy_path: str = "", duration: int = 30) -> str:
    """
    Run pspy process monitor for N seconds to capture process execution events.
    Phase: Tool Execution
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect, tool_hydra_bruteforce
    """
    candidates = [Path(pspy_path)] if pspy_path else []
    td = Path(_TOOLS_DIR)
    for name in ("pspy64", "pspy", "pspy32"):
        candidates.append(td / name)
    binary = None
    for c in candidates:
        if c.exists():
            binary = c
            break
    if not binary:
        return "pspy binary not found (tried /share/tools/pspy64, pspy)"
    try:
        r = subprocess.run([str(binary), "-p", str(duration)],
                           capture_output=True, text=True, timeout=duration + 15)
        out = r.stdout[-2000:] + "\n...(truncated)" if len(r.stdout) > 2000 else r.stdout
        return f"pspy ran for {duration}s:\n{out}"
    except subprocess.TimeoutExpired:
        return f"pspy timed out (expected for duration={duration}s)"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
async def tool_bloodhound_py_ingest(domain: str, username: str, password: str,
                                    dc_ip: str = "", dns_server: str = "",
                                    collection_method: str = "All") -> str:
    """
    Run BloodHound.py Python ingestor against a domain.
    Phase: Tool Execution
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect, tool_hydra_bruteforce
    """
    from modules.tool_wrappers import bloodhound_ingest
    r = await _run_async(bloodhound_ingest, domain=domain, username=username,
             password=password, dc_ip=dc_ip, dns_server=dns_server,
             collection_method=collection_method)
    if r.get("error"):
        return f"Error: {r['error']}"
    return (f"BloodHound collection complete\n"
            f"Output: {r.get('output_dir', '')}\n"
            f"ZIP: {r.get('zip_file', 'N/A')}\n"
            f"{r.get('stdout', '')[:1000]}")


# ---------------------------------------------------------------------------
# Kerberos tools — time sync, krb5.conf, kinit, klist
# ---------------------------------------------------------------------------
@mcp.tool()
def kerberos_time_sync(server: str = "") -> str:
    """
    Sync system clock with a Kerberos KDC or NTP server.
    Phase: Kerberos Auth
    Related: kerberos_config, kerberos_kinit, kerberos_klist, kerberos_setup
    """
    from modules.kerberos_tools import time_sync
    r = _run(time_sync, server=server)
    if r.get("error"):
        return f"Error: {r['error']}"
    return f"Time sync: {r.get('status', 'done')} (method: {r.get('method_used', '?')})"


@mcp.tool()
def kerberos_config(domain: str, kdc: str, admin_server: str = "",
                    output_file: str = "") -> str:
    """
    Generate krb5.conf for a domain/realm.
    Phase: Kerberos Auth
    Related: kerberos_time_sync, kerberos_kinit, kerberos_klist, kerberos_setup
    """
    from modules.kerberos_tools import krb5_config
    r = _run(krb5_config, domain=domain, kdc=kdc,
             admin_server=admin_server, output_file=output_file)
    if r.get("error"):
        return f"Error: {r['error']}"
    return f"Kerberos config: {r.get('status', 'done')}\nRealm: {r.get('realm', '?')}\nKDC: {r.get('kdc', '?')}"


@mcp.tool()
def kerberos_kinit(principal: str, password: str = "",
                   keytab: str = "", realm: str = "",
                   lifetime: str = "24h") -> str:
    """
    Obtain a Kerberos TGT via kinit.
    Phase: Kerberos Auth
    Related: kerberos_time_sync, kerberos_config, kerberos_klist, kerberos_setup
    """
    from modules.kerberos_tools import kinit_user
    r = _run(kinit_user, principal=principal, password=password,
             keytab=keytab, realm=realm, lifetime=lifetime)
    if r.get("error"):
        return f"Error: {r['error']}"
    return r.get("status", "TGT obtained")


@mcp.tool()
def kerberos_klist() -> str:
    """List current Kerberos ticket cache."""
    from modules.kerberos_tools import klist_tickets
    r = _run(klist_tickets)
    if r.get("error"):
        return f"Error: {r['error']}"
    tickets = r.get("tickets", [])
    lines = [f"Tickets: {len(tickets)}"]
    for t in tickets:
        lines.append(f"  Principal: {t.get('principal', '?')}")
        lines.append(f"  Cache: {t.get('cache', '?')}")
    return "\n".join(lines)


@mcp.tool()
def kerberos_setup(domain: str, kdc: str, username: str = "",
                   password: str = "", skip_time_sync: bool = False) -> str:
    """
    Full Kerberos setup: time sync → krb5.conf → kinit (if creds).
    Phase: Kerberos Auth
    Related: kerberos_time_sync, kerberos_config, kerberos_kinit, kerberos_klist
    """
    from modules.kerberos_tools import setup_for_domain
    r = _run(setup_for_domain, domain=domain, kdc=kdc,
             username=username, password=password,
             skip_time_sync=skip_time_sync)
    if r.get("error"):
        return f"Error: {r['error']}"
    steps = r.get("steps", {})
    lines = [f"Kerberos setup for {domain}: {r.get('status', 'done')}"]
    for step_name, step_result in steps.items():
        if step_result.get("error"):
            lines.append(f"  {step_name}: FAIL ({step_result['error'][:60]})")
        else:
            lines.append(f"  {step_name}: OK")
    return "\n".join(lines)


@mcp.tool()
def tool_lazagne_run(software: str = "all",
                     password: str = "", target_path: str = "") -> str:
    """
    Run LaZagne credential recovery (all, browsers, wifi, git, etc).
    Phase: Tool Execution
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect, tool_hydra_bruteforce
    """
    lz_dir = Path(_TOOLS_DIR) / "LaZagne"
    lz_script = lz_dir / "Linux" / "laZagne.py"
    if not lz_script.exists():
        return f"LaZagne not found at {lz_script}"
    cmd = ["python3", str(lz_script), software]
    if password:
        cmd += ["-password", password]
    if target_path:
        cmd += ["-path", target_path]
    try:
        r = subprocess.run(cmd, cwd=str(lz_dir), capture_output=True,
                           text=True, timeout=_TIMEOUT)
        out = r.stdout[-3000:] + "\n...(truncated)" if len(r.stdout) > 3000 else r.stdout
        return f"LaZagne completed (exit: {r.returncode}):\n{out}"
    except subprocess.TimeoutExpired:
        return f"Timed out after {_TIMEOUT}s"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
async def tool_responder_analyze(interface: str = "eth0", analyze_mode: bool = False,
                                 verbose: bool = False, timeout: int = 60) -> str:
    """
    Start Responder in analyze or poison mode to capture NTLMv2 hashes.
    Phase: Tool Execution
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_poison, tool_evil_winrm_connect, tool_hydra_bruteforce
    """
    from modules.tool_wrappers import responder_analyze
    r = await _run_async(responder_analyze, interface=interface, analyze_mode=analyze_mode,
             verbose=verbose, timeout=timeout)
    if r.get("error"):
        return f"Error: {r['error']}"
    lines = [f"Responder {r.get('mode','?')} on {r.get('interface','?')}"]
    out = r.get("output_lines", [])
    lines.extend(out[-20:])
    return "\n".join(lines)


@mcp.tool()
async def tool_responder_poison(interface: str = "eth0") -> str:
    """
    Run Responder in poison mode to capture NTLMv2 hashes.
    Phase: Tool Execution
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_evil_winrm_connect, tool_hydra_bruteforce
    """
    from modules.tool_wrappers import responder_poison
    r = await _run_async(responder_poison, interface=interface)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    return f"Responder poisoning on {interface}: {r}"[:1000]


@mcp.tool()
def tool_evil_winrm_connect(ip: str, username: str = "", password: str = "",
                            hash_value: str = "", command: str = "") -> str:
    """
    Connect to a WinRM service via Evil-WinRM for interactive or command execution.
    Phase: Tool Execution
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_hydra_bruteforce
    """
    from modules.tool_wrappers import evil_winrm_connect
    r = _run(evil_winrm_connect, ip=ip, username=username, password=password,
             hash_value=hash_value, command=command)
    if r.get("error"):
        return f"Error: {r['error']}"
    return r.get("stdout", r.get("output_file", "Evil-WinRM connected"))


@mcp.tool()
async def tool_hydra_bruteforce(protocol: str, target: str, userlist: str,
                                passlist: str, port: int = 0,
                                service: str = "") -> str:
    """
    Run Hydra brute-force attack against a service.
    Phase: Tool Execution
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect
    """
    from modules.tool_wrappers import hydra_bruteforce
    r = await _run_async(hydra_bruteforce, protocol=protocol, target=target,
             userlist=userlist, passlist=passlist, port=port, service=service)
    if r.get("error"):
        return f"Error: {r['error']}"
    return _fmt(r)


@mcp.tool()
async def tool_john_crack(hash_file: str, wordlist: str = "",
                          format: str = "", show: bool = False) -> str:
    """
    Crack hashes with John the Ripper.
    Phase: Tool Execution
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect
    """
    from modules.tool_wrappers import john_crack
    r = await _run_async(john_crack, hash_file=hash_file, wordlist=wordlist,
             format=format, show=show)
    if r.get("error"):
        return f"Error: {r['error']}"
    if show and r.get("cracked"):
        return f"Cracked ({len(r['cracked'])}):\n" + "\n".join(r["cracked"][:30])
    return _fmt(r)


@mcp.tool()
async def tool_metasploit_module(module: str, payload: str, target: str,
                                 lhost: str = "", lport: int = 4444,
                                 timeout: int = 120) -> str:
    """
    Run a Metasploit module with a payload against a target.
    Phase: Tool Execution
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect
    """
    from modules.tool_wrappers import metasploit_module
    r = await _run_async(metasploit_module, module=module, payload=payload, target=target,
                         lhost=lhost, lport=lport, timeout=timeout)
    if r.get("error"):
        return f"Error: {r['error']}"
    return _fmt(r)


@mcp.tool()
async def tool_metasploit_resource(resource_script: str) -> str:
    """
    Run a Metasploit resource script (.rc) via msfconsole -q -r.
    Phase: Tool Execution
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect
    """
    from modules.tool_wrappers import metasploit_resource
    r = await _run_async(metasploit_resource, resource_script=resource_script)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    return _fmt(r)


@mcp.tool()
async def tool_sqlmap_detect(url: str, data: str = "", cookie: str = "",
                             level: int = 1, risk: int = 1) -> str:
    """
    Detect SQL injection vulnerabilities with SQLMap.
    Phase: Tool Execution
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect
    """
    from modules.tool_wrappers import sqlmap_detect
    r = await _run_async(sqlmap_detect, url=url, data=data, cookie=cookie,
             level=level, risk=risk)
    if r.get("error"):
        return f"Error: {r['error']}"
    vulnerable = "VULNERABLE" if r.get("vulnerable") else "No injection detected"
    return f"SQLMap: {vulnerable}\n" + _fmt(r)


@mcp.tool()
async def tool_sqlmap_exploit(url: str) -> str:
    """
    Exploit SQL injection with SQLMap (OS shell, dump DB, etc.).
    Phase: Tool Execution
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect
    """
    from modules.tool_wrappers import sqlmap_exploit
    r = await _run_async(sqlmap_exploit, url=url)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    return _fmt(r)


# ---------------------------------------------------------------------------
# Nmap pipeline
# ---------------------------------------------------------------------------
@mcp.tool()
async def nmap_initial_tcp(target: str, top_ports: int = 1000) -> str:
    """
    Run initial TCP SYN scan (top N ports).
    Phase: Nmap Scanning
    Related: nmap_initial_udp, nmap_full_tcp, nmap_pipeline, nmap_parse
    """
    from modules.nmap_wrapper import scan_initial_tcp
    r = await _run_async(scan_initial_tcp, target=target, top_ports=top_ports)
    return _fmt(r)


@mcp.tool()
async def nmap_initial_udp(target: str, top_ports: int = 1000) -> str:
    """
    Run initial UDP scan (top N ports).
    Phase: Nmap Scanning
    Related: nmap_initial_tcp, nmap_full_tcp, nmap_pipeline, nmap_parse
    """
    from modules.nmap_wrapper import scan_initial_udp
    r = await _run_async(scan_initial_udp, target=target, top_ports=top_ports)
    return _fmt(r)


@mcp.tool()
async def nmap_full_tcp(target: str) -> str:
    """
    Run full TCP port scan (1-65535).
    Phase: Nmap Scanning
    Related: nmap_initial_tcp, nmap_initial_udp, nmap_pipeline, nmap_parse
    """
    from modules.nmap_wrapper import scan_full_tcp
    r = await _run_async(scan_full_tcp, target=target)
    return _fmt(r)


@mcp.tool()
async def nmap_pipeline(target: str, skip_full: bool = False) -> str:
    """
    Run full nmap reconnaissance pipeline (nmaptest.sh workflow).
    Phase: Nmap Scanning
    Related: nmap_initial_tcp, nmap_initial_udp, nmap_full_tcp, nmap_parse
    """
    from modules.nmap_wrapper import scan_pipeline
    r = await _run_async(scan_pipeline, target=target, skip_full=skip_full)
    if r.get("error"):
        return f"Error: {r['error']}"
    phases = r.get("summary", {})
    lines = [f"Nmap pipeline for {target}:"]
    for name, status in phases.items():
        lines.append(f"  {name}: {status}")
    lines.append(f"Output: {r.get('output_dir', '')}")
    return "\n".join(lines)


@mcp.tool()
async def nmap_parse(target: str) -> str:
    """
    Parse all nmap output files into structured JSON.
    Phase: Nmap Scanning
    Related: nmap_initial_tcp, nmap_initial_udp, nmap_full_tcp, nmap_pipeline
    """
    from modules.nmap_wrapper import parse_results
    r = await _run_async(parse_results, target=target)
    if r.get("error"):
        return f"Error: {r['error']}"
    return json.dumps(r, indent=2)[:3000]


_VALID_NMAP_SUBCOMMANDS = [
    "init-tcp", "init-udp", "full-tcp", "full-ack",
    "service-version", "versions-tcp", "versions-udp",
    "vuln", "pipeline", "parse", "custom",
]

@mcp.tool()
async def case_nmap_scan(case_id: str, subcommand: str, target: str,
                         ports: str = "", timeout: int = 7200) -> str:
    """
    Run an nmap scan and attach results to a case (scans/ + evidence).
    Phase: Nmap Scanning
    Related: nmap_initial_tcp, nmap_full_tcp, nmap_pipeline, nmap_parse, case_evidence_list
    """
    if subcommand not in _VALID_NMAP_SUBCOMMANDS:
        return (f"Error: Unknown subcommand '{subcommand}'. "
                f"Valid: {', '.join(_VALID_NMAP_SUBCOMMANDS)}. "
                "(Note: use 'init-tcp' not 'initial-tcp', 'init-udp' not 'initial-udp')")
    cm = CaseManager()
    info = await _run_async(cm.info, case_id)
    if info is None:
        return f"Error: Case '{case_id}' not found"
    import subprocess as _sp
    import sys as _sys
    script = str(Path(__file__).resolve().parent / "kali-command-center.py")
    cmd = [
        _sys.executable or "python3", script, "nmap",
        subcommand, "--target", target, "--case-id", case_id,
    ]
    if ports:
        cmd.extend(["--ports", ports])
    try:
        r = await asyncio.to_thread(_sp.run, cmd, capture_output=True, text=True,
                                    timeout=timeout)
        output = r.stdout[-3000:] if len(r.stdout) > 3000 else r.stdout
        err = r.stderr[-500:] if r.stderr else ""
        refreshed = await _run_async(cm.info, case_id)
        ev_count = len(refreshed.get("evidence", [])) if refreshed else 0
        status = "ok" if r.returncode == 0 else "error"
        lines = [f"Nmap scan ({status}): exit={r.returncode}"]
        if output:
            lines.append(f"Output:\n{output}")
        if err:
            lines.append(f"Stderr:\n{err}")
        lines.append(f"Evidence count: {ev_count}")
        return "\n".join(lines)
    except _sp.TimeoutExpired:
        return f"Error: Scan timed out after {timeout}s. Increase the timeout parameter if needed."


# ---------------------------------------------------------------------------
# Browser forensics — LevelDB / IndexedDB
# ---------------------------------------------------------------------------
@mcp.tool()
def browser_analyze_leveldb(path: str) -> str:
    """
    Analyze a LevelDB directory and classify key-value pairs.
    Phase: General
    Related: browser_extract_sensitive, browser_analyze_chrome_profile
    """
    from modules.browser_db import analyze_leveldb
    r = _run(analyze_leveldb, path=path)
    if r.get("error"):
        return f"Error: {r['error']}"
    lines = [f"LevelDB: {r.get('path', path)}"]
    lines.append(f"  Files: {r.get('files_scanned', '?')}")
    lines.append(f"  Entries: {r.get('total_entries', 0)}")
    lines.append(f"  Store type: {r.get('store_detection', '?')}")
    lines.append("  Category breakdown:")
    for cat, count in r.get("summary", {}).items():
        if count:
            lines.append(f"    {cat}: {count}")
    return "\n".join(lines)


@mcp.tool()
def browser_extract_sensitive(path: str) -> str:
    """
    Extract sensitive data (credentials, tokens, JWTs) from a LevelDB store.
    Phase: General
    Related: browser_analyze_leveldb, browser_analyze_chrome_profile
    """
    from modules.browser_db import extract_sensitive
    r = _run(extract_sensitive, path=path)
    if r.get("error"):
        return f"Error: {r['error']}"
    return (f"Sensitive items: {r.get('sensitive_found', 0)}\n"
            f"By category: {r.get('by_category', {})}\n"
            f"Output: {r.get('output_file', '')}")


@mcp.tool()
def browser_analyze_chrome_profile(profile_path: str) -> str:
    """
    Analyze a full Chrome/Chromium profile for all LevelDB stores.
    Phase: General
    Related: browser_analyze_leveldb, browser_extract_sensitive
    """
    from modules.browser_db import analyze_chrome_profile
    r = _run(analyze_chrome_profile, profile_path=profile_path)
    if r.get("error"):
        return f"Error: {r['error']}"
    return (f"Chrome profile: {r.get('profile', '')}\n"
            f"Stores: {r.get('stores_analyzed', 0)}\n"
            f"Total entries: {r.get('total_entries', 0)}\n"
            f"Sensitive summary:\n{json.dumps(r.get('sensitive_summary', {}), indent=2)[:2000]}")


# ---------------------------------------------------------------------------
# Impacket — AD exploitation
# ---------------------------------------------------------------------------
@mcp.tool()
async def impacket_secretsdump(target: str, username: str = "", password: str = "",
                               domain: str = "", hash: str = "",
                               just_dc: bool = False) -> str:
    """
    Dump SAM/LSA/AD secrets via Impacket secretsdump.
    Phase: Impacket Exploitation
    Related: impacket_wmiexec, impacket_ticketer, impacket_psexec, impacket_smbexec
    """
    from modules.tool_wrappers import impacket_secretsdump
    r = await _run_async(impacket_secretsdump, target=target, username=username,
             password=password, domain=domain, hash=hash, just_dc=just_dc)
    return _fmt(r)


@mcp.tool()
async def impacket_wmiexec(target: str, username: str = "", password: str = "",
                           domain: str = "", hash: str = "", command: str = "whoami") -> str:
    """
    Execute commands via WMI using Impacket wmiexec.
    Phase: Impacket Exploitation
    Related: impacket_secretsdump, impacket_ticketer, impacket_psexec, impacket_smbexec
    """
    from modules.tool_wrappers import impacket_wmiexec
    r = await _run_async(impacket_wmiexec, target=target, username=username,
             password=password, domain=domain, hash=hash, command=command)
    return _fmt(r)


@mcp.tool()
async def impacket_ticketer(domain: str, username: str, ntlm_hash: str,
                            domain_sid: str, krbtgt_hash: str = "",
                            duration_hours: int = 10) -> str:
    """
    Create a golden/silver Kerberos ticket via Impacket ticketer.
    Phase: Impacket Exploitation
    Related: impacket_secretsdump, impacket_wmiexec, impacket_psexec, impacket_smbexec
    """
    from modules.tool_wrappers import impacket_ticketer
    r = await _run_async(impacket_ticketer, domain=domain, username=username,
             ntlm_hash=ntlm_hash, domain_sid=domain_sid,
             krbtgt_hash=krbtgt_hash, duration_hours=duration_hours)
    if r.get("error"):
        return f"Error: {r['error']}"
    return f"Ticket created:\n{r.get('ticket', '')}\n{r.get('stdout', '')[:500]}"


@mcp.tool()
async def impacket_psexec(target: str, username: str = "", password: str = "",
                          domain: str = "", hash: str = "",
                          command: str = "cmd.exe /c whoami") -> str:
    """
    Execute commands via SMB using Impacket psexec.
    Phase: Impacket Exploitation
    Related: impacket_secretsdump, impacket_wmiexec, impacket_ticketer, impacket_smbexec
    """
    from modules.tool_wrappers import impacket_psexec
    r = await _run_async(impacket_psexec, target=target, username=username,
             password=password, domain=domain, hash=hash, command=command)
    return _fmt(r)


@mcp.tool()
async def impacket_smbexec(target: str, username: str = "", password: str = "",
                           domain: str = "", hash: str = "",
                           command: str = "whoami") -> str:
    """
    Execute commands via SMB using Impacket smbexec (no service creation).
    Phase: Impacket Exploitation
    Related: impacket_secretsdump, impacket_wmiexec, impacket_ticketer, impacket_psexec
    """
    from modules.tool_wrappers import impacket_smbexec
    r = await _run_async(impacket_smbexec, target=target, username=username,
             password=password, domain=domain, hash=hash, command=command)
    return _fmt(r)


# ---------------------------------------------------------------------------
# Web fuzzing
# ---------------------------------------------------------------------------
@mcp.tool()
async def ffuf_directory(url: str, wordlist: str, extensions: str = "",
                         filter_size: str = "") -> str:
    """
    Run ffuf for directory/file fuzzing.
    Phase: Web Fuzzing
    """
    from modules.tool_wrappers import ffuf_fuzz
    r = await _run_async(ffuf_fuzz, url=url, wordlist=wordlist, mode="dir",
             extensions=extensions, filter_size=filter_size)
    if r.get("error"):
        return f"Error: {r['error']}"
    total = r.get("total", 0)
    return f"ffuf: {total} results\nOutput: {r.get('output_file', '')}"


@mcp.tool()
async def gobuster_directory(url: str, wordlist: str, extensions: str = "") -> str:
    """
    Run gobuster for directory brute-forcing.
    Phase: Web Brute-force
    """
    from modules.tool_wrappers import gobuster_dir
    r = await _run_async(gobuster_dir, url=url, wordlist=wordlist, extensions=extensions)
    if r.get("error"):
        return f"Error: {r['error']}"
    out = r.get("output", r.get("stdout", ""))[:2000]
    return f"gobuster complete\n{out}"


# ---------------------------------------------------------------------------
# Hash cracking
# ---------------------------------------------------------------------------
@mcp.tool()
async def hashcat_crack(hash_file: str, wordlist: str = "", mask: str = "",
                        hash_mode: int = 0) -> str:
    """
    Crack hashes with hashcat (GPU-accelerated).
    Phase: Hash Cracking
    """
    from modules.tool_wrappers import hashcat_crack as _hc
    r = await _run_async(_hc, hash_file=hash_file, wordlist=wordlist, mask=mask,
                         hash_mode=hash_mode)
    if r.get("error"):
        return f"Error: {r['error']}"
    cnt = r.get("cracked_count", 0)
    return f"hashcat: {cnt} cracked\n{chr(10).join(r.get('cracked', [])[:20])}"


# ---------------------------------------------------------------------------
# Import tools (Burp / Caido)
# ---------------------------------------------------------------------------
@mcp.tool()
def burp_import(xml_file: str) -> str:
    """
    Parse Burp Suite XML export into structured findings.
    Phase: Burp Suite Import
    """
    from modules.tool_wrappers import burp_import_xml
    r = _run(burp_import_xml, xml_file=xml_file)
    if r.get("error"):
        return f"Error: {r['error']}"
    findings = r.get("findings", [])
    lines = [f"Burp import: {r.get('total_findings', 0)} findings"]
    for f in findings[:10]:
        lines.append(f"  [{f.get('severity','?')}] {f.get('name','?')} - {f.get('url','')}")
    return "\n".join(lines)


@mcp.tool()
def tool_caido_import(json_file: str, case_id: str = "") -> str:
    """
    Parse Caido JSON export into structured findings.
    Phase: Tool Execution
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect
    """
    from modules.tool_wrappers import caido_import_json
    r = _run(caido_import_json, json_file=json_file, case_id=case_id)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    findings = r.get("findings", [])
    return f"Caido import: {len(findings)} findings\n" + _fmt(r)


@mcp.tool()
def caido_health() -> str:
    """Probe the Caido instance and report whether its API (or only the web UI)
    is reachable. Use before caido_requests/caido_workflows.
    Phase: DAST
    Related: caido_requests, caido_workflows, tool_caido_import
    """
    from modules.caido_client import CaidoClient
    cfg = _caido_cfg()
    c = CaidoClient(base_url=cfg.get("url", "http://127.0.0.1:8080"),
                    api_key=cfg.get("api_key", ""),
                    api_token=cfg.get("api_token", ""))
    d = c.detect()
    lines = [f"Caido at {d['base_url']}: web UI {'up' if d['web_ui'] in (200, 401, 403) else 'down'}",
             f"API reachable: {d['api_reachable']}"]
    for name, p in d.get("probes", {}).items():
        lines.append(f"  /api/v1/{name}: HTTP {p.get('status')} "
                     f"json={p.get('json')} {p.get('content_type', '')}")
    if not d["api_reachable"]:
        lines.append("API not reachable -> use tool_caido_import with a Caido JSON export instead.")
    return "\n".join(lines)


@mcp.tool()
def caido_requests(limit: int = 50) -> str:
    """List recent proxied requests from the Caido API (only works if the API is up).
    Phase: DAST
    Related: caido_health, caido_workflows, tool_caido_import
    """
    from modules.caido_client import CaidoClient
    cfg = _caido_cfg()
    c = CaidoClient(base_url=cfg.get("url", "http://127.0.0.1:8080"),
                    api_key=cfg.get("api_key", ""),
                    api_token=cfg.get("api_token", ""))
    if not c.detect().get("api_reachable"):
        return "Caido API is not reachable; use tool_caido_import with an export instead."
    r = c.requests_recent(limit=limit)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    items = r.get("requests", r.get("data", [r]))[:limit]
    lines = [f"Caido requests ({len(items)}):"]
    for it in items:
        lines.append(f"  {it.get('id', it.get('uuid', '?'))} "
                     f"{it.get('method', it.get('req', {}).get('method', '?'))} "
                     f"{it.get('url', it.get('uri', ''))}")
    return "\n".join(lines)


@mcp.tool()
def caido_workflows() -> str:
    """List Caido workflows/scans via the API (only works if the API is up).
    Phase: DAST
    Related: caido_health, caido_requests, tool_caido_import
    """
    from modules.caido_client import CaidoClient
    cfg = _caido_cfg()
    c = CaidoClient(base_url=cfg.get("url", "http://127.0.0.1:8080"),
                    api_key=cfg.get("api_key", ""),
                    api_token=cfg.get("api_token", ""))
    if not c.detect().get("api_reachable"):
        return "Caido API is not reachable; use tool_caido_import with an export instead."
    r = c.workflows_list()
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    items = r.get("workflows", r.get("data", [r]))
    return f"Caido workflows ({len(items)}):\n" + "\n".join(f"  {w}" for w in items[:30])


def _caido_cfg() -> dict:
from modules.config import load_config
    cfg = load_config()
    return {
        "url": cfg.get("caido_url", "http://127.0.0.1:8080"),
        "api_key": cfg.get("caido_api_key", ""),
        "api_token": cfg.get("caido_api_token", ""),
    }


# ---------------------------------------------------------------------------
# Secret scanning
# ---------------------------------------------------------------------------
@mcp.tool()
async def tool_trufflehog_org(org: str, output_dir: str = "") -> str:
    """
    Scan a GitHub org for secrets via TruffleHog Docker image.
    Phase: Tool Execution
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect
    """
    from modules.tool_wrappers import trufflehog_org
    from pathlib import Path
    od = Path(output_dir) if output_dir else None
    r = await _run_async(trufflehog_org, org=org, output_dir=od)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    return f"TruffleHog org scan: {r.get('verified', 0)} verified, {r.get('unverified', 0)} unverified\nFile: {r.get('raw_file', '')}"


@mcp.tool()
async def tool_trufflehog_local(path: str, output_dir: str = "") -> str:
    """
    Run TruffleHog on a local directory to find secrets.
    Phase: Tool Execution
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect
    """
    from modules.tool_wrappers import trufflehog_local
    from pathlib import Path
    od = Path(output_dir) if output_dir else None
    r = await _run_async(trufflehog_local, path=path, output_dir=od)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    return f"TruffleHog local scan: {r.get('verified', 0)} verified, {r.get('unverified', 0)} unverified\nFile: {r.get('raw_file', '')}"


# ---------------------------------------------------------------------------
# Privesc check (linpeas / winpeas)
# ---------------------------------------------------------------------------
@mcp.tool()
async def linpeas_local() -> str:
    """Run linpeas.sh locally for privilege escalation checks."""
    from modules.tool_wrappers import linpeas_run
    r = await _run_async(linpeas_run)
    if r.get("error"):
        return f"Error: {r['error']}"
    return f"linpeas complete\nOutput: {r.get('output_file', '')}"


@mcp.tool()
async def tool_winpeas_run(target_host: str = "", target_user: str = "",
                           target_pass: str = "", local_path: str = "") -> str:
    """
    Execute winPEAS.exe on a remote target for Windows privesc checks.
    Phase: Tool Execution
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect
    """
    from modules.tool_wrappers import winpeas_run
    r = await _run_async(winpeas_run, target_host=target_host, target_user=target_user,
             target_pass=target_pass, local_path=local_path)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    return f"winPEAS: {r.get('output_file', 'done')}"


# ---------------------------------------------------------------------------
# Tunnel management (chisel)
# ---------------------------------------------------------------------------
@mcp.tool()
def chisel_tunnel(server: str, remote_port: int = 8080,
                  local_port: int = 1080, socks: bool = True,
                  reverse: bool = False) -> str:
    """
    Start a chisel tunnel client.
    Phase: Tunneling
    """
    from modules.tool_wrappers import chisel_client
    r = _run(chisel_client, server=server, remote_port=remote_port,
             local_port=local_port, socks=socks, reverse=reverse)
    if r.get("error"):
        return f"Error: {r['error']}"
    pid = r.get("pid", "?")
    return f"Chisel tunnel client connecting to {server}:{remote_port} (PID: {pid})"


@mcp.tool()
def tool_chisel_server(port: int = 8080, socks: bool = True) -> str:
    """
    Start a chisel server for incoming tunnel connections.
    Phase: Tool Execution
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect
    """
    from modules.tool_wrappers import chisel_server
    r = _run(chisel_server, port=port, socks=socks)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    pid = r.get("pid", "?")
    return f"Chisel server on port {port} (socks: {socks}, PID: {pid})"


# ---------------------------------------------------------------------------
# Phishing tools
# ---------------------------------------------------------------------------
@mcp.tool()
def tool_evilginx_start(domain: str, config_dir: str = "",
                        phishing_dir: str = "") -> str:
    """
    Start EvilGinx2 with a given phishing domain.
    Phase: Tool Execution
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect
    """
    from modules.tool_wrappers import evilginx_start
    r = _run(evilginx_start, domain=domain, config_dir=config_dir or None,
             phishing_dir=phishing_dir or None)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    return f"EvilGinx started for {domain}: {r}"[:1000]


@mcp.tool()
def tool_gophish_import(campaign_file: str, gophish_url: str = "",
                        api_key: str = "") -> str:
    """
    Import a GoPhish campaign JSON file (or send via API).
    Phase: Tool Execution
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect
    """
    from modules.tool_wrappers import gophish_import_campaign
    r = _run(gophish_import_campaign, campaign_file=campaign_file,
             gophish_url=gophish_url, api_key=api_key)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    return f"GoPhish import: {r}"[:1000]


# ---------------------------------------------------------------------------
# SMB enumeration
# ---------------------------------------------------------------------------
@mcp.tool()
def enum4linux(target: str, username: str = "", password: str = "",
               domain: str = "") -> str:
    """
    Enumerate Windows/Samba hosts via enum4linux-ng.
    Phase: SMB Enumeration
    """
    from modules.tool_wrappers import enum4linux_ng
    r = _run(enum4linux_ng, target=target, username=username,
             password=password, domain=domain)
    if r.get("error"):
        return f"Error: {r['error']}"
    users = r.get("users", [])
    shares = r.get("shares", [])
    return f"Users: {len(users)}, Shares: {len(shares)}\n" + _fmt(r)


# ---------------------------------------------------------------------------
# ProjectDiscovery recon stack (subfinder / httpx / naabu / dnsx / katana)
# ---------------------------------------------------------------------------
@mcp.tool()
async def pd_subfinder(domain: str, recursive: bool = False,
                       all_sources: bool = False, resolvers: str = "",
                       threads: int = 0) -> str:
    """
    Enumerate subdomains with ProjectDiscovery subfinder.
    Phase: Subdomain Enumeration
    Related: pd_httpx, pd_naabu, dns_resolve, auto_recon
    """
    from modules.tool_wrappers import subfinder_enum
    r = await _run_async(subfinder_enum, domain, recursive=recursive,
                         all_sources=all_sources, resolvers=resolvers,
                         threads=threads)
    if r.get("error"):
        return f"Error: {r['error']}"
    subs = r.get("subdomains", [])
    lines = [f"subfinder: {r.get('total', 0)} subdomains for {domain}"]
    lines.extend(f"  {s}" for s in subs[:100])
    if len(subs) > 100:
        lines.append(f"  ... and {len(subs) - 100} more (full list in output file)")
    lines.append(f"Output: {r.get('output_file', '')}")
    return "\n".join(lines)


@mcp.tool()
async def pd_httpx(target: str = "", list_file: str = "",
                   status_codes: str = "", include_title: bool = True,
                   tech_detect: bool = True, follow_redirects: bool = False,
                   threads: int = 0) -> str:
    """
    Probe hosts/URLs with ProjectDiscovery httpx (live hosts, status, title, tech).
    Phase: Web Probing
    Related: pd_subfinder, pd_naabu, web_nuclei_scan, auto_recon
    """
    from modules.tool_wrappers import httpx_probe
    r = await _run_async(httpx_probe, target, list_file, status_codes=status_codes,
                         include_title=include_title, tech_detect=tech_detect,
                         follow_redirects=follow_redirects, threads=threads)
    if r.get("error"):
        return f"Error: {r['error']}"
    hosts = r.get("hosts", [])
    lines = [f"httpx: {r.get('total', 0)} live hosts"]
    for h in hosts[:100]:
        tech = ",".join((h.get("tech") or [])[:3])
        lines.append(f"  {h.get('status_code','')} {h.get('url','')}  "
                     f"{h.get('title','')[:60]}  {h.get('webserver','')} {tech}")
    if len(hosts) > 100:
        lines.append(f"  ... and {len(hosts) - 100} more (full list in output file)")
    lines.append(f"Output: {r.get('output_file', '')}")
    return "\n".join(lines)


@mcp.tool()
async def pd_naabu(target: str, ports: str = "", top_ports: int = 0,
                   rate: int = 0, service_detect: bool = False) -> str:
    """
    Fast port scan with ProjectDiscovery naabu.
    Phase: Port Scanning
    Related: nmap_initial_tcp, pd_httpx, pd_subfinder
    """
    from modules.tool_wrappers import naabu_scan
    r = await _run_async(naabu_scan, target, ports=ports, top_ports=top_ports,
                         rate=rate, service_detect=service_detect)
    if r.get("error"):
        return f"Error: {r['error']}"
    ports_open = r.get("ports", [])
    lines = [f"naabu {target}: {r.get('total_open', 0)} open port(s)"]
    lines.append("  " + ", ".join(str(p) for p in ports_open[:100]))
    lines.append(f"Output: {r.get('output_file', '')}")
    return "\n".join(lines)


@mcp.tool()
async def pd_dnsx(domain: str = "", list_file: str = "",
                  record_types: str = "a,aaaa,cname,mx,ns,txt,soa",
                  resp_only: bool = False) -> str:
    """
    Run DNS lookups with ProjectDiscovery dnsx.
    Phase: DNS / Network
    Related: dns_resolve, pd_subfinder, dns_history
    """
    from modules.tool_wrappers import dnsx_probe
    r = await _run_async(dnsx_probe, domain, list_file, record_types=record_types,
                         resp_only=resp_only)
    if r.get("error"):
        return f"Error: {r['error']}"
    records = r.get("records", [])
    lines = [f"dnsx: {r.get('total', 0)} record(s)"]
    for rec in records[:100]:
        val = rec.get("value", "")
        lines.append(f"  {rec.get('host','')} {rec.get('type','')}: {val}")
    if len(records) > 100:
        lines.append(f"  ... and {len(records) - 100} more (full list in output file)")
    lines.append(f"Output: {r.get('output_file', '')}")
    return "\n".join(lines)


@mcp.tool()
async def pd_katana(url: str = "", list_file: str = "", depth: int = 2,
                    js_crawl: bool = False, known_files: bool = False) -> str:
    """
    Crawl a web app with ProjectDiscovery katana.
    Phase: Web Crawling
    Related: pd_httpx, ffuf_directory, web_nuclei_scan
    """
    from modules.tool_wrappers import katana_crawl
    r = await _run_async(katana_crawl, url, list_file, depth=depth,
                         js_crawl=js_crawl, known_files=known_files)
    if r.get("error"):
        return f"Error: {r['error']}"
    urls = r.get("urls", [])
    lines = [f"katana: {r.get('total', 0)} endpoints discovered"]
    lines.extend(f"  {u}" for u in urls[:100])
    if len(urls) > 100:
        lines.append(f"  ... and {r.get('total', len(urls)) - len(urls)} more (full list in output file)")
    lines.append(f"Output: {r.get('output_file', '')}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Auto-recon pipeline
# ---------------------------------------------------------------------------
@mcp.tool()
async def auto_recon(target: str) -> str:
    """
    Chain nmap → ffuf → nuclei in a single reconnaissance pipeline.
    Phase: Automated Recon
    """
    from modules.tool_wrappers import auto_recon
    r = await _run_async(auto_recon, target=target)
    if r.get("error"):
        return f"Error: {r['error']}"
    phases = r.get("phases", {})
    lines = [f"Auto-recon for {target}:"]
    for name, result in phases.items():
        lines.append(f"  {name}: {result}")
    lines.append(f"Output: {r.get('output_dir', '')}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Loot DB
# ---------------------------------------------------------------------------
@mcp.tool()
def loot_add_credential(source: str, target: str, username: str,
                        password: str = "", hash: str = "",
                        hash_type: str = "", domain: str = "",
                        protocol: str = "", port: int = 0) -> str:
    """
    Store a captured/compromised credential in the loot database (plaintext).
    Use this for credentials found via dumping, cracking, phishing, or tool output.
    For managed/known credentials of an inventory asset use credentials_create.
    Phase: Loot Database
    Related: loot_search, loot_list_credentials, loot_delete_credential, credentials_create, credentials_list
    """
    from modules.tool_wrappers import LootDB
    def _store():
        db = LootDB()
        try:
            return db.add_credential(source=source, target=target, username=username,
                                    password=password, hash=hash, hash_type=hash_type,
                                    domain=domain, protocol=protocol, port=port)
        finally:
            db.close()
    cid = _run(_store)
    if isinstance(cid, dict) and cid.get("error"):
        return cid["error"]
    return f"Credential stored (id={cid})"


@mcp.tool()
def loot_search(query: str) -> str:
    """
    Search the loot database for captured credentials, tokens, sessions.
    Does not search the asset inventory — use credentials_list for that.
    Phase: Loot Database
    Related: loot_add_credential, loot_list_credentials, loot_list_tokens, loot_list_sessions, credentials_list
    """
    from modules.tool_wrappers import LootDB
    def _search():
        db = LootDB()
        try:
            return db.search(query)
        finally:
            db.close()
    results = _run(_search)
    if isinstance(results, dict) and results.get("error"):
        return results["error"]
    creds = results.get("credentials", [])
    tokens = results.get("tokens", [])
    sessions = results.get("sessions", [])
    lines = [f"Loot search: '{query}'"]
    lines.append(f"  Credentials: {len(creds)}")
    for c in creds[:10]:
        lines.append(f"    {c.get('username','?')}:{c.get('password','')} @ {c.get('target','?')}")
    lines.append(f"  Tokens: {len(tokens)}")
    for t in tokens[:5]:
        lines.append(f"    [{t.get('token_type','?')}] {t.get('token_value','')[:60]}")
    lines.append(f"  Sessions: {len(sessions)}")
    return "\n".join(lines)


@mcp.tool()
def loot_list_credentials(limit: int = 50) -> str:
    """
    List recent credentials from the loot database (captured/compromised creds).
    For managed/known credentials of inventory assets use credentials_list.
    Phase: Loot Database
    Related: loot_add_credential, loot_delete_credential, loot_search, credentials_list
    """
    from modules.tool_wrappers import LootDB
    def _list():
        db = LootDB(CC_DIR / "loot.db")
        try:
            return db.list_credentials(limit=limit)
        finally:
            db.close()
    creds = _run(_list)
    if isinstance(creds, dict) and creds.get("error"):
        return creds["error"]
    if not creds:
        return "No credentials found."
    lines = [f"Credentials ({len(creds)}):"]
    for c in creds:
        lines.append(f"  #{c['id']:<6} {c.get('username','?'):<20} {c.get('password',''):<20} @ {c.get('target','?'):<30} [{c.get('protocol','')}{':'+str(c['port']) if c.get('port') else ''}] {c.get('source','')}")
    return "\n".join(lines)


@mcp.tool()
def loot_delete_credential(cred_id: int) -> str:
    """
    Delete a credential from the loot database by ID.
    Phase: Loot Database
    Related: loot_list_credentials, loot_add_credential, loot_search
    """
    from modules.tool_wrappers import LootDB
    def _del():
        db = LootDB(CC_DIR / "loot.db")
        try:
            cur = db._conn.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
            db._conn.commit()
            return cur.rowcount
        finally:
            db.close()
    cnt = _run(_del)
    if isinstance(cnt, dict) and cnt.get("error"):
        return cnt["error"]
    if cnt == 0:
        return f"Credential {cred_id} not found."
    return f"Credential {cred_id} deleted."


@mcp.tool()
def loot_list_tokens(limit: int = 50) -> str:
    """
    List tokens from the loot database.
    Phase: Loot Database
    Related: loot_add_token, loot_delete_token, loot_search
    """
    from modules.tool_wrappers import LootDB
    def _list():
        db = LootDB(CC_DIR / "loot.db")
        try:
            rows = db._conn.execute(
                "SELECT * FROM tokens ORDER BY discovered DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(zip(["id","source","token_type","token_value","target","expires","notes","discovered"], r)) for r in rows]
        finally:
            db.close()
    tokens = _run(_list)
    if isinstance(tokens, dict) and tokens.get("error"):
        return tokens["error"]
    if not tokens:
        return "No tokens found."
    lines = [f"Tokens ({len(tokens)}):"]
    for t in tokens:
        tv = t.get('token_value', '')
        lines.append(f"  #{t['id']:<6} [{t.get('token_type','?'):<10}] {tv[:60]:<60} \u2192 {t.get('target','?'):<20} ({t.get('source','')})")
    return "\n".join(lines)


@mcp.tool()
def loot_add_token(source: str, token_type: str, token_value: str,
                   target: str = "", expires: str = "",
                   notes: str = "") -> str:
    """
    Store a token in the loot database.
    Phase: Loot Database
    Related: loot_list_tokens, loot_delete_token, loot_search
    """
    from modules.tool_wrappers import LootDB
    def _store():
        db = LootDB(CC_DIR / "loot.db")
        try:
            return db.add_token(source=source, token_type=token_type,
                               token_value=token_value, target=target,
                               expires=expires, notes=notes)
        finally:
            db.close()
    tid = _run(_store)
    if isinstance(tid, dict) and tid.get("error"):
        return tid["error"]
    return f"Token stored (id={tid})"


@mcp.tool()
def loot_delete_token(token_id: int) -> str:
    """
    Delete a token from the loot database by ID.
    Phase: Loot Database
    Related: loot_list_tokens, loot_add_token, loot_search
    """
    from modules.tool_wrappers import LootDB
    def _del():
        db = LootDB(CC_DIR / "loot.db")
        try:
            cur = db._conn.execute("DELETE FROM tokens WHERE id = ?", (token_id,))
            db._conn.commit()
            return cur.rowcount
        finally:
            db.close()
    cnt = _run(_del)
    if isinstance(cnt, dict) and cnt.get("error"):
        return cnt["error"]
    if cnt == 0:
        return f"Token {token_id} not found."
    return f"Token {token_id} deleted."


@mcp.tool()
def loot_list_sessions(limit: int = 50) -> str:
    """
    List sessions from the loot database.
    Phase: Loot Database
    Related: loot_add_session, loot_delete_session, loot_search
    """
    from modules.tool_wrappers import LootDB
    def _list():
        db = LootDB(CC_DIR / "loot.db")
        try:
            rows = db._conn.execute(
                "SELECT * FROM sessions ORDER BY discovered DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(zip(["id","source","session_id","target","protocol","data","discovered"], r)) for r in rows]
        finally:
            db.close()
    sessions = _run(_list)
    if isinstance(sessions, dict) and sessions.get("error"):
        return sessions["error"]
    if not sessions:
        return "No sessions found."
    lines = [f"Sessions ({len(sessions)}):"]
    for s in sessions:
        lines.append(f"  #{s['id']:<6} {s.get('session_id',''):<30} \u2192 {s.get('target','?'):<20} [{s.get('protocol','?'):<10}] ({s.get('source','')})")
    return "\n".join(lines)


@mcp.tool()
def loot_add_session(source: str, session_id: str, target: str = "",
                     protocol: str = "", data: str = "") -> str:
    """
    Store a session in the loot database.
    Phase: Loot Database
    Related: loot_list_sessions, loot_delete_session, loot_search
    """
    from modules.tool_wrappers import LootDB
    def _store():
        db = LootDB(CC_DIR / "loot.db")
        try:
            return db.add_session(source=source, session_id=session_id,
                                 target=target, protocol=protocol,
                                 data=data)
        finally:
            db.close()
    sid = _run(_store)
    if isinstance(sid, dict) and sid.get("error"):
        return sid["error"]
    return f"Session stored (id={sid})"


@mcp.tool()
def loot_delete_session(sid: int) -> str:
    """
    Delete a session from the loot database by ID.
    Phase: Loot Database
    Related: loot_list_sessions, loot_add_session, loot_search
    """
    from modules.tool_wrappers import LootDB
    def _del():
        db = LootDB(CC_DIR / "loot.db")
        try:
            cur = db._conn.execute("DELETE FROM sessions WHERE id = ?", (sid,))
            db._conn.commit()
            return cur.rowcount
        finally:
            db.close()
    cnt = _run(_del)
    if isinstance(cnt, dict) and cnt.get("error"):
        return cnt["error"]
    if cnt == 0:
        return f"Session {sid} not found."
    return f"Session {sid} deleted."


# ---------------------------------------------------------------------------
# pypykatz — LSASS dump parsing
# ---------------------------------------------------------------------------
@mcp.tool()
def pypykatz_parse(dump_file: str) -> str:
    """
    Parse a LSASS minidump with pypykatz to extract credentials.
    Phase: Credential Extraction
    """
    from modules.tool_wrappers import pypykatz_parse as _ppk
    r = _run(_ppk, dump_file=dump_file)
    if r.get("error"):
        return f"Error: {r['error']}"
    return (f"Logon sessions: {r.get('logon_sessions', '?')}\n"
            f"Credentials: {r.get('total_credentials', '?')}\n"
            f"Usernames: {', '.join(r.get('usernames', []))}\n"
            f"Output: {r.get('output_file', '')}")


# ---------------------------------------------------------------------------
# Binary Exploitation (ai-bug-bounty integration)
# ---------------------------------------------------------------------------

def _bin_result(r: dict) -> str:
    if r.get("error"):
        return f"Error: {r['error']}"
    if r.get("stdout"):
        return r["stdout"][:4000]
    return json.dumps(r, indent=2, default=str)[:4000]

async def _run_bin_noargs(fn):
    """Run a blocking binary-wrapper fn in a worker thread with a timeout."""
    try:
        return _bin_result(await asyncio.wait_for(asyncio.to_thread(fn), timeout=_TIMEOUT))
    except asyncio.TimeoutError:
        return f"Error: Timed out after {_TIMEOUT}s"


async def _run_bin_binary(fn, binary_path: str):
    """Run a blocking binary-wrapper fn in a worker thread with a timeout."""
    try:
        return _bin_result(await asyncio.wait_for(asyncio.to_thread(fn, binary_path), timeout=_TIMEOUT))
    except asyncio.TimeoutError:
        return f"Error: Timed out after {_TIMEOUT}s"


async def _run_bin_kwargs(fn, *args, **kwargs):
    """Run a blocking binary-wrapper fn in a worker thread with a timeout."""
    try:
        return _bin_result(await asyncio.wait_for(asyncio.to_thread(fn, *args, **kwargs), timeout=_TIMEOUT))
    except asyncio.TimeoutError:
        return f"Error: Timed out after {_TIMEOUT}s"

@mcp.tool()
async def binary_check() -> str:
    """Check what binary exploitation / reverse engineering tools are available on this system. Reports 40+ tools across 9 categories."""
    from modules.bin_wrapper import check as _bc
    return await _run_bin_noargs(_bc)

@mcp.tool()
async def binary_analyze(binary_path: str) -> str:
    """
    Run a full binary exploitation analysis on a target binary (ELF/PE/Mach-O). Returns file info, security mitigations, vulnerability scan, exploitability scoring, and tool-specific deep analysis (angr, pwntools, r2).
    Phase: Binary Exploitation
    Related: binary_check, binary_summary, binary_vulns, binary_checksec, binary_gadgets, binary_exploit_strategy, binary_functions, binary_strings, binary_fmtstr, binary_heap, binary_angr, binary_fuzz
    """
    from modules.bin_wrapper import analyze as _ba
    return await _run_bin_binary(_ba, binary_path)

@mcp.tool()
async def binary_summary(binary_path: str) -> str:
    """
    Get a concise markdown summary of a binary's security posture and exploitability. Optimized for AI consumption — includes mitigation status, vulnerability list, and exploitation strategy.
    Phase: Binary Exploitation
    Related: binary_check, binary_analyze, binary_vulns, binary_checksec, binary_gadgets, binary_exploit_strategy, binary_functions, binary_strings, binary_fmtstr, binary_heap, binary_angr, binary_fuzz
    """
    from modules.bin_wrapper import summary as _bs
    return await _run_bin_binary(_bs, binary_path)

@mcp.tool()
async def binary_vulns(binary_path: str) -> str:
    """
    Scan a binary for common vulnerability patterns: dangerous functions (gets/strcpy/system), format strings, command injection, insecure APIs, packer detection, anti-debug, and suspicious strings.
    Phase: Binary Exploitation
    Related: binary_check, binary_analyze, binary_summary, binary_checksec, binary_gadgets, binary_exploit_strategy, binary_functions, binary_strings, binary_fmtstr, binary_heap, binary_angr, binary_fuzz
    """
    from modules.bin_wrapper import vulns as _bv
    return await _run_bin_binary(_bv, binary_path)

@mcp.tool()
async def binary_checksec(binary_path: str) -> str:
    """
    Check binary security mitigations: NX (no-execute), Stack Canary, RELRO (GOT protection), PIE (position-independent), and PE-specific (ASLR, CFG, SafeSEH).
    Phase: Binary Exploitation
    Related: binary_check, binary_analyze, binary_summary, binary_vulns, binary_gadgets, binary_exploit_strategy, binary_functions, binary_strings, binary_fmtstr, binary_heap, binary_angr, binary_fuzz
    """
    from modules.bin_wrapper import checksec as _bc
    return await _run_bin_binary(_bc, binary_path)

@mcp.tool()
async def binary_gadgets(binary_path: str) -> str:
    """
    Search for ROP gadgets in a binary using ropper or ROPgadget. Returns categorized gadgets: pop rdi/ret, pop rsi/ret, syscall, ret, etc.
    Phase: Binary Exploitation
    Related: binary_check, binary_analyze, binary_summary, binary_vulns, binary_checksec, binary_exploit_strategy, binary_functions, binary_strings, binary_fmtstr, binary_heap, binary_angr, binary_fuzz
    """
    from modules.bin_wrapper import gadgets as _bg
    return await _run_bin_binary(_bg, binary_path)

@mcp.tool()
async def binary_exploit_strategy(binary_path: str) -> str:
    """
    Generate an exploitation strategy for a binary. Scores exploitability (0-100), recommends techniques (shellcode injection, ret2libc, ROP chain), and lists available gadgets.
    Phase: Binary Exploitation
    Related: binary_check, binary_analyze, binary_summary, binary_vulns, binary_checksec, binary_gadgets, binary_functions, binary_strings, binary_fmtstr, binary_heap, binary_angr, binary_fuzz
    """
    from modules.bin_wrapper import exploit as _be
    return await _run_bin_binary(_be, binary_path)

@mcp.tool()
async def binary_functions(binary_path: str) -> str:
    """
    List all exported and visible functions in a binary using nm/objdump/pwntools.
    Phase: Binary Exploitation
    Related: binary_check, binary_analyze, binary_summary, binary_vulns, binary_checksec, binary_gadgets, binary_exploit_strategy, binary_strings, binary_fmtstr, binary_heap, binary_angr, binary_fuzz
    """
    from modules.bin_wrapper import functions as _bf
    return await _run_bin_binary(_bf, binary_path)

@mcp.tool()
async def binary_strings(binary_path: str) -> str:
    """
    Extract printable strings from a binary. Useful for finding hardcoded paths, credentials, format strings, and suspicious keywords.
    Phase: Binary Exploitation
    Related: binary_check, binary_analyze, binary_summary, binary_vulns, binary_checksec, binary_gadgets, binary_exploit_strategy, binary_functions, binary_fmtstr, binary_heap, binary_angr, binary_fuzz
    """
    from modules.bin_wrapper import strings as _bs
    return await _run_bin_binary(_bs, binary_path)

@mcp.tool()
async def binary_fmtstr(binary_path: str) -> str:
    """
    Analyze format string vulnerabilities. Reports detected printf-family imports, read/write primitives (%p/%n/%hn/%hhn), offset finding guide, and exploitation techniques per mitigation level.
    Phase: Binary Exploitation
    Related: binary_check, binary_analyze, binary_summary, binary_vulns, binary_checksec, binary_gadgets, binary_exploit_strategy, binary_functions, binary_strings, binary_heap, binary_angr, binary_fuzz
    """
    from modules.bin_wrapper import fmtstr as _bf
    return await _run_bin_binary(_bf, binary_path)

@mcp.tool()
async def binary_heap(binary_path: str) -> str:
    """
    Analyze heap usage and suggest exploitation techniques. Detects allocator (glibc ptmalloc/Windows Heap), identifies heap functions, and provides technique guides (tcache poisoning, fastbin, unsafe unlink, House of Force).
    Phase: Binary Exploitation
    Related: binary_check, binary_analyze, binary_summary, binary_vulns, binary_checksec, binary_gadgets, binary_exploit_strategy, binary_functions, binary_strings, binary_fmtstr, binary_angr, binary_fuzz
    """
    from modules.bin_wrapper import heap as _bh
    return await _run_bin_binary(_bh, binary_path)

@mcp.tool()
async def binary_angr(binary_path: str, target_func: str = "system") -> str:
    """
    Run angr symbolic execution on a binary to find execution paths. Optionally find path to a target function (default: system). Returns function list, CFG stats, and path info.
    Phase: Binary Exploitation
    Related: binary_check, binary_analyze, binary_summary, binary_vulns, binary_checksec, binary_gadgets, binary_exploit_strategy, binary_functions, binary_strings, binary_fmtstr, binary_heap, binary_fuzz
    """
    from modules.bin_wrapper import angr as _ba
    return await _run_bin_kwargs(_ba, binary_path, target_func=target_func)

@mcp.tool()
async def binary_fuzz(binary_path: str) -> str:
    """
    Generate a fuzzing harness for a binary. Creates AFL++ harness.c and Python fuzz.py in a fuzz_harness/ directory with instructions.
    Phase: Binary Exploitation
    Related: binary_check, binary_analyze, binary_summary, binary_vulns, binary_checksec, binary_gadgets, binary_exploit_strategy, binary_functions, binary_strings, binary_fmtstr, binary_heap, binary_angr
    """
    from modules.bin_wrapper import fuzz as _bf
    return await _run_bin_binary(_bf, binary_path)

@mcp.tool()
async def binary_cyclic(length: int) -> str:
    """
    Generate a de Bruijn cyclic pattern of the given length for overflow offset discovery.
    Phase: Binary Exploitation
    Related: binary_check, binary_analyze, binary_summary, binary_vulns, binary_checksec, binary_gadgets, binary_exploit_strategy, binary_functions, binary_strings, binary_fmtstr, binary_heap, binary_angr
    """
    from modules.bin_wrapper import cyclic as _bc
    return await _run_bin_kwargs(_bc, length=length)

@mcp.tool()
async def binary_pattern_offset(value: str) -> str:
    """
    Find the offset of a value (hex like 0x61616171 or ASCII) in the cyclic pattern. Used after a crash to determine buffer overflow offset.
    Phase: Binary Exploitation
    Related: binary_check, binary_analyze, binary_summary, binary_vulns, binary_checksec, binary_gadgets, binary_exploit_strategy, binary_functions, binary_strings, binary_fmtstr, binary_heap, binary_angr
    """
    from modules.bin_wrapper import pattern_offset as _bp
    return await _run_bin_kwargs(_bp, value=value)


@mcp.tool()
async def bin_surface(target: str, max_depth: int = 3, with_strings: bool = True) -> str:
    """
    Scan a directory (or single file) of compiled binaries and map their CLI
    surface: subcommands, option switches, usage hints, URLs, CVE/version hints,
    embedded paths. Great for finding attack surface in bundled tools/agents.
    Phase: Binary Exploitation
    Related: binary_strings, binary_functions, binary_vulns, binary_analyze
    """
    from modules.bin_surface import scan_directory, scan_binary, format_report
    from pathlib import Path
    p = Path(target)
    if p.is_file():
        r = {"target": str(p), "found": 1, "scanned": 1,
             "results": [scan_binary(p, with_strings=with_strings)], "errors": []}
    else:
        r = await asyncio.to_thread(scan_directory, p, max_depth, with_strings)
    return format_report(r)


@mcp.tool()
async def compiled_scan(target: str, max_depth: int = 4, with_yara: bool = False,
                        min_severity: str = "info") -> str:
    """
    Scan compiled artifacts (ELF/PE/Mach-O/.NET/.class/.jar/.pyc) for common
    weaknesses visible without source: missing mitigations (NX/PIE/canary/
    RELRO/ASLR/DEP/CFG), command-execution sinks (system/popen/exec*/WinExec,
    CreateProcess), insecure DLL/library loading (LoadLibrary* + relative path,
    SetDllDirectory, ELF RPATH/RUNPATH), process-injection APIs, weak crypto
    (MD5/RC4), dangerous memory functions, embedded secrets (AWS/Google/JWT/keys)
    and TLS verify-bypass strings. Optional with_yara runs the bundled rules/yara
    set over each binary. Set min_severity to 'warning' or 'error' to filter.
    Phase: Binary Exploitation
    Related: bin_surface, binary_strings, binary_analyze, binary_checksec
    """
    from modules.compiled_scan import scan_target, format_report
    from pathlib import Path
    p = Path(target)
    if p.is_file():
        r = await asyncio.to_thread(scan_target, str(p), 1, with_yara, min_severity)
    else:
        r = await asyncio.to_thread(scan_target, str(p), max_depth, with_yara, min_severity)
    return format_report(r)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Case Notes
# ---------------------------------------------------------------------------
@mcp.tool()
def case_notes_add(case_id: str, body: str, tags: str = "") -> str:
    """
    Add a note to a case with optional comma-separated tags.
    Phase: Case Management
    Related: case_notes_list, case_info, case_list
    """
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
    r = _run(CaseManager().add_note, case_id, body, tag_list)
    if r is None:
        return "Case not found"
    return "Note added."


@mcp.tool()
def case_notes_list(case_id: str) -> str:
    """
    List all notes for a case.
    Phase: Case Management
    Related: case_notes_add, case_info, case_list
    """
    notes = _run(CaseManager().get_notes, case_id)
    if not notes:
        return "No notes."
    lines = [f"Notes ({len(notes)}):"]
    for i, n in enumerate(notes):
        ts = n.get("timestamp", "?")[:19]
        body = n.get("body", "")[:120]
        tags_str = ",".join(n.get("tags", []))
        tags_str = f" [{tags_str}]" if tags_str else ""
        lines.append(f"  [{i}] {ts}{tags_str} {body}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Evidence Management
# ---------------------------------------------------------------------------
@mcp.tool()
def case_evidence_list(case_id: str) -> str:
    """
    List evidence records for a case.
    Phase: Case Management
    Related: case_evidence_add, case_evidence_verify, case_info
    """
    ev = _run(CaseManager().get_evidence, case_id)
    if not ev:
        return "No evidence."
    lines = [f"Evidence ({len(ev)}):"]
    for e in ev:
        lines.append(f"  {e.get('filename','')} ({e.get('category','')}) — {e.get('sha256','')[:16]}... [{e.get('size',0)} bytes]")
    return "\n".join(lines)


@mcp.tool()
def case_evidence_upload(case_id: str, filepath: str, category: str = "evidence",
                         description: str = "") -> str:
    """
    Upload a file as evidence for a case.
    Phase: Case Management
    Related: case_evidence_add, case_evidence_list, case_evidence_verify, case_info
    """
    from pathlib import Path
    p = Path(filepath)
    if not p.exists():
        return f"Error: File not found: {filepath}"
    r = _run(CaseManager().add_evidence, case_id, str(p.resolve()),
             category=category, description=description)
    if r is None:
        return "Case not found or copy failed"
    return f"Evidence added: {r.get('filename','')} (sha256: {r.get('sha256','')[:16]}...)"


# ---------------------------------------------------------------------------
# Findings (global + per-case)
# ---------------------------------------------------------------------------
@mcp.tool()
def findings_list(severity: str = "", search: str = "",
                  case_id: str = "", tag: str = "") -> str:
    """
    List findings across all cases, optionally filtered by severity, search text, case, or tag.
    Phase: Case Management
    Related: findings_stats, case_finding_add, case_finding_detail, case_finding_update, case_findings_bulk_update, case_findings_bulk_delete
    """
    cm = CaseManager()
    sev = severity.lower().strip()
    search_lower = search.lower().strip()

    if case_id:
        cases = [{"case_id": case_id}]
    else:
        cases = _run(cm.list_cases)

    results = []
    for c in cases:
        cid = c.get("case_id", "")
        case_path = _run(cm._case_path, cid)
        if not case_path or not case_path.exists():
            continue
        db = FindingsDB(case_path)
        try:
            findings = _run(db.list)
        except Exception:
            continue
        for f in findings:
            if sev and f.get("severity", "").lower() != sev:
                continue
            if search_lower:
                txt = (f.get("title","") + " " + f.get("cve","") + " " + f.get("description","") + " " + f.get("id","")).lower()
                if search_lower not in txt:
                    ftag_text = " ".join(f.get("tags", [])).lower()
                    if search_lower not in ftag_text:
                        continue
            if tag:
                ftags = f.get("tags", [])
                if tag not in ftags:
                    continue
            # Stash the case id on each finding so the listing shows which
            # case it belongs to (was always blank because it was never set).
            f["_case_id"] = cid
            results.append(f)

    if not results:
        return "No findings match the filters."

    lines = [f"Findings ({len(results)}):"]
    for f in results:
        lines.append(f"  [{f.get('_case_id','')}] ({f.get('severity','?')}) {f.get('title','')[:70]} — {f.get('status','')}")
    return "\n".join(lines)


@mcp.tool()
def findings_stats() -> str:
    """
    Aggregated findings statistics across all cases.
    Phase: Case Management
    Related: findings_list, case_findings_list, case_info
    """
    cm = CaseManager()
    cases = _run(cm.list_cases)
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    status_counts = {}
    total = 0
    tag_counts = {}
    for c in cases:
        cid = c.get("case_id", "")
        db = FindingsDB(cm._case_path(cid))
        try:
            findings = _run(db.list)
        except Exception:
            continue
        for f in findings:
            total += 1
            sev = f.get("severity", "info")
            if sev in severity_counts:
                severity_counts[sev] += 1
            st = f.get("status", "unvalidated")
            status_counts[st] = status_counts.get(st, 0) + 1
            for t in f.get("tags", []):
                tag_counts[t] = tag_counts.get(t, 0) + 1
    lines = [f"Findings Stats ({total} total):"]
    lines.append("  By severity: " + ", ".join(f"{k}={v}" for k, v in sorted(severity_counts.items()) if v))
    lines.append("  By status: " + ", ".join(f"{k}={v}" for k, v in sorted(status_counts.items())))
    top_tags = sorted(tag_counts.items(), key=lambda x: -x[1])[:10]
    if top_tags:
        lines.append("  Top tags: " + ", ".join(f"{k}({v})" for k, v in top_tags))
    return "\n".join(lines)


@mcp.tool()
def case_finding_detail(case_id: str, finding_id: str) -> str:
    """
    Get full detail of a single finding.
    Phase: Case Management
    Related: case_finding_add, case_finding_update, findings_list, case_info
    """
    cm = CaseManager()
    info = _run(cm.info, case_id)
    if not info:
        return "Case not found"
    db = FindingsDB(cm._case_path(case_id))
    finding = _run(db.get, finding_id)
    if not finding:
        return "Finding not found"
    lines = [f"Finding: {finding.get('title','')}"]
    for k in ("id", "severity", "status", "cve", "cwe", "cvss_score", "cvss_vector", "source", "created", "updated"):
        v = finding.get(k, "")
        if v is not None and v != "":
            lines.append(f"  {k}: {v}")
    tags = finding.get("tags", [])
    if tags:
        lines.append(f"  tags: {', '.join(tags)}")
    for k in ("description", "remediation", "impact", "poc"):
        v = (finding.get(k, "") or "")[:500]
        if v:
            lines.append(f"  {k}: {v}")
    refs = finding.get("references", "")
    if refs:
        if isinstance(refs, list):
            lines.append("  references: " + ", ".join(refs))
        else:
            lines.append("  references: " + str(refs)[:200])
    return "\n".join(lines)


@mcp.tool()
def case_finding_delete(case_id: str, finding_id: str) -> str:
    """
    Delete a finding from a case.
    Phase: Case Management
    Related: case_finding_add, case_finding_update, case_finding_detail, findings_list
    """
    cm = CaseManager()
    info = _run(cm.info, case_id)
    if not info:
        return "Case not found"
    db = FindingsDB(cm._case_path(case_id))
    ok = _run(db.delete, finding_id)
    if ok:
        return f"Finding '{finding_id}' deleted."
    return "Finding not found"


@mcp.tool()
def case_findings_bulk_update(case_id: str, finding_ids: str,
                              status: str = "", severity: str = "",
                              title: str = "", description: str = "",
                              remediation: str = "", impact: str = "",
                              poc: str = "",
                              tags: str = "") -> str:
    """
    Bulk update multiple findings in a case. Provide comma-separated finding_ids.
    Only non-empty fields are updated.
    Phase: Case Management
    Related: case_finding_update, case_findings_bulk_delete, findings_list
    """
    ids = [f.strip() for f in finding_ids.split(",") if f.strip()]
    if not ids:
        return "Error: No finding_ids provided"
    cm = CaseManager()
    info = _run(cm.info, case_id)
    if not info:
        return "Case not found"
    changes = {k: v for k, v in {"status": status, "severity": severity, "title": title,
                                  "description": description, "remediation": remediation,
                                  "impact": impact, "poc": poc}.items() if v}
    if tags:
        changes["tags"] = [t.strip() for t in tags.split(",") if t.strip()]
    if not changes:
        return "Error: No fields to update"
    db = FindingsDB(cm._case_path(case_id))
    updated = 0
    errors = []
    for fid in ids:
        try:
            ok = _run(db.update, fid, **changes)
            if ok:
                updated += 1
            else:
                errors.append(fid)
        except Exception as e:
            errors.append(f"{fid}: {e}")
    parts = [f"Updated {updated}/{len(ids)} findings."]
    if errors:
        parts.append(f"Errors: {', '.join(errors[:5])}")
    return "\n".join(parts)


@mcp.tool()
def case_findings_bulk_delete(case_id: str, finding_ids: str) -> str:
    """
    Bulk delete findings from a case. Provide comma-separated finding_ids.
    Phase: Case Management
    Related: case_finding_delete, case_findings_bulk_update, findings_list
    """
    ids = [f.strip() for f in finding_ids.split(",") if f.strip()]
    if not ids:
        return "Error: No finding_ids provided"
    cm = CaseManager()
    info = _run(cm.info, case_id)
    if not info:
        return "Case not found"
    db = FindingsDB(cm._case_path(case_id))
    deleted = 0
    errors = []
    for fid in ids:
        try:
            ok = _run(db.delete, fid)
            if ok:
                deleted += 1
            else:
                errors.append(fid)
        except Exception as e:
            errors.append(f"{fid}: {e}")
    parts = [f"Deleted {deleted}/{len(ids)} findings."]
    if errors:
        parts.append(f"Errors: {', '.join(errors[:5])}")
    return "\n".join(parts)


@mcp.tool()
def case_finding_create(case_id: str, title: str,
                        severity: str = "medium",
                        description: str = "",
                        remediation: str = "",
                        source: str = "manual",
                        cve: str = "", cwe: str = "",
                        impact: str = "", poc: str = "",
                        status: str = "",
                        command_output: str = "",
                        cvss_score: float = None, cvss_vector: str = "",
                        tags: str = "", cpe: str = "") -> str:
    """
    Create a new finding in a case. Returns the created finding summary.
    Supports CVSS score/vector, tag labels, and a CPE 2.3 component identifier.
    Phase: Case Management
    Related: case_finding_detail, case_finding_update, case_finding_delete, findings_list
    """
    cm = CaseManager()
    info = _run(cm.info, case_id)
    if not info:
        return "Case not found"
    db = FindingsDB(cm._case_path(case_id))
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
    finding = _run(db.add, title=title, severity=severity, description=description,
                   remediation=remediation, source=source, cve=cve, cwe=cwe,
                   impact=impact, poc=poc,
                   command_output=command_output,
                   cvss_score=cvss_score, cvss_vector=cvss_vector,
                   tags=tag_list, cpe=cpe)
    if status and status != "unvalidated":
        _run(db.update, finding["id"], status=status)
    return f"Finding created: {finding.get('id','')} ({severity}) — {title[:60]}"


# ---------------------------------------------------------------------------
# @mcp.prompt() — Pre-canned prompt templates for AI clients
# ---------------------------------------------------------------------------

@mcp.prompt(name="analyze_finding", title="Analyze a Finding",
            description="Given a case and finding ID, returns a structured analysis prompt to assess the vulnerability.")
def analyze_finding(case_id: str, finding_id: str) -> list[dict]:
    return [
        {"role": "user", "content": {
            "type": "resource",
            "resource": {"uri": f"cc://cases/{case_id}/findings", "text": ""}
        }},
        {"role": "user", "content": f"""You are analyzing finding **{finding_id}** from case **{case_id}**.

Please provide:
1. **Vulnerability Assessment** — What is the root cause? What is the real-world impact?
2. **Exploitability** — How easy is it to exploit? What prerequisites are needed?
3. **Business Impact** — What data/systems are at risk? Compliance implications?
4. **Recommended Remediation** — Specific steps to fix the vulnerability.
5. **References** — CWE/CVE links, similar vulnerabilities, mitigation patterns.

Be specific and actionable. Reference CVSS vector if available."""}
    ]


@mcp.prompt(name="generate_finding", title="Generate a Finding from Output",
            description="Given raw command output and target info, returns a prompt to create a structured finding.")
def generate_finding(command_output: str, target: str = "", source: str = "") -> list[dict]:
    source_line = f" from **{source}**" if source else ""
    target_line = f"\n**Target:** {target}\n" if target else "\n"
    return [
        {"role": "user", "content": f"""You are a penetration tester documenting a finding.

Raw output captured{source_line}:{target_line}
```
{command_output[:4000]}
```

Please produce a structured finding with:
- **Title** (concise, descriptive)
- **Severity** (critical/high/medium/low/info)
- **Description** (what was found, why it matters)
- **Impact** (business/technical consequences)
- **Remediation** (specific fix steps)
- **CVSS vector** (if applicable)
- **Tags** (e.g. cwe:79, mitre-attack:T1078)

Output as JSON with keys: title, severity, description, impact, remediation, cvss_vector, tags."""}
    ]


@mcp.prompt(name="pentest_plan", title="Pentest Methodology Plan",
            description="Given a case type and target, generates a step-by-step pentest methodology plan.")
def pentest_plan(case_type: str, target: str = "") -> list[dict]:
    target_line = f" against **{target}**" if target else ""
    return [
        {"role": "user", "content": f"""You are planning a {case_type} penetration test{target_line}.

Please produce a step-by-step methodology plan covering:

1. **Reconnaissance** — Passive and active information gathering
2. **Enumeration** — Service/port scanning, banner grabbing, technology fingerprinting
3. **Vulnerability Assessment** — Scanning, manual checks, configuration review
4. **Exploitation** — Prioritized attack paths
5. **Post-Exploitation** — Privilege escalation, lateral movement, persistence
6. **Reporting** — Findings documentation, evidence gathering

Tailor each phase to the **{case_type}** assessment type. Include specific tools and techniques relevant to this scenario."""}
    ]


@mcp.prompt(name="report_section", title="Write a Report Section",
            description="Given a case ID and section name, returns a prompt to draft that section of the pentest report.")
def report_section(case_id: str, section: str) -> list[dict]:
    return [
        {"role": "user", "content": {
            "type": "resource",
            "resource": {"uri": f"cc://cases/{case_id}", "text": ""}
        }},
        {"role": "user", "content": f"""You are writing the **{section}** section of a penetration test report for case **{case_id}**.

Use the case data above and produce professional report text that is:
- Clear and concise for both technical and non-technical readers
- Specific to the findings and scope of this engagement
- Actionable with concrete observations

The section "{section}" should include relevant findings, evidence, and recommendations."""}
    ]


@mcp.prompt(name="remediate_finding", title="Suggest Remediation",
            description="Given a finding ID, returns a remediation-focused prompt.")
def remediate_finding(case_id: str, finding_id: str) -> list[dict]:
    return [
        {"role": "user", "content": {
            "type": "resource",
            "resource": {"uri": f"cc://cases/{case_id}/findings", "text": ""}
        }},
        {"role": "user", "content": f"""You are a remediation specialist reviewing finding **{finding_id}** from case **{case_id}**.

Please provide:

1. **Root Cause Analysis** — What configuration, code, or design flaw caused this?
2. **Remediation Steps** — Detailed, step-by-step fix instructions. Include specific commands, code changes, or configuration modifications.
3. **Verification** — How to confirm the fix is effective.
4. **Alternative Mitigations** — If full remediation isn't immediately possible, what compensating controls can reduce risk?
5. **Timeline Estimate** — Estimated effort (hours/days) to implement the fix.

Focus on practical, implementable solutions."""}
    ]


@mcp.prompt(name="summarize_case", title="Summarize Case for Executive Report",
            description="Returns a prompt to generate an executive summary of a case's findings and impact.")
def summarize_case(case_id: str) -> list[dict]:
    return [
        {"role": "user", "content": {
            "type": "resource",
            "resource": {"uri": f"cc://cases/{case_id}", "text": ""}
        }},
        {"role": "user", "content": {
            "type": "resource",
            "resource": {"uri": f"cc://cases/{case_id}/findings", "text": ""}
        }},
        {"role": "user", "content": f"""You are writing an executive summary for case **{case_id}**.

Based on the case data and findings provided, produce:

1. **Executive Summary** — 2-3 paragraphs describing the engagement scope, key findings, and overall security posture (non-technical).
2. **Key Observations** — Bullet points of the most critical issues found.
3. **Risk Overview** — Summary of risk levels and affected areas.
4. **Top Recommendations** — 3-5 prioritized action items for leadership.

Write for a C-suite audience: clear, impactful, non-technical where possible."""}
    ]


@mcp.prompt(name="review_scope", title="Review Scope and Attack Paths",
            description="Given a case ID, returns a prompt to review in-scope targets and suggest attack paths.")
def review_scope(case_id: str) -> list[dict]:
    return [
        {"role": "user", "content": {
            "type": "resource",
            "resource": {"uri": f"cc://cases/{case_id}/scope", "text": ""}
        }},
        {"role": "user", "content": f"""You are reviewing the scope for case **{case_id}**.

Based on the in-scope and out-of-scope targets above, please:

1. **Attack Surface Analysis** — Identify the most promising entry points
2. **Attack Path Suggestions** — Propose 3-5 specific attack paths an adversary might use
3. **Lateral Movement Vectors** — How an attacker might pivot between targets
4. **High-Value Targets** — Which assets are most critical to protect
5. **Scope Edge Cases** — Any ambiguous scope items that need clarification

Consider the relationships between targets and common misconfigurations for each service/application type."""}
    ]


@mcp.prompt(name="crack_hashes", title="Hash Cracking Strategy",
            description="Given hash types and optional sample hashes, suggests a cracking strategy.")
def crack_hashes(hash_types: str, hashes: str = "") -> list[dict]:
    hash_sample = f"\nSample hashes:\n```\n{hashes[:2000]}\n```\n" if hashes else "\n"
    return [
        {"role": "user", "content": f"""You are assisting with hash cracking during a penetration test.

Hash types identified: **{hash_types}**{hash_sample}

Please provide:

1. **Hash Identification** — Confirm each hash type and its hashcat mode number
2. **Wordlist Strategy** — Recommended wordlists and rule files for each type
3. **Attack Mode Plan** — Dictionary → Rule-based → Mask → Brute-force progression
4. **Time Estimates** — Approximate cracking time for each hash type given common hardware
5. **Alternative Approaches** — If cracking fails, what other methods can obtain the plaintext?
6. **Prioritization** — Which hashes to crack first based on type and likelihood of success

Output a clear step-by-step plan."""}
    ]


@mcp.prompt(name="analyze_network", title="Analyze Network Scan Results",
            description="Given target and port data, analyzes network scan findings for vulnerabilities.")
def analyze_network(target: str, ports: str = "") -> list[dict]:
    ports_line = f"\nOpen ports/services:\n```\n{ports[:2000]}\n```\n" if ports else "\n"
    return [
        {"role": "user", "content": f"""You are analyzing network scan results for target **{target}**.{ports_line}

Please provide:

1. **Attack Surface Summary** — What services and versions are exposed?
2. **High-Risk Services** — Which services are most likely to be vulnerable?
3. **Known Vulnerabilities** — CVEs or common misconfigurations for each service
4. **Exploitation Priority** — Rank services by likelihood of successful exploitation
5. **Recommended Next Steps** — Specific enumeration or exploitation actions to take

Be specific about versions, known CVEs, and relevant exploit techniques (e.g., EternalBlue, Log4Shell, etc.)."""}
    ]


@mcp.prompt(name="write_rules", title="Generate Detection Rules",
            description="Given a threat description and target format, generates detection rules.")
def write_rules(description: str, rule_format: str = "sigma") -> list[dict]:
    return [
        {"role": "user", "content": f"""You are a detection engineer creating **{rule_format}** rules.

Threat description:
```
{description}
```

Please generate:

1. **Rule Title** — Clear, descriptive name
2. **Log Sources Needed** — What logs are required (e.g., Windows Event ID 4688, Sysmon EID 1)
3. **Detection Logic** — The actual {rule_format} rule with proper syntax
4. **False Positives** — Known scenarios that could trigger false alarms
5. **Testing Steps** — How to validate the rule works

Output the complete {rule_format} rule in a code block, plus explanatory notes."""}
    ]


@mcp.prompt(name="investigate_loot", title="Investigate Looted Credentials",
            description="Given loot credentials, suggests reuse testing and lateral movement opportunities.")
def investigate_loot(source: str, target: str = "") -> list[dict]:
    target_line = f" from **{target}**" if target else ""
    return [
        {"role": "user", "content": {
            "type": "resource",
            "resource": {"uri": "cc://loot/credentials", "text": ""}
        }},
        {"role": "user", "content": f"""You are investigating looted credentials{source}{target_line}.

Based on the available loot database entries, please analyze:

1. **Credential Reuse Potential** — What services/systems could these credentials be tested against?
2. **Lateral Movement Opportunities** — Can any credentials grant access to other systems?
3. **Privilege Escalation Paths** — Any privileged accounts found?
4. **Pattern Analysis** — Common themes (default passwords, company name patterns, password policy indicators)
5. **Testing Priority** — Which credentials to test first for maximum impact

Focus on practical password reuse and lateral movement scenarios."""}
    ]


@mcp.prompt(name="evidence_request", title="Request Evidence Collection",
            description="Given a case and finding type, suggests what evidence to collect for that finding.")
def evidence_request(case_id: str, finding_type: str = "") -> list[dict]:
    type_line = f" for **{finding_type}**" if finding_type else ""
    return [
        {"role": "user", "content": f"""You are guiding evidence collection for case **{case_id}**{type_line}.

Please suggest:

1. **Required Evidence** — What screenshots, logs, or output is needed to prove each finding
2. **Collection Commands** — Specific commands to run (nmap, curl, sqlmap, etc.) to capture evidence
3. **Documentation Standards** — How to label and organize evidence files
4. **Chain of Custody** — How to maintain integrity (hashes, timestamps)
5. **Minimum Viable Evidence** — What's the smallest amount of evidence needed to validate each finding

Be practical — suggest commands that produce clear, court-admissible evidence."""}
    ]


# ---------------------------------------------------------------------------
# Prompts Library (YAML-backed tools)
# ---------------------------------------------------------------------------
@mcp.tool()
def prompts_list() -> str:
    """
    List all available prompt templates.
    Phase: Case Management
    Related: prompts_get
    """
    import yaml
    prompts_dir = _HERE / "prompts"
    if not prompts_dir.is_dir():
        return "No prompts directory."
    results = []
    for f in sorted(prompts_dir.glob("*.yaml")):
        try:
            data = yaml.safe_load(f.read_text()) or {}
            results.append(f"  {f.stem:<30} {data.get('title',''):<40} {data.get('description','')[:50]}")
        except Exception as e:
            results.append(f"  {f.stem:<30} ERROR: {e}")
    if not results:
        return "No prompts found."
    return f"Prompts ({len(results)}):\n" + "\n".join(results)


@mcp.tool()
def prompts_get(name: str) -> str:
    """
    Get the full content of a prompt template by name.
    Phase: Case Management
    Related: prompts_list
    """
    import yaml
    path = _HERE / "prompts" / f"{name}.yaml"
    if not path.is_file():
        return f"Prompt '{name}' not found"
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except Exception as e:
        return f"Error loading prompt: {e}"
    lines = [f"Prompt: {data.get('title', name)}"]
    desc = data.get("description", "")
    if desc:
        lines.append(f"Description: {desc}")
    tags = data.get("tags", [])
    if tags:
        lines.append(f"Tags: {', '.join(tags)}")
    prompt_text = data.get("prompt", "")
    if prompt_text:
        lines.append(f"\n--- Content ---\n{prompt_text}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Flashcards
# ---------------------------------------------------------------------------
@mcp.tool()
def flashcards_list() -> str:
    """
    List all available flashcard decks with card counts.
    Phase: Case Management
    Related: flashcards_deck
    """
    import yaml
    decks_dir = _HERE / "flashcards"
    if not decks_dir.is_dir():
        return "No flashcards directory."
    results = []
    for f in sorted(decks_dir.glob("*.yaml")):
        try:
            data = yaml.safe_load(f.read_text()) or {}
            results.append(f"  {f.stem:<30} {data.get('title',''):<40} {len(data.get('cards',[]))} cards")
        except Exception:
            results.append(f"  {f.stem:<30} ERROR")
    if not results:
        return "No flashcard decks found."
    return f"Flashcard Decks ({len(results)}):\n" + "\n".join(results)


@mcp.tool()
def flashcards_deck(name: str) -> str:
    """
    Get the full content of a flashcard deck by name (including all cards).
    Phase: Case Management
    Related: flashcards_list
    """
    import re as _re
    import yaml
    if not _re.fullmatch(r"[A-Za-z0-9_-]+", name or ""):
        return f"Invalid deck name: {name!r}"
    decks_dir = (_HERE / "flashcards").resolve()
    path = decks_dir / f"{name}.yaml"
    if path.parent != decks_dir or not path.is_file():
        return f"Deck '{name}' not found"
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except Exception as e:
        return f"Error loading deck: {e}"
    cards = data.get("cards", [])
    lines = [f"Deck: {data.get('title', name)}", f"Description: {data.get('description','')}",
             f"Cards: {len(cards)}"]
    for i, c in enumerate(cards):
        q = c.get("question", "")[:100]
        a = c.get("answer", "")[:100]
        lines.append(f"  [{i+1}] Q: {q}")
        lines.append(f"       A: {a}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Case Tasks (toggle + delete)
# ---------------------------------------------------------------------------
@mcp.tool()
def case_task_toggle(case_id: str, task_id: str) -> str:
    """
    Mark a task as done/completed.
    Phase: Case Management
    Related: case_task_add, case_task_list, case_task_delete
    """
    cm = CaseManager()
    tasks = _run(cm.task_list, case_id, True)
    task = next((t for t in tasks if t.get("id") == task_id), None)
    if not task:
        return "Task not found"
    if task.get("done"):
        return "Task already done"
    r = _run(cm.task_done, case_id, task_id)
    if r:
        return "Task marked done."
    return "Failed to update task"


@mcp.tool()
def case_task_delete(case_id: str, task_id: str) -> str:
    """
    Delete a task from a case.
    Phase: Case Management
    Related: case_task_add, case_task_list, case_task_toggle
    """
    cm = CaseManager()
    ok = _run(cm.task_delete, case_id, task_id)
    if ok:
        return "Task deleted."
    return "Task not found"


# ---------------------------------------------------------------------------
# Strengths / Weaknesses (remove)
# ---------------------------------------------------------------------------
@mcp.tool()
def case_strength_remove(case_id: str, index: int) -> str:
    """
    Remove a strength from a case by index.
    Phase: Case Management
    Related: case_strength_add, case_strength_list, case_weakness_add, case_weakness_list
    """
    cm = CaseManager()
    info = _run(cm.info, case_id)
    if not info:
        return "Case not found"
    strengths = info.get("strengths", [])
    if index < 0 or index >= len(strengths):
        return f"Invalid index {index}. Has {len(strengths)} strengths."
    _run(cm.remove_strength, case_id, index=index)
    return "Strength removed."


@mcp.tool()
def case_weakness_remove(case_id: str, index: int) -> str:
    """
    Remove a weakness from a case by index.
    Phase: Case Management
    Related: case_weakness_add, case_weakness_list, case_strength_add, case_strength_list
    """
    cm = CaseManager()
    info = _run(cm.info, case_id)
    if not info:
        return "Case not found"
    weaknesses = info.get("weaknesses", [])
    if index < 0 or index >= len(weaknesses):
        return f"Invalid index {index}. Has {len(weaknesses)} weaknesses."
    _run(cm.remove_weakness, case_id, index=index)
    return "Weakness removed."


# ---------------------------------------------------------------------------
# Case File Browser
# ---------------------------------------------------------------------------
@mcp.tool()
def case_files_list(case_id: str, path: str = "") -> str:
    """
    List files in a case's subdirectory (e.g. scans/, evidence/, loot/).
    Phase: Case Management
    Related: case_files_preview, case_info
    """
    cm = CaseManager()
    info = _run(cm.info, case_id)
    if not info:
        return "Case not found"
    case_dir = cm._case_path(case_id)
    target = (case_dir / path).resolve()
    if not _path_is_inside(target, case_dir) and target != case_dir:
        return "Access denied"
    if not target.exists():
        return f"Path not found: {path}"
    if target.is_file():
        return f"Cannot list: {path} is a file"
    entries = []
    for child in sorted(target.iterdir()):
        if child.name.startswith("."):
            continue
        rel = str(child.relative_to(case_dir)).replace("\\", "/")
        if child.is_dir():
            entries.append(f"  [DIR] {child.name}/  ({rel})")
        else:
            size = child.stat().st_size
            entries.append(f"  [FILE] {child.name:<30} {size:>8,} bytes  ({rel})")
    if not entries:
        return f"Empty directory: {path or '/'}"
    header = f"Case files: {path or '/'} ({len(entries)} items)"
    return header + "\n" + "\n".join(entries)


@mcp.tool()
def case_files_preview(case_id: str, file_path: str, max_chars: int = 2000) -> str:
    """
    Preview a file's contents from a case directory.
    Phase: Case Management
    Related: case_files_list, case_info
    """
    cm = CaseManager()
    info = _run(cm.info, case_id)
    if not info:
        return "Case not found"
    case_dir = cm._case_path(case_id)
    target = (case_dir / file_path).resolve()
    if not _path_is_inside(target, case_dir):
        return "Access denied"
    if not target.exists() or not target.is_file():
        return "File not found"
    try:
        text = target.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return f"Binary file ({target.stat().st_size} bytes) — cannot preview as text"
    if len(text) > max_chars:
        text = text[:max_chars] + f"\n... (truncated, full size: {len(text):,} chars)"
    return f"--- {target.name} ({target.stat().st_size:,} bytes) ---\n{text}"


@mcp.tool()
def case_files_upload(case_id: str, source_path: str, subdir: str = "") -> str:
    """
    Upload a local file to a case's directory (not evidence — use case_evidence_upload for evidence).
    Phase: Case Management
    Related: case_files_list, case_files_preview, case_files_delete, case_files_tree, case_evidence_upload
    """
    from pathlib import Path
    cm = CaseManager()
    info = _run(cm.info, case_id)
    if info is None:
        return f"Error: Case '{case_id}' not found"
    src = Path(source_path)
    if not src.exists():
        return f"Error: Source file not found: {source_path}"
    case_dir = cm._case_path(case_id)
    target_dir = (case_dir / subdir).resolve()
    if not _path_is_inside(target_dir, case_dir) and target_dir != case_dir:
        return "Error: Access denied (path traversal)"
    target_dir.mkdir(parents=True, exist_ok=True)
    dest = target_dir / src.name
    import shutil
    shutil.copy2(str(src), str(dest))
    return f"Uploaded '{src.name}' to case '{case_id}'/{subdir} ({dest.stat().st_size:,} bytes)"


@mcp.tool()
def case_files_delete(case_id: str, file_path: str) -> str:
    """
    Delete a file from a case directory (not evidence — use the evidence API for that).
    Phase: Case Management
    Related: case_files_list, case_files_preview, case_files_upload, case_files_tree
    """
    cm = CaseManager()
    info = _run(cm.info, case_id)
    if info is None:
        return f"Error: Case '{case_id}' not found"
    case_dir = cm._case_path(case_id)
    target = (case_dir / file_path).resolve()
    if not _path_is_inside(target, case_dir):
        return "Error: Access denied (path traversal)"
    if not target.exists():
        return f"Error: File not found: {file_path}"
    if target.is_dir():
        return "Error: Cannot delete directories via this endpoint"
    sz = target.stat().st_size
    target.unlink()
    return f"Deleted '{file_path}' ({sz:,} bytes) from case '{case_id}'"


@mcp.tool()
def case_files_tree(case_id: str) -> str:
    """
    Return the full directory tree for a case.
    Phase: Case Management
    Related: case_files_list, case_files_preview, case_files_upload, case_files_delete
    """
    cm = CaseManager()
    info = _run(cm.info, case_id)
    if info is None:
        return f"Error: Case '{case_id}' not found"
    case_dir = cm._case_path(case_id)
    if not case_dir.exists():
        return f"Case directory for '{case_id}' is empty or does not exist."
    lines = [f"File tree for case '{case_id}':"]
    def _walk(d, prefix=""):
        entries = sorted(d.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
        for i, entry in enumerate(entries):
            is_last = i == len(entries) - 1
            connector = "└── " if is_last else "├── "
            lines.append(prefix + connector + entry.name + ("/" if entry.is_dir() else ""))
            if entry.is_dir():
                ext = "    " if is_last else "│   "
                _walk(entry, prefix + ext)
    _walk(case_dir)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Dashboard Stats
# ---------------------------------------------------------------------------
@mcp.tool()
def dashboard_stats() -> str:
    """
    Get aggregated dashboard statistics across all cases and findings.
    Phase: Case Management
    Related: findings_stats, case_list, projects_board_data
    """
    cm = CaseManager()
    cases = _run(cm.list_cases)
    by_status = {}
    by_type = {}
    all_findings = []
    cases_list = []
    for c in cases:
        st = c.get("status", "unknown")
        by_status[st] = by_status.get(st, 0) + 1
        tp = c.get("type", "unknown")
        by_type[tp] = by_type.get(tp, 0) + 1
        cid = c.get("case_id", "")
        db = FindingsDB(cm._case_path(cid))
        try:
            c_findings = _run(db.list)
        except Exception:
            c_findings = []
        c_finding_sev = {}
        for ff in c_findings:
            s = ff.get("severity", "info")
            c_finding_sev[s] = c_finding_sev.get(s, 0) + 1
        cases_list.append(f"  {cid:<25} status={st:<10} type={tp:<15} findings={len(c_findings)} critical={c_finding_sev.get('critical',0)}")
        for f in c_findings:
            all_findings.append(f)
    by_severity = {}
    for f in all_findings:
        sev = f.get("severity", "info")
        by_severity[sev] = by_severity.get(sev, 0) + 1
    lines = [f"Dashboard: {len(cases)} cases, {len(all_findings)} findings"]
    lines.append("  Cases by status: " + ", ".join(f"{k}={v}" for k, v in sorted(by_status.items())))
    lines.append("  Cases by type: " + ", ".join(f"{k}={v}" for k, v in sorted(by_type.items())))
    lines.append("  Findings by severity: " + ", ".join(f"{k}={v}" for k, v in sorted(by_severity.items())))
    lines.append("\nCases:")
    lines.extend(cases_list)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Projects Board (Kanban)
# ---------------------------------------------------------------------------
@mcp.tool()
def projects_board_data() -> str:
    """
    Get the Kanban project board data with cases grouped by status column.
    Phase: Case Management
    Related: projects_board_update, dashboard_stats, case_list
    """
    cm = CaseManager()
    cases = _run(cm.list_cases)
    cols = {"open": [], "pending": [], "on-hold": [], "closed": []}
    for c in cases:
        status = c.get("status", "open")
        if status not in cols:
            status = "open"
        cid = c.get("case_id", "")
        db = FindingsDB(cm._case_path(cid))
        try:
            findings = _run(db.list)
        except Exception:
            findings = []
        cols[status].append(f"  {cid:<25} {c.get('client',''):<20} findings={len(findings)}")
    lines = ["Project Board:"]
    for col_name, items in cols.items():
        if items:
            lines.append(f"\n  [{col_name}] ({len(items)} cases)")
            lines.extend(items)
    return "\n".join(lines)


@mcp.tool()
def projects_board_update(case_id: str, status: str) -> str:
    """
    Update a case's status on the project board (open/pending/on-hold/closed).
    Phase: Case Management
    Related: projects_board_data, case_update_meta
    """
    valid = {"open", "pending", "on-hold", "closed"}
    if status not in valid:
        return f"Invalid status: {status}. Valid: {', '.join(sorted(valid))}"
    cm = CaseManager()
    r = _run(cm.set_meta, case_id, status=status)
    if r is None:
        return "Case not found"
    return f"Case '{case_id}' status updated to '{status}'."


# ---------------------------------------------------------------------------
# Job Queue
# ---------------------------------------------------------------------------
@mcp.tool()
def jobs_list() -> str:
    """
    List recent jobs in the job queue.
    Phase: Case Management
    Related: job_status, job_create, job_cancel
    """
    from modules.job_queue import get_job_manager
    jm = get_job_manager()
    jobs = _run(jm.list_jobs, 50)
    if not jobs:
        return "No jobs."
    lines = [f"Jobs ({len(jobs)}):"]
    for j in jobs:
        lines.append(f"  {j.get('id','')[:20]:<25} {j.get('type','?'):<20} {j.get('status','?'):<12} {j.get('title','')[:40]}")
    return "\n".join(lines)


@mcp.tool()
def job_status(job_id: str) -> str:
    """
    Get the status and details of a specific job.
    Phase: Case Management
    Related: jobs_list, job_create, job_cancel
    """
    from modules.job_queue import get_job_manager
    jm = get_job_manager()
    job = _run(jm.get, job_id)
    if not job:
        return "Job not found"
    lines = [f"Job: {job.get('title','')}"]
    for k in ("id", "type", "status", "progress", "total_steps", "result", "error", "created", "updated"):
        v = job.get(k)
        if v is not None and v != "":
            lines.append(f"  {k}: {v}")
    return "\n".join(lines)


@mcp.tool()
def job_create(job_type: str = "custom", title: str = "Untitled Job",
               total_steps: int = 100, case_id: str = "") -> str:
    """
    Create a new job in the job queue (optionally tied to a case).
    Phase: Case Management
    Related: jobs_list, job_status, job_cancel
    """
    from modules.job_queue import get_job_manager
    jm = get_job_manager()
    job_id = _run(jm.create, job_type, title, total_steps, case_id=case_id)
    return f"Job created: {job_id}"


@mcp.tool()
def job_cancel(job_id: str) -> str:
    """
    Cancel a running job.
    Phase: Case Management
    Related: jobs_list, job_status, job_create
    """
    from modules.job_queue import get_job_manager
    jm = get_job_manager()
    _run(jm.cancel, job_id)
    return f"Job '{job_id}' cancelled."


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------
@mcp.tool()
def assets_list(customer_id: str = "", kind: str = "",
                tag: str = "", search: str = "") -> str:
    """
    List assets in the asset inventory, optionally filtered.
    Phase: Utility / Infrastructure
    Related: assets_create, assets_delete, assets_stats, assets_import_nmap
    """
    from modules.asset_tracker import AssetTracker
    at = AssetTracker()
    assets = _run(at.list_assets, customer_id=customer_id, kind=kind, tag=tag, search=search)
    if not assets:
        return "No assets match the filters."
    lines = [f"Assets ({len(assets)}):"]
    for a in assets:
        lines.append(f"  {a.get('id','')[:16]:<18} {a.get('kind','?'):<10} {a.get('address',''):<20} {a.get('label',''):<30} {a.get('fqdn','')}")
    return "\n".join(lines)


@mcp.tool()
def assets_create(kind: str, address: str, customer_id: str = "",
                  label: str = "", fqdn: str = "", os_info: str = "",
                  tags: str = "", notes: str = "") -> str:
    """
    Create a new asset in the inventory.
    Phase: Utility / Infrastructure
    Related: assets_list, assets_delete, assets_stats, assets_import_nmap
    """
    from modules.asset_tracker import AssetTracker
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
    at = AssetTracker()
    try:
        a = _run(at.create_asset, customer_id=customer_id, kind=kind,
                 address=address, label=label, fqdn=fqdn,
                 os=os_info, tags=tag_list, source="manual", notes=notes)
        return f"Asset created: {a.get('id','')} ({kind}) — {address}"
    except ValueError as e:
        return f"Error: {e}"


@mcp.tool()
def assets_delete(asset_id: str) -> str:
    """
    Delete an asset from the inventory.
    Phase: Utility / Infrastructure
    Related: assets_list, assets_create, assets_stats
    """
    from modules.asset_tracker import AssetTracker
    try:
        _run(AssetTracker().delete_asset, asset_id)
        return f"Asset '{asset_id}' deleted."
    except FileNotFoundError as e:
        return f"Error: {e}"


@mcp.tool()
def assets_stats() -> str:
    """
    Get asset inventory statistics.
    Phase: Utility / Infrastructure
    Related: assets_list, assets_create, assets_delete
    """
    from modules.asset_tracker import AssetTracker
    stats = _run(AssetTracker().get_stats)
    if not stats:
        return "No assets."
    lines = ["Asset Stats:"]
    for k, v in stats.items():
        if isinstance(v, dict):
            lines.append(f"  {k}: " + ", ".join(f"{sk}={sv}" for sk, sv in v.items()))
        else:
            lines.append(f"  {k}: {v}")
    return "\n".join(lines)


@mcp.tool()
def assets_import_nmap(xml: str, customer_id: str = "", case_id: str = "") -> str:
    """
    Import assets from Nmap XML output.
    Phase: Utility / Infrastructure
    Related: assets_list, assets_create, assets_stats
    """
    from modules.asset_tracker import AssetTracker
    try:
        result = _run(AssetTracker().import_nmap_xml, xml,
                      customer_id=customer_id, case_id=case_id)
        return f"Imported {result.get('imported', 0)} assets, {result.get('updated', 0)} updated, {result.get('errors', 0)} errors."
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Customers
# ---------------------------------------------------------------------------
@mcp.tool()
def customers_list() -> str:
    """
    List all customers in the asset inventory.
    Phase: Utility / Infrastructure
    Related: customers_create, customers_delete, assets_list
    """
    from modules.asset_tracker import AssetTracker
    customers = _run(AssetTracker().list_customers)
    if not customers:
        return "No customers."
    lines = [f"Customers ({len(customers)}):"]
    for c in customers:
        lines.append(f"  {c.get('id','')[:16]:<18} {c.get('name',''):<30} {c.get('notes','')[:50]}")
    return "\n".join(lines)


@mcp.tool()
def customers_create(name: str, notes: str = "") -> str:
    """
    Create a new customer record.
    Phase: Utility / Infrastructure
    Related: customers_list, customers_delete, assets_list
    """
    from modules.asset_tracker import AssetTracker
    try:
        c = _run(AssetTracker().create_customer, name, notes)
        return f"Customer created: {c.get('id','')} ({name})"
    except ValueError as e:
        return f"Error: {e}"


@mcp.tool()
def customers_delete(customer_id: str) -> str:
    """
    Delete a customer record.
    Phase: Utility / Infrastructure
    Related: customers_list, customers_create, assets_list
    """
    from modules.asset_tracker import AssetTracker
    try:
        _run(AssetTracker().delete_customer, customer_id)
        return f"Customer '{customer_id}' deleted."
    except FileNotFoundError as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------
@mcp.tool()
def credentials_list(asset_id: str = "") -> str:
    """
    List managed credentials in the asset inventory, optionally filtered by asset.
    For captured/compromised credentials (hashes, dumped passwords) use loot_list_credentials.
    Phase: Utility / Infrastructure
    Related: credentials_create, credentials_get, credentials_delete, assets_list, loot_list_credentials
    """
    from modules.asset_tracker import AssetTracker
    creds = _run(AssetTracker().list_credentials, asset_id=asset_id)
    if not creds:
        return "No credentials."
    lines = [f"Credentials ({len(creds)}):"]
    for c in creds:
        lines.append(f"  {c.get('id','')[:16]:<18} {c.get('kind','?'):<15} {c.get('username',''):<20} {c.get('service',''):<15} asset={c.get('asset_id','')[:16]}")
    return "\n".join(lines)


@mcp.tool()
def credentials_create(asset_id: str, kind: str, username: str,
                       secret: str, service: str = "",
                       url: str = "", notes: str = "") -> str:
    """
    Store a managed credential for an inventory asset (encrypted at rest).
    Use this for known/preshared credentials tied to an asset.
    For captured/compromised credentials (hashes, dumped passwords) use loot_add_credential.
    Phase: Utility / Infrastructure
    Related: credentials_list, credentials_get, credentials_delete, assets_list, loot_add_credential
    """
    from modules.asset_tracker import AssetTracker
    try:
        c = _run(AssetTracker().add_credential, asset_id=asset_id, kind=kind,
                 username=username, secret=secret, service=service,
                 url=url, notes=notes)
        return f"Credential created: {c.get('id','')} ({kind}:{username})"
    except ValueError as e:
        return f"Error: {e}"


@mcp.tool()
def credentials_get(cred_id: str, decrypt: bool = False) -> str:
    """
    Get managed credential details from the asset inventory (optionally decrypt).
    Phase: Utility / Infrastructure
    Related: credentials_list, credentials_create, credentials_delete, loot_search
    """
    from modules.asset_tracker import AssetTracker
    c = _run(AssetTracker().get_credential, cred_id, decrypt=decrypt)
    if not c:
        return "Credential not found"
    lines = [f"Credential: {c.get('id','')}"]
    for k in ("kind", "username", "service", "url", "asset_id", "notes", "created"):
        v = c.get(k, "")
        if v:
            lines.append(f"  {k}: {v}")
    secret = c.get("secret", "")
    if secret:
        if decrypt:
            lines.append(f"  secret: {secret}")
        else:
            lines.append(f"  secret: {'*' * min(len(secret), 16)} (hidden, use decrypt=True)")
    return "\n".join(lines)


@mcp.tool()
def credentials_delete(cred_id: str) -> str:
    """
    Delete a managed credential from the asset inventory.
    Phase: Utility / Infrastructure
    Related: credentials_list, credentials_create, credentials_get, loot_delete_credential
    """
    from modules.asset_tracker import AssetTracker
    try:
        _run(AssetTracker().delete_credential, cred_id)
        return f"Credential '{cred_id}' deleted."
    except FileNotFoundError as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Case Topology (from nmap scans)
# ---------------------------------------------------------------------------
@mcp.tool()
def case_topology(case_id: str) -> str:
    """
    Parse nmap scan outputs in a case's scans/ directory and return network topology.
    Phase: Case Management
    Related: case_info, case_files_list, nmap_initial_tcp, nmap_full_tcp
    """
    import re
    cm = CaseManager()
    info = _run(cm.info, case_id)
    if not info:
        return "Case not found"
    scans_dir = cm._case_path(case_id) / "scans"
    hosts = []
    seen_targets = set()
    nmap_files = sorted(scans_dir.glob("*.nmap")) if scans_dir.exists() else []
    for f in nmap_files:
        text = f.read_text(errors="ignore")
        target = f.stem.replace("-scan", "")
        ip_match = re.search(r"Nmap scan report for ([\d.]+)", text)
        if ip_match:
            target = ip_match.group(1)
        if target in seen_targets:
            continue
        seen_targets.add(target)
        ports = []
        os_info = []
        for m in re.finditer(r"^(\d+)/(tcp|udp)\s+open\s+(\S*)\s*(.*)$", text, re.MULTILINE):
            ports.append({"port": int(m.group(1)), "protocol": m.group(2),
                          "service": m.group(3), "extra": m.group(4).strip()})
        for m in re.finditer(r"OS details:\s*(.*)", text):
            os_info.append(m.group(1).strip())
        hosts.append({"id": target, "os": os_info[0] if os_info else "unknown",
                      "ports": ports})
    if not hosts:
        return "No scan data found. Run an nmap scan first."
    lines = [f"Topology: {len(hosts)} hosts, {sum(len(h['ports']) for h in hosts)} total ports"]
    for h in hosts:
        port_str = ", ".join(f"{p['port']}/{p['protocol']}({p['service']})" for p in h['ports'][:10])
        if len(h['ports']) > 10:
            port_str += f" ... and {len(h['ports'])-10} more"
        lines.append(f"  {h['id']:<16} OS: {h['os'][:30]} Ports: {port_str}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# WiFi Monitor (read-only: sessions, status, data, interfaces)
# ---------------------------------------------------------------------------
@mcp.tool()
def wifi_monitor_sessions() -> str:
    """
    List all WiFi monitor sessions (past and present).
    Phase: Wireless Pentesting
    Related: wifi_monitor_status, wifi_monitor_data, wifi_scan, wifi_handshake_capture
    """
    from modules.wifi_monitor import get_monitor_manager
    mgr = get_monitor_manager()
    sessions = _run(mgr.list_sessions)
    if not sessions:
        return "No WiFi monitor sessions."
    lines = [f"WiFi Monitor Sessions ({len(sessions)}):"]
    for s in sessions:
        lines.append(f"  {s.get('id',''):<30} iface={s.get('iface',''):<10} status={s.get('status',''):<12} ap={s.get('target_essid','') or s.get('target_bssid','')}")
    return "\n".join(lines)


@mcp.tool()
def wifi_monitor_status(session_id: str = "") -> str:
    """
    Get the status of a WiFi monitor session (or the active session if no ID given).
    Phase: Wireless Pentesting
    Related: wifi_monitor_sessions, wifi_monitor_data, wifi_monitor_interfaces
    """
    from modules.wifi_monitor import get_monitor_manager
    mgr = get_monitor_manager()
    if session_id:
        sess = _run(mgr.get_session, session_id)
        if not sess:
            return "Session not found"
    else:
        sess = _run(mgr.get_active_session)
        if not sess:
            return "No active session"
    info = _run(sess.status_info)
    lines = ["WiFi Monitor Status:"]
    for k, v in info.items():
        if isinstance(v, dict):
            lines.append(f"  {k}: {json.dumps(v)[:100]}")
        else:
            lines.append(f"  {k}: {v}")
    return "\n".join(lines)


@mcp.tool()
def wifi_monitor_data(session_id: str = "") -> str:
    """
    Get captured data from a WiFi monitor session.
    Phase: Wireless Pentesting
    Related: wifi_monitor_sessions, wifi_monitor_status, wifi_scan
    """
    from modules.wifi_monitor import get_monitor_manager
    mgr = get_monitor_manager()
    if session_id:
        sess = _run(mgr.get_session, session_id)
    else:
        sess = _run(mgr.get_active_session)
    if not sess:
        return "No session found"
    data = _run(sess.get_data)
    if not data:
        return "No data captured yet."
    return json.dumps(data, indent=2, default=str)[:2000]


@mcp.tool()
def wifi_monitor_interfaces() -> str:
    """
    List available wireless interfaces.
    Phase: Wireless Pentesting
    Related: wifi_scan, wifi_monitor_sessions, wifi_monitor_status
    """
    import subprocess
    try:
        r = subprocess.run(["iwconfig"], capture_output=True, text=True, timeout=5)
        ifaces = [line.split()[0] for line in r.stdout.splitlines() if "IEEE 802.11" in line]
        if not ifaces:
            r2 = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
            ifaces = [line.split()[-1] for line in r2.stdout.splitlines() if "Interface" in line]
        if ifaces:
            return "Wireless interfaces:\n" + "\n".join(f"  {i}" for i in ifaces)
        return "No wireless interfaces found."
    except Exception:
        return "Could not detect wireless interfaces."


@mcp.tool()
def wifi_monitor_start(iface: str = "wlan0", band: str = "abg",
                       target_bssid: str = "", target_essid: str = "",
                       session_id: str = "") -> str:
    """
    Start a WiFi monitor session for packet capture.
    Phase: Wireless Pentesting
    Related: wifi_monitor_stop, wifi_monitor_sessions, wifi_monitor_status, wifi_monitor_data, wifi_monitor_parse_pcap, wifi_scan
    """
    from modules.wifi_monitor import get_monitor_manager
    import time
    mgr = get_monitor_manager()
    sid = session_id or f"wifi-{int(time.time())}"
    r = _run(mgr.start_session, sid, iface, band, target_bssid, target_essid)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    return f"WiFi monitor session '{sid}' started on {iface}"


@mcp.tool()
def wifi_monitor_stop(session_id: str = "", force: bool = False) -> str:
    """
    Stop a WiFi monitor session.
    Phase: Wireless Pentesting
    Related: wifi_monitor_start, wifi_monitor_sessions, wifi_monitor_status, wifi_monitor_data, wifi_monitor_parse_pcap
    """
    from modules.wifi_monitor import get_monitor_manager
    mgr = get_monitor_manager()
    if session_id:
        sess = _run(mgr.get_session, session_id)
        if not sess:
            return f"Session '{session_id}' not found"
        r = _run(sess.force_kill if force else sess.stop)
    else:
        active = _run(mgr.get_active_session)
        if not active:
            return "No active session to stop"
        r = _run(active.force_kill if force else active.stop)
    if isinstance(r, dict) and r.get("error"):
        return f"Error stopping: {r['error']}"
    return f"WiFi monitor session stopped{' (force)' if force else ''}"


@mcp.tool()
def wifi_monitor_parse_pcap(session_id: str = "") -> str:
    """
    Parse captured PCAP data from a WiFi monitor session now.
    Phase: Wireless Pentesting
    Related: wifi_monitor_start, wifi_monitor_stop, wifi_monitor_sessions, wifi_monitor_status, wifi_monitor_data
    """
    from modules.wifi_monitor import get_monitor_manager
    mgr = get_monitor_manager()
    if session_id:
        sess = _run(mgr.get_session, session_id)
    else:
        sess = _run(mgr.get_active_session)
    if not sess:
        return "No session found"
    r = _run(sess.parse_pcap_now)
    if isinstance(r, dict) and r.get("error"):
        return f"Error parsing pcap: {r['error']}"
    return f"PCAP parsed for session '{session_id or 'active'}': {json.dumps(r, default=str)[:500]}"


@mcp.tool()
def wifi_monitor_cleanup_orphans() -> str:
    """
    Find and clean up leftover monitor-mode interfaces not in use by any active session.
    Phase: Wireless Pentesting
    Related: wifi_monitor_start, wifi_monitor_stop, wifi_monitor_sessions, wifi_monitor_status, wifi_monitor_interfaces
    """
    import subprocess as _sp
    from modules.wifi_monitor import get_monitor_manager
    mgr = get_monitor_manager()
    active = _run(mgr.get_active_session)
    active_in_use = {active.mon_iface, active.iface} if active else set()
    cleaned = []
    try:
        r = _sp.run(["iwconfig"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            if "Mode:Monitor" in line:
                iface = line.split()[0]
                if iface in active_in_use:
                    continue
                _sp.run(["airmon-ng", "stop", iface], capture_output=True, timeout=5)
                cleaned.append(iface)
        if cleaned:
            return f"Cleaned up orphaned monitor interfaces: {', '.join(cleaned)}"
        return "No orphaned monitor interfaces found."
    except Exception as e:
        return f"Error cleaning up: {str(e)}"


# ---------------------------------------------------------------------------
# DNS Monitor
# ---------------------------------------------------------------------------
@mcp.tool()
def dns_resolve(domain: str, types: str = "") -> str:
    """
    Resolve DNS records for a domain.
    Phase: DNS / Network
    Related: dns_monitors, dns_track_domain, dns_history
    """
    from modules.dns_wrapper import resolve as dns_resolve_fn
    type_list = [t.strip() for t in types.split(",") if t.strip()] if types else None
    result = _run(dns_resolve_fn, domain, type_list)
    if not result:
        return "No records found."
    if isinstance(result, dict):
        return json.dumps(result, indent=2)[:2000]
    return str(result)[:2000]


@mcp.tool()
def dns_monitors() -> str:
    """
    List all active DNS monitors.
    Phase: DNS / Network
    Related: dns_resolve, dns_track_domain, dns_history
    """
    from modules.dns_wrapper import list_monitors
    monitors = _run(list_monitors)
    if not monitors:
        return "No active DNS monitors."
    lines = [f"DNS Monitors ({len(monitors)}):"]
    for m in monitors:
        lines.append(f"  {m}")
    return "\n".join(lines)


@mcp.tool()
def dns_monitor_start(domain: str, record_types: str = "",
                      interval: int = 300, duration: int = 0) -> str:
    """
    Start tracking DNS resolutions for a domain over time.
    Phase: DNS / Network
    Related: dns_monitors, dns_track_domain, dns_history, dns_monitor_stop
    """
    from modules.dns_wrapper import start_monitor, start_background_monitor
    _run(start_background_monitor)
    result = _run(start_monitor, domain, record_types if record_types else None,
                   interval, duration)
    return json.dumps(result, default=str)[:1000]


@mcp.tool()
def dns_monitor_stop(domain: str) -> str:
    """
    Stop tracking DNS resolutions for a domain.
    Phase: DNS / Network
    Related: dns_monitors, dns_monitor_start, dns_history, dns_track_domain
    """
    from modules.dns_wrapper import stop_monitor, remove_monitor
    _run(stop_monitor, domain)
    result = _run(remove_monitor, domain)
    return json.dumps(result, default=str)[:500]


@mcp.tool()
def dns_history(domain: str, limit: int = 100) -> str:
    """
    Get historical DNS resolution data for a domain.
    Phase: DNS / Network
    Related: dns_resolve, dns_monitors, dns_track_domain
    """
    from modules.dns_wrapper import get_history
    history = _run(get_history, domain, limit)
    if not history:
        return "No history for this domain."
    lines = [f"DNS History for {domain} ({len(history)} records):"]
    for h in history[:limit]:
        if isinstance(h, dict):
            lines.append(f"  {h.get('timestamp','')[:19]:<22} {h.get('type','?'):<8} {h.get('value','')}")
        else:
            lines.append(f"  {h}")
    return "\n".join(lines)




# ---------------------------------------------------------------------------
# Bug Bounty (HackerOne / Bugcrowd)
# ---------------------------------------------------------------------------
@mcp.tool()
def bb_creds_set(platform: str, identifier: str = "", token: str = "",
                 client_id: str = "", client_secret: str = "",
                 public_only: bool = True) -> str:
    """
    Store encrypted API credentials for a bug bounty platform
    (hackerone/bugcrowd/yeswehack/intigriti; immunefi needs none).
    Phase: Bug Bounty
    Related: bb_creds_list, bb_creds_clear, bb_programs_list
    """
    from modules.bugbounty_clients import BugBountyManager
    result = _run(BugBountyManager().set_credentials, platform, identifier, token,
                  client_id, client_secret, public_only)
    return json.dumps(result, default=str)


@mcp.tool()
def bb_creds_list() -> str:
    """
    List bug bounty platform credential status (no secrets).
    Phase: Bug Bounty
    Related: bb_creds_set, bb_creds_clear
    """
    from modules.bugbounty_clients import BugBountyManager
    result = _run(BugBountyManager().configured_platforms)
    return json.dumps(result, default=str, indent=2)


@mcp.tool()
def bb_creds_clear(platform: str) -> str:
    """
    Remove stored credentials for a bug bounty platform.
    Phase: Bug Bounty
    Related: bb_creds_set, bb_creds_list
    """
    from modules.bugbounty_clients import BugBountyManager
    _run(BugBountyManager().clear_credentials, platform)
    return f"Credentials cleared for '{platform}'."


@mcp.tool()
def bb_programs_list(platform: str = "", search: str = "") -> str:
    """
    List bug bounty programs from the local cache.
    Phase: Bug Bounty
    Related: bb_program_get, bb_sync, bb_sync_program
    """
    from modules.bugbounty_clients import BugBountyManager, format_programs
    mgr = BugBountyManager()
    programs = _run(mgr.list_programs, platform, search)
    return format_programs(programs)


@mcp.tool()
async def bb_program_get(platform: str, slug: str, refresh: bool = False) -> str:
    """
    Get a cached bug bounty program with its scope (refresh to re-fetch).
    Phase: Bug Bounty
    Related: bb_programs_list, bb_sync_program, bb_import_case
    """
    from modules.bugbounty_clients import BugBountyManager, format_program
    mgr = BugBountyManager()
    prog = await _run_async(mgr.get_program, platform, slug, refresh)
    if not prog:
        return f"Program '{platform}:{slug}' not in cache. Run `bb sync_program` first."
    return format_program(prog)


@mcp.tool()
async def bb_discover(platform: str = "hackerone", limit: int = 100) -> str:
    """
    Discover public bug bounty programs from a platform API
    (hackerone/yeswehack/immunefi need no token; intigriti needs its token).
    Phase: Bug Bounty
    Related: bb_sync, bb_programs_list
    """
    from modules.bugbounty_clients import BugBountyManager
    mgr = BugBountyManager()
    found = await _run_async(mgr.discover, platform)
    lines = [f"Discovered {len(found)} programs (cached minimal entries):"]
    for p in found[:limit]:
        lines.append(f"  [{p.get('platform','?'):<9}] {p.get('slug','?'):<28} "
                     f"{p.get('name','')}")
    if len(found) > limit:
        lines.append(f"  ... {len(found) - limit} more (use bb_sync to cache them)")
    return "\n".join(lines)


@mcp.tool()
async def bb_sync_program(platform: str, slug: str) -> str:
    """
    Fetch a specific bug bounty program + scope from the platform and cache it.
    Phase: Bug Bounty
    Related: bb_program_get, bb_sync, bb_import_case
    """
    from modules.bugbounty_clients import BugBountyManager, format_program
    mgr = BugBountyManager()
    prog = await _run_async(mgr.sync_program, platform, slug, True)
    return format_program(prog)


@mcp.tool()
async def bb_sync(platform: str = "", limit: int = 0, refresh: bool = True,
                  max_age_hours: float = 24.0) -> str:
    """
    Refresh cached bug bounty programs (optionally discover new ones).

    Programs synced within max_age_hours are skipped (set max_age_hours=0 to
    force a full refresh of every cached program). Runs off the event loop so
    other MCP requests stay responsive.
    Phase: Bug Bounty
    Related: bb_discover, bb_programs_list
    """
    from modules.bugbounty_clients import BugBountyManager
    mgr = BugBountyManager()
    result = await _run_async(mgr.sync_all, platform, limit, refresh, max_age_hours)
    lines = [f"Synced {len(result.get('synced', []))} programs, "
             f"skipped {result.get('skipped_fresh', 0)} fresh, "
             f"discovered {result.get('new_discovered', 0)} new."]
    for f in result.get("failed", []):
        lines.append(f"  FAILED {f.get('program')}: {f.get('error')}")
    return "\n".join(lines)


@mcp.tool()
def bb_import_case(platform: str, slug: str, case_id: str = "",
                   client: str = "", customer_id: str = "",
                   include_assets: bool = True) -> str:
    """
    Import a bug bounty program as a case with scope + optional asset inventory entries.
    Phase: Bug Bounty
    Related: bb_sync_program, bb_program_get, case_info
    """
    from modules.bugbounty_clients import BugBountyManager
    mgr = BugBountyManager()
    result = _run(mgr.import_case, platform, slug, case_id, client, customer_id,
                  include_assets)
    return json.dumps(result, default=str, indent=2)


@mcp.tool()
def bb_reports_get(platform: str = "hackerone", limit: int = 20,
                   program_slugs: str = "") -> str:
    """
    List reports submitted by the current user (HackerOne or YesWeHack).
    Phase: Bug Bounty
    Related: bb_creds_set, bb_program_get
    """
    from modules.bugbounty_clients import BugBountyManager
    mgr = BugBountyManager()
    slugs = [s.strip() for s in program_slugs.split(",") if s.strip()] or None
    reports = _run(mgr.get_reports, platform, limit, slugs)
    if not reports:
        return "No reports found."
    lines = [f"{platform} reports ({len(reports)}):"]
    for r in reports:
        lines.append(f"  #{r.get('id','?'):<8} [{r.get('state','?')}] "
                     f"{r.get('severity','') or 'n/a':<8} {r.get('title','')} "
                     f"-> {r.get('program','')}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# MCP Resources — read-only data sources discoverable by AI clients
# ---------------------------------------------------------------------------

@mcp.resource("cc://cases/list", title="Case List", description="All cases with status, type, creation date")
def resource_cases_list() -> str:
    """List all pentest/forensic cases."""
    cm = CaseManager()
    cases = cm.list_cases()
    if not cases:
        return "No cases found."
    lines = [f"{'Case ID':<20} {'Client':<20} {'Type':<22} {'Status':<12} Created"]
    lines.append("-" * 100)
    for c in sorted(cases, key=lambda x: x.get("created", ""), reverse=True):
        lines.append(f"{c.get('case_id','?'):<20} {c.get('client','?'):<20} "
                     f"{c.get('type','?'):<22} {c.get('status','?'):<12} "
                     f"{c.get('created','?')[:19]}")
    return "\n".join(lines)


@mcp.resource("cc://cases/{case_id}", title="Case Detail",
             description="Full case info including findings summary, scope count, tasks, and file sizes")
def resource_case_detail(case_id: str) -> str:
    """Get detailed case information including evidence, findings, tasks, and scope."""
    cm = CaseManager()
    info = cm.info(case_id)
    if not info:
        return f"Case '{case_id}' not found."
    import json as _json
    return _json.dumps(info, indent=2, default=str)


@mcp.resource("cc://cases/{case_id}/findings", title="Case Findings",
             description="All structured findings for a case")
def resource_case_findings(case_id: str) -> str:
    """Get all findings for a case."""
    case_dir = _case_dir(case_id)
    if not case_dir.is_dir():
        return f"Case '{case_id}' not found."
    db = FindingsDB(case_dir)
    data = db._read()
    findings = data.get("findings", [])
    if not findings:
        return "No findings for this case."
    import json as _json
    return _json.dumps(findings, indent=2, default=str)


@mcp.resource("cc://cases/{case_id}/notes", title="Case Notes",
             description="All case notes with timestamps and tags")
def resource_case_notes(case_id: str) -> str:
    """Get all notes for a case."""
    cm = CaseManager()
    notes = cm.get_notes(case_id)
    if not notes:
        return "No notes for this case."
    import json as _json
    return _json.dumps(notes, indent=2, default=str)


@mcp.resource("cc://cases/{case_id}/scope", title="Case Scope",
             description="In-scope and out-of-scope targets")
def resource_case_scope(case_id: str) -> str:
    """Get scope (in-scope and out-of-scope targets) for a case."""
    cm = CaseManager()
    info = cm.info(case_id)
    if not info:
        return f"Case '{case_id}' not found."
    scope = info.get("scope", {})
    if not scope:
        return "No scope defined for this case."
    import json as _json
    return _json.dumps(scope, indent=2, default=str)


@mcp.resource("cc://cases/{case_id}/tasks", title="Case Tasks",
             description="Task checklist with completion status and priority")
def resource_case_tasks(case_id: str) -> str:
    """Get all tasks for a case."""
    cm = CaseManager()
    info = cm.info(case_id)
    if not info:
        return f"Case '{case_id}' not found."
    tasks = info.get("tasks", info.get("_tasks", []))
    if not tasks:
        return "No tasks for this case."
    import json as _json
    return _json.dumps(tasks, indent=2, default=str)


@mcp.resource("cc://cases/{case_id}/runbook/log", title="Runbook Execution Log",
             description="Runbook/playbook execution results including step outputs and exit codes")
def resource_case_runbook_log(case_id: str) -> str:
    """Get the runbook execution log for a case."""
    cm = CaseManager()
    log_path = cm._case_path(case_id) / "runbook-log.json"
    if not log_path.exists():
        return "No runbook log found for this case."
    import json as _json
    return _json.dumps(_json.loads(log_path.read_text()), indent=2, default=str)


@mcp.resource("cc://flashcards", title="Flashcard Deck List",
             description="All available flashcard decks with card counts")
def resource_flashcards_list() -> str:
    """List all available flashcard decks with card counts."""
    import yaml
    decks_dir = CC_DIR / "flashcards"
    if not decks_dir.is_dir():
        return "No flashcard decks found."
    decks = []
    for f in sorted(decks_dir.glob("*.yaml")):
        try:
            data = yaml.safe_load(f.read_text()) or {}
            decks.append({"id": f.stem, "title": data.get("title", f.stem),
                          "description": data.get("description", ""),
                          "card_count": len(data.get("cards", []))})
        except Exception:
            pass
    if not decks:
        return "No flashcard decks found."
    import json as _json
    return _json.dumps(decks, indent=2)


@mcp.resource("cc://flashcards/{name}", title="Flashcard Deck Detail",
             description="Full flashcard deck with all questions and answers")
def resource_flashcards_deck(name: str) -> str:
    """Get a specific flashcard deck by name."""
    import re as _re
    if not _re.fullmatch(r"[A-Za-z0-9_-]+", name or ""):
        return f"Invalid deck name: {name!r}"
    import yaml
    decks_dir = (CC_DIR / "flashcards").resolve()
    path = decks_dir / f"{name}.yaml"
    if path.parent != decks_dir or not path.is_file():
        return f"Deck '{name}' not found."
    try:
        data = yaml.safe_load(path.read_text()) or {}
        import json as _json
        return _json.dumps(data, indent=2)
    except Exception as e:
        return f"Error reading deck: {e}"


@mcp.resource("cc://playbooks", title="Playbook List",
             description="All available YAML playbooks/runbooks for automated pentest workflows")
def resource_playbooks_list() -> str:
    """List all available YAML playbooks/runbooks."""
    import yaml
    from modules.playbook_engine import RunbookEngine
    engine = RunbookEngine()
    books = engine.list_runbooks()
    if not books:
        return "No playbooks found."
    results = []
    for b in sorted(books, key=lambda x: x.name):
        try:
            data = yaml.safe_load(b.read_text()) or {}
            results.append({"name": b.name, "description": (data.get("description") or "")[:120],
                            "step_count": len(data.get("steps", []))})
        except Exception:
            results.append({"name": b.name, "description": "", "step_count": 0})
    import json as _json
    return _json.dumps(results, indent=2)


@mcp.resource("cc://prompts", title="Prompt Template List",
             description="All available AI prompt templates for pentest methodology")
def resource_prompts_list() -> str:
    """List all available prompt templates."""
    import yaml
    prompts_dir = CC_DIR / "prompts"
    if not prompts_dir.is_dir():
        return "No prompts found."
    results = []
    for f in sorted(prompts_dir.glob("*.yaml")):
        try:
            data = yaml.safe_load(f.read_text()) or {}
            results.append({"id": f.stem, "title": data.get("title", f.stem),
                            "description": data.get("description", "")[:120]})
        except Exception:
            results.append({"id": f.stem, "title": f.stem, "description": ""})
    if not results:
        return "No prompts found."
    import json as _json
    return _json.dumps(results, indent=2)


@mcp.resource("cc://findings/stats", title="Findings Statistics",
             description="Aggregated findings statistics across all cases")
def resource_findings_stats() -> str:
    """Get aggregated findings statistics across all cases."""
    total = 0
    by_severity = {}
    by_case = {}
    if not CASES_DIR.is_dir():
        return "No cases directory found."
    for case_dir in sorted(CASES_DIR.iterdir()):
        if case_dir.is_dir():
            db = FindingsDB(case_dir)
            data = db._read()
            findings = data.get("findings", [])
            if findings:
                cid = case_dir.name
                by_case[cid] = len(findings)
                total += len(findings)
                for f in findings:
                    s = f.get("severity", "unknown")
                    by_severity[s] = by_severity.get(s, 0) + 1
    import json as _json
    return _json.dumps({
        "total_findings": total,
        "by_severity": by_severity,
        "by_case": by_case,
    }, indent=2)


@mcp.resource("cc://loot/credentials", title="Loot Credentials",
             description="All captured credentials stored in the loot database")
def resource_loot_credentials() -> str:
    """List all credentials in the loot database."""
    from modules.tool_wrappers import LootDB
    import json as _json
    db = LootDB(CC_DIR / "loot.db")
    creds = db.list_credentials()
    if not creds:
        return "No credentials in loot database."
    return _json.dumps(creds, indent=2, default=str)


@mcp.resource("cc://loot/tokens", title="Loot Tokens",
             description="All captured tokens in the loot database")
def resource_loot_tokens() -> str:
    """List all tokens in the loot database."""
    from modules.tool_wrappers import LootDB
    import json as _json
    db = LootDB(CC_DIR / "loot.db")
    try:
        rows = db._conn.execute(
            "SELECT * FROM tokens ORDER BY discovered DESC"
        ).fetchall()
        results = [dict(zip(["id","source","token_type","token_value","target","expires","notes","discovered"], r)) for r in rows]
    finally:
        db.close()
    if not results:
        return "No tokens in loot database."
    return _json.dumps(results, indent=2, default=str)


@mcp.resource("cc://loot/sessions", title="Loot Sessions",
             description="All captured sessions in the loot database")
def resource_loot_sessions() -> str:
    """List all sessions in the loot database."""
    from modules.tool_wrappers import LootDB
    import json as _json
    db = LootDB(CC_DIR / "loot.db")
    try:
        rows = db._conn.execute(
            "SELECT * FROM sessions ORDER BY discovered DESC"
        ).fetchall()
        results = [dict(zip(["id","source","session_id","target","protocol","data","discovered"], r)) for r in rows]
    finally:
        db.close()
    if not results:
        return "No sessions in loot database."
    return _json.dumps(results, indent=2, default=str)


# ---------------------------------------------------------------------------
# AppSec: SBOM / SCA / secrets
# ---------------------------------------------------------------------------
@mcp.tool()
async def sbom_generate(target: str, format: str = "cyclonedx-json",
                        tool: str = "syft", output: str = "") -> str:
    """Generate an SBOM for a directory, image archive, or container image.

    format: cyclonedx-json (default), spdx-json, or syft-json.
    tool: syft (default) or trivy.
    Phase: AppSec
    Related: sca_grype_scan, sca_trivy_scan, secret_scan, appsec_scan
    """
    from modules.appsec import sbom_generate as _impl
    r = await _run_async(_impl, target, format=format, tool=tool, output=output)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    lines = [f"SBOM generated ({r.get('tool')} / {r.get('format')}): {r.get('output_file')}"]
    s = r.get("summary")
    if s:
        lines.append(f"  components: {s.get('components', '?')}")
        by = s.get("by_type", {})
        if by:
            lines.append("  by type: " + ", ".join(f"{k}={v}" for k, v in sorted(by.items())))
    if r.get("stderr"):
        lines.append(f"  stderr: {r['stderr'][:300]}")
    return "\n".join(lines)


@mcp.tool()
async def sca_grype_scan(target: str, output: str = "") -> str:
    """Run a Grype SCA vulnerability scan against a directory or container image.

    Returns severity counts and the top vulnerable packages with fix info.
    Phase: AppSec
    Related: sca_trivy_scan, sbom_generate, secret_scan, appsec_scan
    """
    from modules.appsec import sca_grype_scan as _impl
    r = await _run_async(_impl, target, output=output)
    return _fmt_sca(r)


@mcp.tool()
async def sca_trivy_scan(target: str, output: str = "") -> str:
    """Run a Trivy SCA vulnerability scan against a filesystem directory.

    Returns severity counts and top vulnerable packages with fixed versions.
    Phase: AppSec
    Related: sca_grype_scan, sbom_generate, secret_scan, appsec_scan
    """
    from modules.appsec import sca_trivy_scan as _impl
    r = await _run_async(_impl, target, output=output)
    return _fmt_sca(r)


@mcp.tool()
async def secret_scan(path: str, report_file: str = "") -> str:
    """Scan a directory for secrets/hardcoded credentials with Gitleaks.

    Phase: AppSec
    Related: tool_trufflehog_local, sca_grype_scan, sbom_generate
    """
    from modules.appsec import secret_scan as _impl
    r = await _run_async(_impl, path, report_file=report_file)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    s = r.get("summary", {})
    lines = [f"Gitleaks scan: {s.get('leaks', 0)} leak(s) in {r.get('target')}",
             f"  report: {r.get('report_file')}"]
    by = s.get("by_rule", {})
    if by:
        lines.append("  by rule: " + ", ".join(f"{k}={v}" for k, v in by.items()))
    for it in (s.get("sample") or [])[:15]:
        lines.append(f"  {it.get('file')}:{it.get('line')} [{it.get('rule')}] {it.get('match')}")
    return "\n".join(lines)


@mcp.tool()
async def sast_scan(target: str) -> str:
    """Run a lightweight pattern-based SAST scan over a directory.

    Prefers the real semgrep CLI when installed; otherwise uses a built-in
    python regex rule set (eval/exec, shell=True, pickle, SQL injection,
    hardcoded secrets, XSS sinks, weak crypto).
    Phase: AppSec
    Related: appsec_scan, sca_grype_scan, rules_scan_target
    """
    from modules.appsec import sast_scan as _impl
    r = await _run_async(_impl, target)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    sev = r.get("by_severity") or {}
    lines = [f"SAST ({r.get('engine')}) on {r.get('target')}: {r.get('findings', 0)} finding(s)",
             f"  critical={sev.get('critical', 0)} high={sev.get('high', 0)} "
             f"medium={sev.get('medium', 0)} low={sev.get('low', 0)}"]
    by = r.get("by_rule") or {}
    if by:
        lines.append("  by rule: " + ", ".join(f"{k}={v}" for k, v in sorted(by.items(), key=lambda kv: -kv[1])[:12]))
    for f in (r.get("sample") or [])[:20]:
        lines.append(f"  [{f.get('severity')}] {f.get('file')}:{f.get('line')} {f.get('id')} - {f.get('message')}")
    return "\n".join(lines)


@mcp.tool()
async def osv_scan(target: str, use_live: bool = True) -> str:
    """Check Python package versions against the OSV vulnerability database.

    Discovers pinned deps from requirements*.txt, queries the OSV querybatch
    API (when online), and merges the bundled offline snapshot
    (modules/osv_snapshot.json) so results exist even without network.
    Phase: AppSec
    Related: sca_grype_scan, appsec_scan, sbom_generate
    """
    from modules.appsec import osv_scan as _impl
    r = await _run_async(_impl, target, use_live=use_live)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    sev = r.get("by_severity") or {}
    lines = [f"OSV check ({r.get('source')}) on {r.get('target')}: "
             f"{r.get('checked', 0)} pkg(s), {r.get('vulns', 0)} vuln(s)",
             f"  critical={sev.get('critical', 0)} high={sev.get('high', 0)} "
             f"medium={sev.get('medium', 0)} low={sev.get('low', 0)}"]
    for v in (r.get("top_vulns") or [])[:25]:
        fix = f"  fix: {v.get('fixed')}" if v.get("fixed") else ""
        lines.append(f"  [{v.get('severity','?')}] {v.get('id')} {v.get('pkg')}{fix}")
    return "\n".join(lines)


@mcp.tool()
async def cdn_scan(target: str) -> str:
    """Inventory CDN frontend libraries referenced in templates/HTML.

    Extracts lib@version from jsdelivr/unpkg/cdnjs/quilljs URLs, lists the
    inventory, and flags known-vulnerable versions (advisory map + OSV npm
    snapshot, e.g. quill CVE-2025-15056).
    Phase: AppSec
    Related: appsec_scan, sbom_generate, secret_scan
    """
    from modules.appsec import cdn_scan as _impl
    r = await _run_async(_impl, target)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    lines = [f"CDN lib scan on {r.get('target')}: {r.get('libs', 0)} lib(s), "
             f"{r.get('flagged', 0)} flagged"]
    for lib in (r.get("inventory") or [])[:30]:
        files = ", ".join(lib.get("files", [])[:2])
        lines.append(f"  {lib.get('name')}@{lib.get('version')}  ({files})")
    for a in (r.get("advisories") or [])[:20]:
        lines.append(f"  [!] {a.get('pkg')}@{a.get('version')} [{a.get('severity')}] "
                     f"{a.get('id')} - {a.get('summary')}")
    return "\n".join(lines)


@mcp.tool()
async def sbom_existing(target: str) -> str:
    """Find and summarize pre-built CycloneDX SBOMs under the target.

    Surfaces components + vulnerabilities from existing sbom_*.json files so
    manual/scoped SBOMs are not lost when the dashboard regenerates via syft.
    Phase: AppSec
    Related: sbom_generate, sca_grype_scan, appsec_scan
    """
    from modules.appsec import sbom_existing as _impl
    r = await _run_async(_impl, target)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    lines = [f"Existing SBOMs under {r.get('target')}: {r.get('sboms_found', 0)} found"]
    for s in (r.get("sboms") or []):
        sev = s.get("by_severity") or {}
        lines.append(f"  {s.get('file')} ({s.get('format')} {s.get('spec')})")
        lines.append(f"    components={s.get('components')} vulns={s.get('vulnerabilities')} "
                     f"crit={sev.get('critical', 0)} high={sev.get('high', 0)} "
                     f"med={sev.get('medium', 0)} low={sev.get('low', 0)}")
        ids = s.get("vuln_ids") or []
        if ids:
            lines.append("    ids: " + ", ".join(ids[:15]))
    return "\n".join(lines) or "No pre-built SBOMs found."


@mcp.tool()
async def appsec_scan(target: str, sbom: bool = True, sca: bool = True,
                      secrets: bool = True, sca_tool: str = "grype",
                      sast: bool = True, osv: bool = True,
                      cdn: bool = True, sbom_existing: bool = True) -> str:
    """Run a full AppSec audit on a directory/image: SBOM + SCA + secrets +
    SAST + OSV deps + CDN libs + existing-SBOM ingestion.

    sca_tool: grype (default) or trivy.
    Phase: AppSec
    Related: sbom_generate, sca_grype_scan, sca_trivy_scan, secret_scan,
             sast_scan, osv_scan, cdn_scan, sbom_existing
    """
    from modules.appsec import appsec_scan as _impl
    r = await _run_async(_impl, target, do_sbom=sbom, do_sca=sca,
                         do_secrets=secrets, sca_tool=sca_tool,
                         do_sast=sast, do_osv=osv, do_cdn=cdn,
                         do_sbom_existing=sbom_existing)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    lines = [f"AppSec audit of {r.get('target')}:"]
    for stage, res in (r.get("stages") or {}).items():
        if isinstance(res, dict) and res.get("error"):
            lines.append(f"  [{stage}] Error: {res['error']}")
        elif stage == "sbom":
            s = res.get("summary") or {}
            lines.append(f"  [sbom] {res.get('tool')} -> {res.get('output_file')} ({s.get('components', '?')} components)")
        elif stage == "sca":
            s = res.get("summary") or {}
            sev = s.get("by_severity") or {}
            lines.append(f"  [sca] {res.get('tool')}: {s.get('total', 0)} vulns "
                         f"(crit={sev.get('critical', 0)} high={sev.get('high', 0)} "
                         f"med={sev.get('medium', 0)} low={sev.get('low', 0)})")
        elif stage == "secrets":
            s = res.get("summary") or {}
            lines.append(f"  [secrets] gitleaks: {s.get('leaks', 0)} leak(s) -> {res.get('report_file')}")
        elif stage == "sast":
            sev = res.get("by_severity") or {}
            lines.append(f"  [sast] {res.get('engine')}: {res.get('findings', 0)} findings "
                         f"(high={sev.get('high', 0)} med={sev.get('medium', 0)})")
        elif stage == "osv":
            sev = res.get("by_severity") or {}
            lines.append(f"  [osv] {res.get('checked', 0)} pkg(s), {res.get('vulns', 0)} vulns "
                         f"(high={sev.get('high', 0)} med={sev.get('medium', 0)})")
        elif stage == "cdn":
            lines.append(f"  [cdn] {res.get('libs', 0)} lib(s), {res.get('flagged', 0)} flagged")
        elif stage == "sbom_existing":
            lines.append(f"  [sbom_existing] {res.get('sboms_found', 0)} pre-built SBOM(s)")
    return "\n".join(lines)


def _fmt_sca(r: dict) -> str:
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    s = r.get("summary", {})
    sev = s.get("by_severity") or {}
    lines = [f"{r.get('tool', 'SCA')} scan of {r.get('target')}: {s.get('total', 0)} vuln(s)",
             f"  critical={sev.get('critical', 0)} high={sev.get('high', 0)} "
             f"medium={sev.get('medium', 0)} low={sev.get('low', 0)}"]
    for v in (s.get("top_vulns") or [])[:25]:
        fix = (v.get("fix") or v.get("fixed") or "")
        fix_s = f"  fix: {fix}" if fix else ""
        lines.append(f"  [{v.get('severity','?')}] {v.get('id')} {v.get('pkg')}"
                     f"@{v.get('version') or v.get('installed')}{fix_s}")
    return "\n".join(lines)


def _fmt(r: dict, fmt: str = "default") -> str:
    if r.get("error"):
        return f"Error: {r['error']}"
    if fmt == "nuclei":
        cnt = r.get("finding_count", 0)
        out = r.get("output_file", "")
        return f"Nuclei scan complete: {cnt} findings\nOutput: {out}"
    if fmt == "codeql":
        cnt = r.get("finding_count", 0)
        lang = r.get("language", "?")
        query = r.get("query", "?")
        lines = [f"CodeQL scan ({lang}): {cnt} findings in {query}"]
        sarif = r.get("sarif", {})
        for run in sarif.get("runs", [])[:1]:
            for res in run.get("results", [])[:20]:
                loc = res.get("locations", [{}])[0].get("physicalLocation", {})
                art = loc.get("artifactLocation", {}).get("uri", "?")
                msg = res.get("message", {}).get("text", "")
                lines.append(f"  {art}: {msg[:120]}")
        return "\n".join(lines)
    if fmt == "yara":
        matches = r.get("matches", [])
        total = r.get("total", 0)
        lines = [f"YARA scan: {total} matches"]
        for m in matches[:30]:
            lines.append(f"  Rule: {m['rule']:<30} File: {m['file']}")
        return "\n".join(lines)
    parts = []
    for k in ("stdout", "stderr", "output_file", "output_dir", "results_file", "raw_file"):
        v = r.get(k)
        if v:
            s = str(v)
            parts.append(f"{k}: {s[:500]}")
    if not parts:
        parts.append(str(r)[:500])
    return "\n".join(parts)


def _apply_tool_allowlist(mcp_instance, allowlist: str, denylist: str = "") -> None:
    """Remove MCP tools according to allowlist/denylist prefixes.

    allowlist: comma-separated tool-name prefixes (case-insensitive). An exact
    name matches, and a prefix matches every tool starting with it (e.g. "bb"
    keeps all bug-bounty tools). Empty or "*" keeps all tools.
    denylist: comma-separated prefixes that are force-removed even when the
    allowlist (or a broader group prefix) would keep them. "*" denies all.
    doctor_run is always kept regardless of the lists.
    """
    allowed = [p.strip().lower() for p in (allowlist or "").split(",") if p.strip()]
    denied = [p.strip().lower() for p in (denylist or "").split(",") if p.strip()]
    if not allowed and not denied:
        return
    if "*" in allowed:
        allowed = []
    manager = mcp_instance._tool_manager
    for tool in manager.list_tools():
        name = tool.name.lower()
        if name == "doctor_run":
            # Capability/health check is always exposed (documented behavior).
            continue
        if denied and (any(name == d or name.startswith(d) for d in denied)
                       or "*" in denied):
            manager.remove_tool(tool.name)
        elif allowed and not any(name == a or name.startswith(a) for a in allowed):
            manager.remove_tool(tool.name)


def _log(msg: str) -> None:
    """Write to stderr (safe for stdio MCP transports)."""
    sys.stderr.write(f"[cc-toolkit] {msg}\n")


# ---------------------------------------------------------------------------
# EDR (Endpoint Detection & Response)
# ---------------------------------------------------------------------------
try:
    from edr.mcp import register_edr_tools as _register_edr_tools
    _register_edr_tools(mcp)
    _log("EDR tools registered")
except Exception as _edr_err:
    _log(f"EDR tools not loaded: {_edr_err}")


def main():
    manager = mcp._tool_manager
    try:
        from modules.feature_groups import save_tool_index
        save_tool_index([t.name for t in manager.list_tools()])
    except Exception as exc:  # index write must never block startup
        _log(f"could not write tool index: {exc}")

    total = len(manager.list_tools())
    env_allowlist = os.environ.get("CC_MCP_TOOLS", "").strip()
    allowlist = ""
    denylist = ""
    config_ok = False
    try:
from modules.config import load_config
        from modules.feature_groups import build_allowlist, build_denylist
        feats = load_config().get("features") or {}
        config_allowlist = build_allowlist(feats)
        config_denylist = build_denylist(feats)
        config_ok = True
    except Exception as exc:
        _log(f"could not load feature config: {exc}")

    if env_allowlist:
        # Env CC_MCP_TOOLS overrides the config allowlist, but the config
        # denylist still applies as a safety net (previously it was dropped).
        allowlist = env_allowlist
        denylist = config_denylist if config_ok else "*"
    elif config_ok:
        allowlist = config_allowlist
        denylist = config_denylist
    else:
        # Fail closed: a config read error must NOT widen the exposed surface.
        # Previously this exposed all tools; now nothing is exposed.
        allowlist = ""
        denylist = "*"
    _apply_tool_allowlist(mcp, allowlist, denylist)
    exposed = len(manager.list_tools())
    src = "env CC_MCP_TOOLS" if env_allowlist else "config.json features"
    _log(f"MCP ready: {exposed}/{total} tools exposed (source: {src}; allowlist: {allowlist or 'all'}; denylist: {denylist or 'none'})")
    mcp.run()


if __name__ == "__main__":
    main()
