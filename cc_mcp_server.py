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
"""

import atexit
import concurrent.futures
import datetime
import json
import os
import subprocess
import sys
import threading
import uuid
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from mcp.server.fastmcp import FastMCP
from modules.config import TOOLS_DIR, SCRIPTS_DIR, CASES_DIR

mcp = FastMCP("CC Toolkit")

_TIMEOUT = int(os.environ.get("CC_MCP_TIMEOUT", "300"))
_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=4)
_TOOLS_DIR = os.environ.get("CC_TOOLS_DIR", str(TOOLS_DIR))
atexit.register(lambda: _POOL.shutdown(wait=False))


def _run(fn, *args, **kwargs):
    """Run a function with the configured timeout. Raises TimeoutError if exceeded."""
    fut = _POOL.submit(fn, *args, **kwargs)
    try:
        return fut.result(timeout=_TIMEOUT)
    except concurrent.futures.TimeoutError:
        return f"Error: Timed out after {_TIMEOUT}s (increase CC_MCP_TIMEOUT env var)"


# ---------------------------------------------------------------------------
# AD Security
# ---------------------------------------------------------------------------
@mcp.tool()
def ad_certipy_find(domain: str, target: str, username: str = "",
                    password: str = "", ca: str = "") -> str:
    """
    Enumerate AD Certificate Services misconfigurations (ESC1-ESC8) on a domain controller.
    Phase: Active Directory Security
    Parameters:
      domain: Target domain (e.g., "example.local") (str)
      target: Target hostname, IP, or URL (str)
      username: Username for authentication (str) [default: '']
      password: Password for authentication (str) [default: '']
      ca: Certificate Authority server name (str) [default: '']
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
    Parameters:
      domain: Target domain (e.g., "example.local") (str)
      target: Target hostname, IP, or URL (str)
      template: Template name or path (str)
      username: Username for authentication (str) [default: '']
      password: Password for authentication (str) [default: '']
      upn: User Principal Name for certificate (str) [default: '']
      dns: DNS name for certificate (str) [default: '']
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
    Parameters:
      server: Target server address (IP or hostname) (str)
      action: Action to perform (str)
      username: Username for authentication (str) [default: '']
      password: Password for authentication (str) [default: '']
      domain: Target domain (e.g., "example.local") (str) [default: '']
      target_dn: Target Distinguished Name (str) [default: '']
      ldap_filter: LDAP search filter (str) [default: '']
      attribute: LDAP attribute to modify (str) [default: '']
      value: Value to set (str) [default: '']
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
    Parameters:
      server: Target server address (IP or hostname) (str)
      username: Username for authentication (str) [default: '']
      password: Password for authentication (str) [default: '']
      domain: Target domain (e.g., "example.local") (str) [default: '']
      object_class: AD object class (user, computer, group) (str) [default: 'user']
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
    Parameters:
      domain: Target domain (e.g., "example.local") (str)
      wordlist: Path to wordlist file (str)
      dc_ip: Domain controller IP address (str) [default: '']
    Related: ad_certipy_find, ad_certipy_request, ad_bloodyad_exec, ad_bloodyad_dump, ad_ldapnomnom_enum, ad_netexec_pre2k, ad_kerbrute_bruteforce
    """
    from modules.tool_wrappers import kerbrute_userenum
    return _fmt(_run(kerbrute_userenum, domain, wordlist, dc_ip=dc_ip))


@mcp.tool()
def ad_ldapnomnom_enum(target: str, base_dn: str = "") -> str:
    """
    Perform anonymous LDAP enumeration against a domain controller.
    Phase: Active Directory Security
    Parameters:
      target: Target hostname, IP, or URL (str)
      base_dn: LDAP base DN (str) [default: '']
    Related: ad_certipy_find, ad_certipy_request, ad_bloodyad_exec, ad_bloodyad_dump, ad_kerbrute_userenum, ad_netexec_pre2k, ad_kerbrute_bruteforce
    """
    from modules.tool_wrappers import ldapnomnom_enum
    return _fmt(_run(ldapnomnom_enum, target, base_dn=base_dn))


@mcp.tool()
def ad_netexec_pre2k(domain: str, dc_ip: str, wordlist: str) -> str:
    """
    Check for pre-created computer accounts via NetExec (pre2k attack).
    Phase: Active Directory Security
    Parameters:
      domain: Target domain (e.g., "example.local") (str)
      dc_ip: Domain controller IP address (str)
      wordlist: Path to wordlist file (str)
    Related: ad_certipy_find, ad_certipy_request, ad_bloodyad_exec, ad_bloodyad_dump, ad_kerbrute_userenum, ad_ldapnomnom_enum, ad_kerbrute_bruteforce
    """
    from modules.tool_wrappers import netexec_pre2k
    return _fmt(_run(netexec_pre2k, domain, dc_ip, wordlist))


@mcp.tool()
def ad_kerbrute_bruteforce(domain: str, user: str, wordlist: str) -> str:
    """
    Brute-force password for a single AD user via Kerberos.
    Phase: Active Directory Security
    Parameters:
      domain: Target domain (e.g., "example.local") (str)
      user: Target username (str)
      wordlist: Path to wordlist file (str)
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
    Parameters:
      token: JWT token string (str)
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
    Parameters:
      token: JWT token string (str)
      attack: Attack type (str) [default: 'none']
      payload_field: JWT payload field name (str) [default: '']
      payload_value: JWT payload value to inject (str) [default: '']
      signing_key: Custom signing key for JWT forgery (str) [default: '']
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
    Parameters:
      target: Target hostname, IP, or URL (str)
    Related: web_jwt_scan, web_jwt_attack, web_nuclei_scan
    """
    from modules.tool_wrappers import graphw00f_scan
    return _fmt(_run(graphw00f_scan, target))


@mcp.tool()
def web_nuclei_scan(target: str, template: str = "") -> str:
    """
    Run Nuclei vulnerability scanner against a target with optional template filter.
    Phase: Web Application Testing
    Parameters:
      target: Target hostname, IP, or URL (str)
      template: Template name or path (str) [default: '']
    Related: web_jwt_scan, web_jwt_attack, web_graphw00f_scan
    """
    from modules.tool_wrappers import nuclei_scan
    return _fmt(_run(nuclei_scan, target, template=template), fmt="nuclei")


# ---------------------------------------------------------------------------
# WiFi / Wireless
# ---------------------------------------------------------------------------
@mcp.tool()
def wifi_eaphammer_attack(bssid: str, essid: str, iface: str,
                          auth_type: str = "WPA2-EAP",
                          pmkid: bool = False,
                          captive: bool = False) -> str:
    """
    Execute EAPHammer enterprise WiFi attack (PMKID capture, captive portal, downgrade).
    Phase: Wireless Pentesting
    Parameters:
      bssid: Target BSSID/MAC address (str)
      essid: Target network name (ESSID) (str)
      iface: Network interface for monitor mode (str)
      auth_type: Authentication type (WPA2-EAP, WPA-EAP, EAP-TLS) (str) [default: 'WPA2-EAP']
      pmkid: Capture PMKID during attack (bool) [default: False]
      captive: Start captive portal (bool) [default: False]
    Related: wifi_scan, wifi_deauth, wifi_handshake_capture, wifi_connect, wifi_network_scan, wifi_arp_spoof, wifi_proxy, wifi_rogue_ap, wifi_sycophant_relay, wifi_mitmproxy, wifi_evil_twin, wifi_auto_attack
    """
    from modules.tool_wrappers import eaphammer_attack
    return _fmt(_run(eaphammer_attack, bssid, essid, iface, auth_type=auth_type,
                     pmkid=pmkid, captive=captive))


@mcp.tool()
def wifi_scan(iface: str = "wlan0", timeout: int = 45) -> str:
    """
    Scan for nearby WiFi networks. Returns list of APs with BSSID, channel, signal, encryption, ESSID.
    Phase: Wireless Pentesting
    Parameters:
      iface: Network interface for monitor mode (str) [default: 'wlan0']
      timeout: Operation timeout in seconds (int) [default: 45]
    Related: wifi_eaphammer_attack, wifi_deauth, wifi_handshake_capture, wifi_connect, wifi_network_scan, wifi_arp_spoof, wifi_proxy, wifi_rogue_ap, wifi_sycophant_relay, wifi_mitmproxy, wifi_evil_twin, wifi_auto_attack
    """
    from modules.wifi_wrapper import wifi_scan as _scan
    result = _run(_scan, iface=iface, timeout=timeout)
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
def wifi_deauth(bssid: str, iface: str = "wlan0",
                station: str = "", count: int = 5) -> str:
    """
    Send deauthentication frames to a BSSID (optionally target a specific station).
    Phase: Wireless Pentesting
    Parameters:
      bssid: Target BSSID/MAC address (str)
      iface: Network interface for monitor mode (str) [default: 'wlan0']
      station: Client station MAC (str) [default: '']
      count: Number of deauth packets (int) [default: 5]
    Related: wifi_eaphammer_attack, wifi_scan, wifi_handshake_capture, wifi_connect, wifi_network_scan, wifi_arp_spoof, wifi_proxy, wifi_rogue_ap, wifi_sycophant_relay, wifi_mitmproxy, wifi_evil_twin, wifi_auto_attack
    """
    from modules.wifi_wrapper import wifi_deauth as _deauth
    result = _run(_deauth, bssid, iface=iface, station=station, count=count)
    if result.get("error"):
        return f"Error: {result['error']}"
    return result.get("status", "Deauth sent")


@mcp.tool()
def wifi_handshake_capture(bssid: str, channel: str, iface: str = "wlan0",
                           essid: str = "", timeout: int = 60) -> str:
    """
    Capture WPA 4-way handshake. Returns path to capture file if successful.
    Phase: Wireless Pentesting
    Parameters:
      bssid: Target BSSID/MAC address (str)
      channel: Wireless channel number (str)
      iface: Network interface for monitor mode (str) [default: 'wlan0']
      essid: Target network name (ESSID) (str) [default: '']
      timeout: Operation timeout in seconds (int) [default: 60]
    Related: wifi_eaphammer_attack, wifi_scan, wifi_deauth, wifi_connect, wifi_network_scan, wifi_arp_spoof, wifi_proxy, wifi_rogue_ap, wifi_sycophant_relay, wifi_mitmproxy, wifi_evil_twin, wifi_auto_attack
    """
    from modules.wifi_wrapper import wifi_handshake_capture as _hs
    result = _run(_hs, bssid, channel, iface=iface, essid=essid, timeout=timeout)
    if result.get("error"):
        return f"Error: {result['error']}"
    if result.get("capture"):
        return f"Handshake captured: {result['capture']} ({result.get('size', 0)} bytes)"
    return result.get("status", "No handshake captured")


@mcp.tool()
def wifi_connect(ssid: str, password: str = "", iface: str = "wlan0") -> str:
    """
    Connect to a WiFi network. For open networks omit password.
    Phase: Wireless Pentesting
    Parameters:
      ssid: Ssid (str)
      password: Password for authentication (str) [default: '']
      iface: Network interface for monitor mode (str) [default: 'wlan0']
    Related: wifi_eaphammer_attack, wifi_scan, wifi_deauth, wifi_handshake_capture, wifi_network_scan, wifi_arp_spoof, wifi_proxy, wifi_rogue_ap, wifi_sycophant_relay, wifi_mitmproxy, wifi_evil_twin, wifi_auto_attack
    """
    from modules.wifi_wrapper import wifi_connect as _conn
    result = _run(_conn, ssid, password=password, iface=iface)
    if result.get("error"):
        return f"Error: {result['error']}"
    return result.get("status", f"Connected to {ssid}")


@mcp.tool()
def wifi_network_scan(iface: str = "wlan0", subnet: str = "") -> str:
    """
    Scan the local network for hosts (ARP scan / ping sweep) after connecting.
    Phase: Wireless Pentesting
    Parameters:
      iface: Network interface for monitor mode (str) [default: 'wlan0']
      subnet: Subnet (str) [default: '']
    Related: wifi_eaphammer_attack, wifi_scan, wifi_deauth, wifi_handshake_capture, wifi_connect, wifi_arp_spoof, wifi_proxy, wifi_rogue_ap, wifi_sycophant_relay, wifi_mitmproxy, wifi_evil_twin, wifi_auto_attack
    """
    from modules.wifi_wrapper import wifi_network_scan as _netscan
    result = _run(_netscan, iface=iface, subnet=subnet)
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
def wifi_arp_spoof(target: str, gateway: str = "", iface: str = "wlan0") -> str:
    """
    Start ARP spoofing between target and gateway to intercept traffic.
    Phase: Wireless Pentesting
    Parameters:
      target: Target hostname, IP, or URL (str)
      gateway: Gateway (str) [default: '']
      iface: Network interface for monitor mode (str) [default: 'wlan0']
    Related: wifi_eaphammer_attack, wifi_scan, wifi_deauth, wifi_handshake_capture, wifi_connect, wifi_network_scan, wifi_proxy, wifi_rogue_ap, wifi_sycophant_relay, wifi_mitmproxy, wifi_evil_twin, wifi_auto_attack
    """
    from modules.wifi_wrapper import wifi_arp_spoof as _arp
    result = _run(_arp, target, gateway=gateway, iface=iface)
    if result.get("error"):
        return f"Error: {result['error']}"
    return result.get("status", "ARP spoofing started")


@mcp.tool()
def wifi_proxy(port: int = 8080, iface: str = "wlan0",
               sslstrip: bool = True) -> str:
    """
    Start BetterCAP transparent HTTP proxy with optional SSL stripping.
    Phase: Wireless Pentesting
    Parameters:
      port: Port number (int) [default: 8080]
      iface: Network interface for monitor mode (str) [default: 'wlan0']
      sslstrip: Sslstrip (bool) [default: True]
    Related: wifi_eaphammer_attack, wifi_scan, wifi_deauth, wifi_handshake_capture, wifi_connect, wifi_network_scan, wifi_arp_spoof, wifi_rogue_ap, wifi_sycophant_relay, wifi_mitmproxy, wifi_evil_twin, wifi_auto_attack
    """
    from modules.wifi_wrapper import wifi_proxy as _proxy
    result = _run(_proxy, port=port, iface=iface, sslstrip=sslstrip)
    if result.get("error"):
        return f"Error: {result['error']}"
    return result.get("status", f"Proxy started on :{port}")


@mcp.tool()
def wifi_rogue_ap(essid: str, iface: str = "wlan0", channel: str = "6",
                  bssid: str = "") -> str:
    """
    Create a rogue access point with the given ESSID using airbase-ng (or hostapd).
    Phase: Wireless Pentesting
    Parameters:
      essid: Target network name (ESSID) (str)
      iface: Network interface for monitor mode (str) [default: 'wlan0']
      channel: Wireless channel number (str) [default: '6']
      bssid: Target BSSID/MAC address (str) [default: '']
    Related: wifi_eaphammer_attack, wifi_scan, wifi_deauth, wifi_handshake_capture, wifi_connect, wifi_network_scan, wifi_arp_spoof, wifi_proxy, wifi_sycophant_relay, wifi_mitmproxy, wifi_evil_twin, wifi_auto_attack
    """
    from modules.wifi_wrapper import airbase_rogue_ap
    result = _run(airbase_rogue_ap, essid, iface=iface, channel=channel, bssid=bssid)
    if result.get("error"):
        return f"Error: {result['error']}"
    return result.get("status", f"Rogue AP '{essid}' started")


@mcp.tool()
def wifi_sycophant_relay(iface: str = "wlan0", target_bssid: str = "",
                         target_essid: str = "") -> str:
    """
    Relay WPA 4-way handshake using wpa_sycophant (MITM without password cracking).
    Phase: Wireless Pentesting
    Parameters:
      iface: Network interface for monitor mode (str) [default: 'wlan0']
      target_bssid: Target Bssid (str) [default: '']
      target_essid: Target Essid (str) [default: '']
    Related: wifi_eaphammer_attack, wifi_scan, wifi_deauth, wifi_handshake_capture, wifi_connect, wifi_network_scan, wifi_arp_spoof, wifi_proxy, wifi_rogue_ap, wifi_mitmproxy, wifi_evil_twin, wifi_auto_attack
    """
    from modules.wifi_wrapper import wpa_sycophant_relay
    result = _run(wpa_sycophant_relay, iface=iface, target_bssid=target_bssid,
                  target_essid=target_essid)
    if result.get("error"):
        return f"Error: {result['error']}"
    return result.get("status", "wpa_sycophant relay started")


@mcp.tool()
def wifi_mitmproxy(port: int = 8080, listen_addr: str = "0.0.0.0",
                   mode: str = "transparent") -> str:
    """
    Start mitmproxy in transparent or regular mode for traffic interception.
    Phase: Wireless Pentesting
    Parameters:
      port: Port number (int) [default: 8080]
      listen_addr: Listen Addr (str) [default: '0.0.0.0']
      mode: Mode (str) [default: 'transparent']
    Related: wifi_eaphammer_attack, wifi_scan, wifi_deauth, wifi_handshake_capture, wifi_connect, wifi_network_scan, wifi_arp_spoof, wifi_proxy, wifi_rogue_ap, wifi_sycophant_relay, wifi_evil_twin, wifi_auto_attack
    """
    from modules.wifi_wrapper import mitmproxy_intercept
    result = _run(mitmproxy_intercept, port=port, listen_addr=listen_addr, mode=mode)
    if result.get("error"):
        return f"Error: {result['error']}"
    return result.get("status", f"mitmproxy started on :{port}")


@mcp.tool()
def wifi_evil_twin(essid: str, iface: str = "wlan0", channel: str = "6",
                   bssid: str = "", portal_dir: str = "",
                   proxy_port: int = 8080) -> str:
    """Full evil twin: rogue AP + captive portal on :80 + transparent proxy.

    Victims connect to the rogue AP, get a captive portal login page,
    entered credentials are logged, and all HTTP traffic is proxied.
    Phase: Wireless Pentesting
    Parameters:
      essid: Target network name (ESSID) (str)
      iface: Network interface for monitor mode (str) [default: 'wlan0']
      channel: Wireless channel number (str) [default: '6']
      bssid: Target BSSID/MAC address (str) [default: '']
      portal_dir: Portal Dir (str) [default: '']
      proxy_port: Proxy port for agent (int) [default: 8080]
    Related: wifi_eaphammer_attack, wifi_scan, wifi_deauth, wifi_handshake_capture, wifi_connect, wifi_network_scan, wifi_arp_spoof, wifi_proxy, wifi_rogue_ap, wifi_sycophant_relay, wifi_mitmproxy, wifi_auto_attack
    """
    from modules.wifi_wrapper import evil_twin_full
    result = _run(evil_twin_full, essid, iface=iface, channel=channel, bssid=bssid,
                  portal_dir=portal_dir, proxy_port=proxy_port)
    if result.get("error"):
        return f"Error: {result['error']}"
    return result.get("status", f"Evil twin '{essid}' running")


@mcp.tool()
def wifi_auto_attack(iface: str = "wlan0", target_bssid: str = "",
                     target_essid: str = "", channel: str = "") -> str:
    """
    Automatically try multiple attack vectors: handshake capture, deauth, evil twin, relay.
    Phase: Wireless Pentesting
    Parameters:
      iface: Network interface for monitor mode (str) [default: 'wlan0']
      target_bssid: Target Bssid (str) [default: '']
      target_essid: Target Essid (str) [default: '']
      channel: Wireless channel number (str) [default: '']
    Related: wifi_eaphammer_attack, wifi_scan, wifi_deauth, wifi_handshake_capture, wifi_connect, wifi_network_scan, wifi_arp_spoof, wifi_proxy, wifi_rogue_ap, wifi_sycophant_relay, wifi_mitmproxy, wifi_evil_twin
    """
    from modules.wifi_wrapper import wifi_auto_attack
    result = _run(wifi_auto_attack, iface=iface, target_bssid=target_bssid,
                  target_essid=target_essid, channel=channel)
    attacks = result.get("attacks", {})
    lines = [f"Auto-attack against {result.get('target', '?')}:"]
    for name, res in attacks.items():
        status = res.get("status", res.get("capture", res.get("error", "done")))
        lines.append(f"  {name}: {status[:80]}")
    return "\n".join(lines)


@mcp.tool()
def wifi_wireless_graph(pcap: str = "", iface: str = "") -> str:
    """
    Parse wireless PCAP or live capture and generate an HTML signal graph.
    Phase: Wireless Pentesting
    Parameters:
      pcap: Path to PCAP file (str) [default: '']
      iface: Network interface for monitor mode (str) [default: '']
    Related: wifi_eaphammer_attack, wifi_scan, wifi_deauth, wifi_handshake_capture, wifi_connect, wifi_network_scan, wifi_arp_spoof, wifi_proxy, wifi_rogue_ap, wifi_sycophant_relay, wifi_mitmproxy, wifi_evil_twin
    """
    from modules.tool_wrappers import wireless_graph
    return _fmt(_run(wireless_graph, pcap=pcap, iface=iface))


@mcp.tool()
def forensics_yara_scan(rule_path: str, target: str) -> str:
    """
    Scan files with YARA rules (rule file/dir vs target file/dir).
    Phase: Digital Forensics
    Parameters:
      rule_path: Path to YARA rule file or directory (str)
      target: Target hostname, IP, or URL (str)
    Related: forensics_kape_collect, forensics_semgrep_scan
    """
    from modules.tool_wrappers import yara_scan
    return _fmt(_run(yara_scan, rule_path, target), fmt="yara")


@mcp.tool()
def forensics_kape_collect(target: str, targets: str = "!BasicCollection",
                           module: str = "", binary_path: str = "kape") -> str:
    """
    Run KAPE Windows forensic artifact collection against a target drive or image.
    Phase: Digital Forensics
    Parameters:
      target: Target hostname, IP, or URL (str)
      targets: Comma-separated target list (str) [default: '!BasicCollection']
      module: Metasploit module path (str) [default: '']
      binary_path: Path to the binary file (str) [default: 'kape']
    Related: forensics_yara_scan, forensics_semgrep_scan
    """
    from modules.tool_wrappers import kape_collect
    return _fmt(_run(kape_collect, target, targets=targets, module=module, binary_path=binary_path))


@mcp.tool()
def forensics_semgrep_scan(config: str, target: str) -> str:
    """
    Run Semgrep SAST scanner against source code.
    Phase: Digital Forensics
    Parameters:
      config: Config (str)
      target: Target hostname, IP, or URL (str)
    Related: forensics_yara_scan, forensics_kape_collect
    """
    from modules.tool_wrappers import semgrep_scan
    return _fmt(_run(semgrep_scan, config, target))


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
    Parameters:
      to: To (str)
      server: Target server address (IP or hostname) (str)
      from_addr: Sender email address (str) [default: '']
      subject: Email subject (str) [default: 'Test']
      body: Email body text (str) [default: '']
      port: Port number (int) [default: 25]
      tls: Use TLS for SMTP (bool) [default: False]
      auth_user: SMTP auth username (str) [default: '']
      auth_pass: SMTP auth password (str) [default: '']
      attach: Attachment file path (str) [default: '']
      header: Custom email header (str) [default: '']
    Related: util_wsgidav_serve, util_mitm_start, util_route_scan, util_sigma_convert
    """
    from modules.tool_wrappers import swaks_send
    return _fmt(_run(swaks_send, to, server, from_addr=from_addr, subject=subject,
                     body=body, port=port, tls=tls, auth_user=auth_user,
                     auth_pass=auth_pass, attach=attach, header=header))


@mcp.tool()
def util_wsgidav_serve(directory: str, host: str = "0.0.0.0",
                       port: int = 8080, auth: bool = False,
                       username: str = "", password: str = "") -> str:
    """
    Start a WebDAV server for file sharing (background process).
    Phase: Utility / Infrastructure
    Parameters:
      directory: Directory to serve (str)
      host: Hostname or IP (str) [default: '0.0.0.0']
      port: Port number (int) [default: 8080]
      auth: Enable authentication (bool) [default: False]
      username: Username for authentication (str) [default: '']
      password: Password for authentication (str) [default: '']
    Related: util_swaks_send, util_mitm_start, util_route_scan, util_sigma_convert
    """
    from modules.tool_wrappers import wsgidav_serve
    fn = lambda: wsgidav_serve(directory, host=host, port=port,
                                auth=auth, username=username, password=password)
    proc = _run(fn)
    return f"WebDAV server started on http://{host}:{port} serving {directory} (PID: {proc.pid})"


@mcp.tool()
def util_mitm_start(port: int = 8080, upstream: str = "") -> str:
    """
    Start a MITM proxy server for traffic interception.
    Phase: Utility / Infrastructure
    Parameters:
      port: Port number (int) [default: 8080]
      upstream: Upstream proxy URL (str) [default: '']
    Related: util_swaks_send, util_wsgidav_serve, util_route_scan, util_sigma_convert
    """
    from modules.tool_wrappers import mitm_start
    r = _run(mitm_start, port=port, upstream=upstream)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    return f"MITM proxy started on port {port}" + (f" (upstream: {upstream})" if upstream else "")


@mcp.tool()
def util_route_scan(target_range: str = "172.16.0.0/12",
                    max_workers: int = 10, arp_only: bool = False) -> str:
    """
    Trace routes to IPs in a range and report suspicious private IPs in transit.
    Phase: Utility / Infrastructure
    Parameters:
      target_range: IP range in CIDR notation (str) [default: '172.16.0.0/12']
      max_workers: Maximum parallel workers (int) [default: 10]
      arp_only: Only send ARP pings (bool) [default: False]
    Related: util_swaks_send, util_wsgidav_serve, util_mitm_start, util_sigma_convert
    """
    from modules.tool_wrappers import route_scan
    r = _run(route_scan, target_range=target_range,
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
    Parameters:
      input_file: Input File (str)
      target_format: Target Format (str) [default: 'siem']
      output: Output (str) [default: '']
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
    Parameters:
      keyword: Search keyword (str) [default: '']
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
    Parameters:
      keyword: Search keyword (str) [default: '']
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
    Parameters:
      keyword: Search keyword (str) [default: '']
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

def _pb_run_background(name: str, target: str, case_id: str, job_id: str):
    """Run a playbook in background and store results."""
    from modules.playbook_engine import RunbookEngine
    from modules.case_manager import CaseManager
    try:
        engine = RunbookEngine()
        cm = CaseManager()
        with _PB_LOCK:
            _playbook_jobs[job_id] = {"status": "running", "progress": 0}
        results = engine.run_file(
            name, targets=[target] if target else [],
            case_id=case_id, verbose=False,
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
        except Exception:
            pass
        with _PB_LOCK:
            _playbook_jobs[job_id] = {
                "status": "completed",
                "progress": 100,
                "step_count": len(results) if results else 0,
                "case_id": case_id,
            }
    except Exception as e:
        with _PB_LOCK:
            _playbook_jobs[job_id] = {
                "status": "failed",
                "error": str(e),
                "case_id": case_id,
            }


@mcp.tool()
def playbook_list() -> str:
    """List all available YAML playbooks/runbooks for automated pentest workflows."""
    from modules.playbook_engine import RunbookEngine
    engine = RunbookEngine()
    books = engine.list_runbooks()
    if not books:
        return "No playbooks found."
    lines = [f"{'Name':<30} Description"]
    lines.append("-" * 80)
    for b in sorted(books, key=lambda x: x.name):
        desc = (b.description or "")[:60]
        lines.append(f"{b.name:<30} {desc}")
    return "\n".join(lines)


@mcp.tool()
def playbook_launch(name: str, target: str = "", case_id: str = "") -> str:
    """Launch a playbook asynchronously. Returns a job_id for status polling.
    Phase: Runbook Orchestration
    Parameters:
      name: Name (str)
      target: Target hostname, IP, or URL (str) [default: '']
      case_id: Case ID to scope results (str) [default: '']
    Related: playbook_list, playbook_status, playbook_log
    Use playbook_status(job_id) to check progress, playbook_log(case_id) to get results."""
    job_id = uuid.uuid4().hex[:8]
    resolved_case_id = case_id or f"mcp-{name.replace('.yaml','')}-{datetime.datetime.now(datetime.timezone.utc):%Y%m%d_%H%M%S}"

    # Create case upfront
    from modules.case_manager import CaseManager
    try:
        cm = CaseManager()
        cm.create(resolved_case_id,
                  description=f"MCP-runbook: {name} against {target or '(no target)'}",
                  targets=[target] if target else [])
    except Exception:
        pass  # case already exists

    with _PB_LOCK:
        _playbook_jobs[job_id] = {"status": "queued", "progress": 0, "case_id": resolved_case_id}
    t = threading.Thread(target=_pb_run_background,
                         args=(name, target, resolved_case_id, job_id), daemon=True)
    t.start()
    return f"Launched playbook '{name}' as job {job_id} in case {resolved_case_id}"


@mcp.tool()
def playbook_status(job_id: str) -> str:
    """
    Check the status of an async playbook launch. Returns JSON with status, progress, and result.
    Phase: Runbook Orchestration
    Parameters:
      job_id: Job Id (str)
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
    Parameters:
      case_id: Case ID to scope results (str)
    Related: playbook_list, playbook_launch, playbook_status
    """
    from modules.case_manager import CaseManager
    from pathlib import Path
    cm = CaseManager()
    log_path = cm._case_path(case_id) / "runbook-log.json"
    if not log_path.exists():
        return f"Error: no runbook log found for case '{case_id}'"
    try:
        return log_path.read_text()
    except Exception as e:
        return f"Error reading log: {e}"


# ---------------------------------------------------------------------------
# Rules — Semgrep / Sigma / YARA / Suricata / Nuclei
# ---------------------------------------------------------------------------

@mcp.tool()
def rules_list(rule_format: str = "", severity: str = "",
               search: str = "", category: str = "") -> str:
    """
    List security rules across all formats (semgrep, sigma, yara, suricata, nuclei). Optionally filter by format, severity (comma-separated), text search, or category/family.
    Phase: Rule Management
    Parameters:
      rule_format: Rule format (semgrep, sigma, yara, suricata, nuclei) (str) [default: '']
      severity: Filter by severity (str) [default: '']
      search: Text search in rule metadata (str) [default: '']
      category: Rule category filter (str) [default: '']
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
        path = r.get("relpath", r.get("filepath", ""))
        lines.append(f"  [{sev:<7}] {rid:<30} {title}")
    return "\n".join(lines)


@mcp.tool()
def rules_get(rule_format: str, rule_id: str) -> str:
    """
    Get full details for a single rule by format (semgrep/sigma/yara/suricata/nuclei) and rule ID. Returns parsed metadata + raw source.
    Phase: Rule Management
    Parameters:
      rule_format: Rule format (semgrep, sigma, yara, suricata, nuclei) (str)
      rule_id: Unique rule identifier (str)
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
    Parameters:
      rule_format: Rule format (semgrep, sigma, yara, suricata, nuclei) (str)
      content: Full rule content (str)
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
    Parameters:
      rule_format: Rule format (semgrep, sigma, yara, suricata, nuclei) (str)
      rule_id: Unique rule identifier (str)
      content: Full rule content (str)
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
    Parameters:
      rule_format: Rule format (semgrep, sigma, yara, suricata, nuclei) (str)
      rule_id: Unique rule identifier (str)
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
    Parameters:
      rule_format: Rule format (semgrep, sigma, yara, suricata, nuclei) (str)
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
    Parameters:
      rule_format: Rule format (semgrep, sigma, yara, suricata, nuclei) (str)
      rule_ids: Rule Ids (str)
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
    Parameters:
      rule_format: Rule format (semgrep, sigma, yara, suricata, nuclei) (str)
      rule_ids: Rule Ids (str) [default: '']
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
    Parameters:
      rule_format: Rule format (semgrep, sigma, yara, suricata, nuclei) (str)
      content: Full rule content (str)
      target_dir: Target directory (str) [default: '']
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
def rules_scan_target(rule_format: str, rule_id: str, target: str) -> str:
    """
    Scan a target with a specific rule (nuclei/yara/semgrep). For nuclei provide a URL, for yara provide a file/directory path, for semgrep provide a source code path.
    Phase: Rule Management
    Parameters:
      rule_format: Rule format (semgrep, sigma, yara, suricata, nuclei) (str)
      rule_id: Unique rule identifier (str)
      target: Target hostname, IP, or URL (str)
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
        result = _run(nuclei_scan, target, template=filepath)
    elif rule_format == "yara":
        from modules.tool_wrappers import yara_scan
        result = _run(yara_scan, filepath, target)
    elif rule_format == "semgrep":
        from modules.tool_wrappers import semgrep_scan
        result = _run(semgrep_scan, filepath, target)
    else:
        return f"Scan not supported for format: {rule_format}"

    return _fmt(result, fmt=rule_format)


@mcp.tool()
def rules_scan_all(rule_format: str, target: str) -> str:
    """
    Scan a target with ALL rules of a given format (nuclei/yara/semgrep). Uses the custom rules directory for the format.
    Phase: Rule Management
    Parameters:
      rule_format: Rule format (semgrep, sigma, yara, suricata, nuclei) (str)
      target: Target hostname, IP, or URL (str)
    Related: rules_list, rules_get, rules_create, rules_save, rules_delete, rules_stats, rules_template, rules_bulk_delete, rules_export, rules_import, rules_scan_target
    """
    from modules.rules_manager import RULE_ROOTS, FLAT_ROOTS
    from pathlib import Path

    if rule_format == "nuclei":
        root = RULE_ROOTS.get("nuclei") or FLAT_ROOTS.get("nuclei")
        if not root or not root.exists():
            return "Nuclei rules directory not found"
        from modules.tool_wrappers import nuclei_scan
        result = _run(nuclei_scan, target, templates_dir=str(root))
        return _fmt(result, fmt="nuclei")
    elif rule_format == "yara":
        root = RULE_ROOTS.get("yara") or FLAT_ROOTS.get("yara")
        if not root or not root.exists():
            return "YARA rules directory not found"
        from modules.tool_wrappers import yara_scan
        result = _run(yara_scan, str(root), target)
        return _fmt(result, fmt="yara")
    elif rule_format == "semgrep":
        root = RULE_ROOTS.get("semgrep")
        if not root or not root.exists():
            return "Semgrep rules directory not found"
        from modules.tool_wrappers import semgrep_scan
        result = _run(semgrep_scan, str(root), target)
        return _fmt(result, fmt="semgrep")
    else:
        return f"Scan not supported for format: {rule_format}"


# ---------------------------------------------------------------------------
# Papermill notebooks
# ---------------------------------------------------------------------------
@mcp.tool()
def papermill_list() -> str:
    """List available Jupyter notebooks that can be executed via papermill."""
    from modules.constants import SCRIPTS_DIR
    nbs = list((SCRIPTS_DIR / "automation-tools").glob("*.ipynb"))
    return "\n".join(f"  {nb.stem:<25} {nb.name}" for nb in nbs) or "No notebooks found."


@mcp.tool()
def papermill_run(notebook: str, params: str = "") -> str:
    """
    Execute a Jupyter notebook with papermill. Format params as 'key=value,key=value'.
    Phase: Notebook Execution
    Parameters:
      notebook: Notebook filename to execute (str)
      params: Comma-separated key=value parameters (str) [default: '']
    Related: papermill_list
    """
    import papermill as pm
    from modules.constants import SCRIPTS_DIR
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
def dns_track_domain(domain: str, interval: int = 300, duration: int = 0) -> str:
    """
    Track DNS resolutions for a domain over time (detect load balancers, CDN, fast-flux).
    Phase: DNS / Network
    Parameters:
      domain: Target domain (e.g., "example.local") (str)
      interval: Interval (int) [default: 300]
      duration: Duration in seconds (int) [default: 0]
    """
    from modules.tool_wrappers import dns_track
    history = _run(dns_track, domain, interval=interval, duration=duration)
    records = history.get(domain, [])
    return f"Tracked {len(records)} DNS resolutions for {domain}"


# ---------------------------------------------------------------------------
# Case Management
# ---------------------------------------------------------------------------
@mcp.tool()
def case_list() -> str:
    """List all pentest/forensic cases with status and creation date."""
    from modules.case_manager import CaseManager
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
    Parameters:
      case_id: Case ID to scope results (str)
      client: Client or organization name (str) [default: '']
      case_type: Case type (pentest, ir, forensics) (str) [default: 'pentest']
      description: Case or task description (str) [default: '']
      targets: Comma-separated target list (str) [default: '']
      goals: Goals (str) [default: '']
    Related: case_list, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done, case_task_list
    """
    from modules.case_manager import CaseManager
    target_list = [t.strip() for t in targets.split(",") if t.strip()] if targets else []
    goal_list = [g.strip() for g in goals.split("|") if g.strip()] if goals else []
    try:
        manifest = _run(CaseManager().create, case_id, client=client, case_type=case_type,
                        description=description, targets=target_list, goals=goal_list)
        return f"Case '{case_id}' created (type: {case_type}, goals: {len(goal_list)})"
    except ValueError as e:
        return f"Error: {e}"


@mcp.tool()
def case_goal_add(case_id: str, goal: str) -> str:
    """
    Add an analysis goal to a case. Required for all case types.
    Phase: Case Management
    Parameters:
      case_id: Case ID to scope results (str)
      goal: Analysis goal description (str)
    Related: case_list, case_create, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done, case_task_list
    """
    from modules.case_manager import CaseManager
    r = _run(CaseManager().goal_add, case_id, goal)
    if r is None:
        return "Case not found"
    return f"Goal added: {goal}\nAll goals: {r.get('goals', [])}"


@mcp.tool()
def case_goal_list(case_id: str) -> str:
    """
    List all analysis goals for a case.
    Phase: Case Management
    Parameters:
      case_id: Case ID to scope results (str)
    Related: case_list, case_create, case_goal_add, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done, case_task_list
    """
    from modules.case_manager import CaseManager
    goals = _run(CaseManager().goal_list, case_id)
    if not goals:
        return "No goals defined for this case."
    return "\n".join(f"  [{i}] {g}" for i, g in enumerate(goals))


# ---------------------------------------------------------------------------
# Incident Response tools
# ---------------------------------------------------------------------------
@mcp.tool()
def ir_timeline_add(case_id: str, timestamp: str, event: str,
                    severity: str = "info", source: str = "") -> str:
    """
    Add a timestamped event to the IR timeline.
    Phase: Incident Response
    Parameters:
      case_id: Case ID to scope results (str)
      timestamp: Timestamp (str)
      event: Event (str)
      severity: Filter by severity (str) [default: 'info']
      source: Source of finding (str) [default: '']
    Related: ir_timeline_list, ir_ttp_add, ir_ttp_list, ir_containment_add, ir_containment_list, ir_summary
    """
    from modules.case_manager import CaseManager
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
    Parameters:
      case_id: Case ID to scope results (str)
    Related: ir_timeline_add, ir_ttp_add, ir_ttp_list, ir_containment_add, ir_containment_list, ir_summary
    """
    from modules.case_manager import CaseManager
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
    Parameters:
      case_id: Case ID to scope results (str)
      tactic: MITRE ATT&CK tactic (str)
      technique: MITRE ATT&CK technique name (str)
      technique_id: MITRE ATT&CK technique ID (str) [default: '']
      notes: Notes (str) [default: '']
    Related: ir_timeline_add, ir_timeline_list, ir_ttp_list, ir_containment_add, ir_containment_list, ir_summary
    """
    from modules.case_manager import CaseManager
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
    Parameters:
      case_id: Case ID to scope results (str)
    Related: ir_timeline_add, ir_timeline_list, ir_ttp_add, ir_containment_add, ir_containment_list, ir_summary
    """
    from modules.case_manager import CaseManager
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
    Parameters:
      case_id: Case ID to scope results (str)
      action: Action to perform (str)
      status: Status value (str) [default: 'pending']
      owner: Owner (str) [default: '']
    Related: ir_timeline_add, ir_timeline_list, ir_ttp_add, ir_ttp_list, ir_containment_list, ir_summary
    """
    from modules.case_manager import CaseManager
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
    Parameters:
      case_id: Case ID to scope results (str)
    Related: ir_timeline_add, ir_timeline_list, ir_ttp_add, ir_ttp_list, ir_containment_add, ir_summary
    """
    from modules.case_manager import CaseManager
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
    Parameters:
      case_id: Case ID to scope results (str)
    Related: ir_timeline_add, ir_timeline_list, ir_ttp_add, ir_ttp_list, ir_containment_add, ir_containment_list
    """
    from modules.case_manager import CaseManager
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
    Parameters:
      case_id: Case ID to scope results (str)
    Related: case_list, case_create, case_goal_add, case_goal_list, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done, case_task_list
    """
    from modules.case_manager import CaseManager
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
    Parameters:
      case_id: Case ID to scope results (str)
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done, case_task_list
    """
    from modules.case_manager import CaseManager
    _run(CaseManager().update_status, case_id, "closed")
    return f"Case '{case_id}' closed."


@mcp.tool()
def case_evidence_add(case_id: str, filepath: str, category: str = "evidence",
                      description: str = "") -> str:
    """
    Add an evidence file to a case with SHA256/MD5 hashing for chain of custody.
    Phase: Case Management
    Parameters:
      case_id: Case ID to scope results (str)
      filepath: Path to file on disk (str)
      category: Rule category filter (str) [default: 'evidence']
      description: Case or task description (str) [default: '']
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done, case_task_list
    """
    from modules.case_manager import CaseManager
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
    Parameters:
      case_id: Case ID to scope results (str)
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_scope_add, case_scope_check, case_task_add, case_task_done, case_task_list
    """
    from modules.case_manager import CaseManager
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
    Parameters:
      case_id: Case ID to scope results (str)
      target: Target hostname, IP, or URL (str)
      in_scope: Whether target is in scope (bool) [default: True]
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_check, case_task_add, case_task_done, case_task_list
    """
    from modules.case_manager import CaseManager
    scope = _run(CaseManager().scope_add, case_id, target, in_scope=in_scope)
    return f"Target '{target}' added to {'in' if in_scope else 'out of'}-scope for '{case_id}'"


@mcp.tool()
def case_scope_check(case_id: str, target: str) -> str:
    """
    Check if a target is in scope for a case. Returns in_scope status and reason.
    Phase: Case Management
    Parameters:
      case_id: Case ID to scope results (str)
      target: Target hostname, IP, or URL (str)
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_task_add, case_task_done, case_task_list
    """
    from modules.case_manager import CaseManager
    result = _run(CaseManager().scope_check, case_id, target)
    return f"Target '{target}': {'IN SCOPE' if result['in_scope'] else 'OUT OF SCOPE'} — {result['reason']}"


@mcp.tool()
def case_task_add(case_id: str, description: str, priority: str = "medium") -> str:
    """
    Add a task to the case checklist.
    Phase: Case Management
    Parameters:
      case_id: Case ID to scope results (str)
      description: Case or task description (str)
      priority: Priority (low, medium, high) (str) [default: 'medium']
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_done, case_task_list
    """
    from modules.case_manager import CaseManager
    task = _run(CaseManager().task_add, case_id, description, priority=priority)
    return f"Task {task['id']} added to '{case_id}': {task['description']} [{task['priority']}]"


@mcp.tool()
def case_task_done(case_id: str, task_id: str) -> str:
    """
    Mark a task as completed in the case checklist.
    Phase: Case Management
    Parameters:
      case_id: Case ID to scope results (str)
      task_id: Task Id (str)
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_list
    """
    from modules.case_manager import CaseManager
    task = _run(CaseManager().task_done, case_id, task_id)
    if not task:
        return f"Task '{task_id}' not found in case '{case_id}'"
    return f"Task {task_id} marked done: {task['description']}"


@mcp.tool()
def case_task_list(case_id: str, show_done: bool = False) -> str:
    """
    List pending (or all) tasks for a case.
    Phase: Case Management
    Parameters:
      case_id: Case ID to scope results (str)
      show_done: Show Done (bool) [default: False]
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done
    """
    from modules.case_manager import CaseManager
    tasks = _run(CaseManager().task_list, case_id, show_done=show_done)
    if not tasks:
        return "No tasks found."
    return "\n".join(
        f"  {t['id']:<8} {'[x]' if t.get('done') else '[ ]'} {t['description']:<50} [{t.get('priority','?')}]"
        for t in tasks
    )


@mcp.tool()
def case_finding_add(case_id: str, title: str, severity: str = "medium",
                     description: str = "", remediation: str = "",
                     source: str = "", cve: str = "", cwe: str = "",
                     impact: str = "", poc: str = "",
                     references: str = "") -> str:
    """Add a structured finding to a case (severity: info/low/medium/high/critical).

    Supports optional CVE/CWE references, impact description, PoC, and
    comma-separated reference URLs.
    Phase: Case Management
    Parameters:
      case_id: Case ID to scope results (str)
      title: Title (str)
      severity: Filter by severity (str) [default: 'medium']
      description: Case or task description (str) [default: '']
      remediation: Remediation steps (str) [default: '']
      source: Source of finding (str) [default: '']
      cve: CVE identifier (str) [default: '']
      cwe: CWE identifier (str) [default: '']
      impact: Impact description (str) [default: '']
      poc: Proof of concept text (str) [default: '']
      references: Reference URLs (comma-separated) (str) [default: '']
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done
    """
    from modules.findings_db import FindingsDB
    from modules.constants import CASES_DIR
    ref_list = [r.strip() for r in references.split(",") if r.strip()] if references else []
    db = FindingsDB(Path(CASES_DIR) / case_id)
    finding = _run(db.add, title, severity=severity, description=description,
                   remediation=remediation, source=source,
                   cve=cve, cwe=cwe, impact=impact, poc=poc,
                   references=ref_list)
    parts = [f"Finding {finding['id']} added: {finding['title']} [{finding['severity']}]"]
    if finding.get('cve'):
        parts.append(f"  CVE: {finding['cve']}")
    if finding.get('cwe'):
        parts.append(f"  CWE: {finding['cwe']}")
    return "\n".join(parts)


@mcp.tool()
def case_finding_update(case_id: str, finding_id: str,
                        severity: str = "", status: str = "",
                        description: str = "", remediation: str = "",
                        cve: str = "", cwe: str = "", impact: str = "",
                        poc: str = "") -> str:
    """
    Update an existing finding's fields. Empty strings are skipped.
    Phase: Case Management
    Parameters:
      case_id: Case ID to scope results (str)
      finding_id: Finding identifier (str)
      severity: Filter by severity (str) [default: '']
      status: Status value (str) [default: '']
      description: Case or task description (str) [default: '']
      remediation: Remediation steps (str) [default: '']
      cve: CVE identifier (str) [default: '']
      cwe: CWE identifier (str) [default: '']
      impact: Impact description (str) [default: '']
      poc: Proof of concept text (str) [default: '']
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done
    """
    from modules.findings_db import FindingsDB
    from modules.constants import CASES_DIR
    db = FindingsDB(Path(CASES_DIR) / case_id)
    kwargs = {}
    for k, v in [("severity", severity), ("status", status),
                 ("description", description), ("remediation", remediation),
                 ("cve", cve), ("cwe", cwe), ("impact", impact), ("poc", poc)]:
        if v:
            kwargs[k] = v
    result = _run(db.update, finding_id, **kwargs)
    if not result:
        return f"Finding '{finding_id}' not found in case '{case_id}'"
    return f"Finding {finding_id} updated"


@mcp.tool()
def case_finding_link_evidence(case_id: str, finding_id: str,
                               evidence: str) -> str:
    """
    Link evidence file(s) to a finding (comma-separated filenames).
    Phase: Case Management
    Parameters:
      case_id: Case ID to scope results (str)
      finding_id: Finding identifier (str)
      evidence: Comma-separated evidence filenames (str)
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done
    """
    from modules.findings_db import FindingsDB
    from modules.constants import CASES_DIR
    db = _run(FindingsDB, CASES_DIR / case_id)
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
    Parameters:
      case_id: Case ID to scope results (str)
      finding_id: Finding identifier (str)
      evidence: Comma-separated evidence filenames (str)
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done
    """
    from modules.findings_db import FindingsDB
    from modules.constants import CASES_DIR
    db = _run(FindingsDB, CASES_DIR / case_id)
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
    Parameters:
      case_id: Case ID to scope results (str)
      client: Client or organization name (str) [default: '']
      description: Case or task description (str) [default: '']
      assessment_dates: Assessment Dates (str) [default: '']
      executive_summary: Executive Summary (str) [default: '']
      key_observations: Key Observations (str) [default: '']
      recommendations: Recommendations (str) [default: '']
      methodology_tools: Methodology Tools (str) [default: '']
      contacts: Contacts (str) [default: '']
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done
    """
    from modules.case_manager import CaseManager
    from modules.constants import CASES_DIR
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
    Parameters:
      case_id: Case ID to scope results (str)
      text: Text (str)
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done
    """
    from modules.case_manager import CaseManager
    result = _run(CaseManager().add_strength, case_id, text)
    if not result:
        return f"Case '{case_id}' not found"
    return f"Strength added to '{case_id}' ({len(result['strengths'])} total)"


@mcp.tool()
def case_strength_list(case_id: str) -> str:
    """
    List identified strengths for a case.
    Phase: Case Management
    Parameters:
      case_id: Case ID to scope results (str)
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done
    """
    from modules.case_manager import CaseManager
    strengths = _run(CaseManager().list_strengths, case_id)
    if not strengths:
        return "No strengths documented."
    return "\n".join(f"  {i+1}. {s}" for i, s in enumerate(strengths))


@mcp.tool()
def case_weakness_add(case_id: str, text: str) -> str:
    """
    Add an identified weakness/vulnerability observation to a case.
    Phase: Case Management
    Parameters:
      case_id: Case ID to scope results (str)
      text: Text (str)
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done
    """
    from modules.case_manager import CaseManager
    result = _run(CaseManager().add_weakness, case_id, text)
    if not result:
        return f"Case '{case_id}' not found"
    return f"Weakness added to '{case_id}' ({len(result['weaknesses'])} total)"


@mcp.tool()
def case_weakness_list(case_id: str) -> str:
    """
    List identified weaknesses for a case.
    Phase: Case Management
    Parameters:
      case_id: Case ID to scope results (str)
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done
    """
    from modules.case_manager import CaseManager
    weaknesses = _run(CaseManager().list_weaknesses, case_id)
    if not weaknesses:
        return "No weaknesses documented."
    return "\n".join(f"  {i+1}. {s}" for i, s in enumerate(weaknesses))


@mcp.tool()
def case_report_engagement(case_id: str) -> str:
    """
    Generate an HTML + Markdown engagement report from case data, findings, and evidence.
    Phase: Case Management
    Parameters:
      case_id: Case ID to scope results (str)
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done
    """
    from modules.report_generator import generate_engagement_report
    from modules.constants import CASES_DIR
    case_dir = Path(CASES_DIR) / case_id
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
    Parameters:
      case_id: Case ID to scope results (str)
      write_sections: Write Sections (bool) [default: False]
      formats: Formats (str) [default: 'md,html,docx,pdf']
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done
    """
    from modules.report_generator import generate_obsidian_report
    from modules.constants import CASES_DIR
    case_dir = Path(CASES_DIR) / case_id
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
def case_timeline(case_id: str) -> str:
    """
    Generate an HTML timeline visualization from case activity (evidence, findings, runbooks).
    Phase: Case Management
    Parameters:
      case_id: Case ID to scope results (str)
    Related: case_list, case_create, case_goal_add, case_goal_list, case_info, case_close, case_evidence_add, case_evidence_verify, case_scope_add, case_scope_check, case_task_add, case_task_done
    """
    from modules.report_generator import generate_timeline_html
    from modules.constants import CASES_DIR
    case_dir = Path(CASES_DIR) / case_id
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
    Parameters:
      filter: Filter by keyword (str) [default: '']
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
    Parameters:
      name: Name (str)
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
    Parameters:
      tool_name: Tool name from /share/tools/ (str)
      args: Additional arguments (str) [default: '']
      workdir_subpath: Subdirectory within tool dir (str) [default: '']
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
def tool_ligolo_proxy(lport: int = 11601, laddr: str = "0.0.0.0",
                      self_cert_dir: str = "") -> str:
    """
    Start ligolo-ng proxy (receive reverse connections from agents).
    Phase: Tool Execution
    Parameters:
      lport: Listen port (int) [default: 11601]
      laddr: Listen address (str) [default: '0.0.0.0']
      self_cert_dir: Directory for self-signed certificates (str) [default: '']
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
        return f"ligolo-ng proxy started on {laddr}:{lport} (PID: {proc.pid})"
    except Exception as e:
        return f"Error starting ligolo proxy: {e}"


@mcp.tool()
def tool_ligolo_agent(proxy_addr: str, proxy_port: int = 11601,
                      tun_iface: str = "ligolo") -> str:
    """
    Start ligolo-ng agent connecting back to the proxy.
    Phase: Tool Execution
    Parameters:
      proxy_addr: Proxy address for agent (str)
      proxy_port: Proxy port for agent (int) [default: 11601]
      tun_iface: TUN interface name (str) [default: 'ligolo']
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect, tool_hydra_bruteforce
    """
    agent = Path(_TOOLS_DIR) / "ligo-agent"
    if not agent.exists():
        return f"ligo-agent not found at {agent}."
    cmd = [str(agent), "-connect", f"{proxy_addr}:{proxy_port}",
           "-tun", tun_iface]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
    Parameters:
      domain: Target domain (e.g., "example.local") (str)
      server: Target server address (IP or hostname) (str) [default: '']
      username: Username for authentication (str) [default: '']
      password: Password for authentication (str) [default: '']
      ldap_filter: LDAP search filter (str) [default: '']
      attrs: Attrs (str) [default: '']
      all_attrs: All Attrs (bool) [default: False]
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
    Parameters:
      pspy_path: Path to pspy binary (str) [default: '']
      duration: Duration in seconds (int) [default: 30]
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
def tool_bloodhound_py_ingest(domain: str, username: str, password: str,
                              dc_ip: str = "", dns_server: str = "",
                              collection_method: str = "All") -> str:
    """
    Run BloodHound.py Python ingestor against a domain.
    Phase: Tool Execution
    Parameters:
      domain: Target domain (e.g., "example.local") (str)
      username: Username for authentication (str)
      password: Password for authentication (str)
      dc_ip: Domain controller IP address (str) [default: '']
      dns_server: Dns Server (str) [default: '']
      collection_method: Collection Method (str) [default: 'All']
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect, tool_hydra_bruteforce
    """
    from modules.tool_wrappers import bloodhound_ingest
    r = _run(bloodhound_ingest, domain=domain, username=username,
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
    Parameters:
      server: Target server address (IP or hostname) (str) [default: '']
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
    Parameters:
      domain: Target domain (e.g., "example.local") (str)
      kdc: Kdc (str)
      admin_server: Admin Server (str) [default: '']
      output_file: Output file path (str) [default: '']
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
    Parameters:
      principal: Principal (str)
      password: Password for authentication (str) [default: '']
      keytab: Keytab (str) [default: '']
      realm: Realm (str) [default: '']
      lifetime: Lifetime (str) [default: '24h']
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
    Parameters:
      domain: Target domain (e.g., "example.local") (str)
      kdc: Kdc (str)
      username: Username for authentication (str) [default: '']
      password: Password for authentication (str) [default: '']
      skip_time_sync: Skip Time Sync (bool) [default: False]
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
    Parameters:
      software: Software category for LaZagne (str) [default: 'all']
      password: Password for authentication (str) [default: '']
      target_path: Target Path (str) [default: '']
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
def tool_responder_analyze(interface: str = "eth0", analyze_mode: bool = False,
                           verbose: bool = False, timeout: int = 60) -> str:
    """
    Start Responder in analyze or poison mode to capture NTLMv2 hashes.
    Phase: Tool Execution
    Parameters:
      interface: Interface (str) [default: 'eth0']
      analyze_mode: Only analyze, don't poison (bool) [default: False]
      verbose: Enable verbose output (bool) [default: False]
      timeout: Operation timeout in seconds (int) [default: 60]
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_poison, tool_evil_winrm_connect, tool_hydra_bruteforce
    """
    from modules.tool_wrappers import responder_analyze
    r = _run(responder_analyze, interface=interface, analyze_mode=analyze_mode,
             verbose=verbose, timeout=timeout)
    if r.get("error"):
        return f"Error: {r['error']}"
    lines = [f"Responder {r.get('mode','?')} on {r.get('interface','?')}"]
    out = r.get("output_lines", [])
    lines.extend(out[-20:])
    return "\n".join(lines)


@mcp.tool()
def tool_responder_poison(interface: str = "eth0") -> str:
    """
    Run Responder in poison mode to capture NTLMv2 hashes.
    Phase: Tool Execution
    Parameters:
      interface: Interface (str) [default: 'eth0']
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_evil_winrm_connect, tool_hydra_bruteforce
    """
    from modules.tool_wrappers import responder_poison
    r = _run(responder_poison, interface=interface)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    return f"Responder poisoning on {interface}: {r}"[:1000]


@mcp.tool()
def tool_evil_winrm_connect(ip: str, username: str = "", password: str = "",
                            hash_value: str = "", command: str = "") -> str:
    """
    Connect to a WinRM service via Evil-WinRM for interactive or command execution.
    Phase: Tool Execution
    Parameters:
      ip: Ip (str)
      username: Username for authentication (str) [default: '']
      password: Password for authentication (str) [default: '']
      hash_value: Hash Value (str) [default: '']
      command: Shell command to execute (str) [default: '']
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_hydra_bruteforce
    """
    from modules.tool_wrappers import evil_winrm_connect
    r = _run(evil_winrm_connect, ip=ip, username=username, password=password,
             hash_value=hash_value, command=command)
    if r.get("error"):
        return f"Error: {r['error']}"
    return r.get("stdout", r.get("output_file", "Evil-WinRM connected"))


@mcp.tool()
def tool_hydra_bruteforce(protocol: str, target: str, userlist: str,
                          passlist: str, port: int = 0,
                          service: str = "") -> str:
    """
    Run Hydra brute-force attack against a service.
    Phase: Tool Execution
    Parameters:
      protocol: Network protocol (str)
      target: Target hostname, IP, or URL (str)
      userlist: Userlist (str)
      passlist: Passlist (str)
      port: Port number (int) [default: 0]
      service: Service (str) [default: '']
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect
    """
    from modules.tool_wrappers import hydra_bruteforce
    r = _run(hydra_bruteforce, protocol=protocol, target=target,
             userlist=userlist, passlist=passlist, port=port, service=service)
    if r.get("error"):
        return f"Error: {r['error']}"
    return _fmt(r)


@mcp.tool()
def tool_john_crack(hash_file: str, wordlist: str = "",
                    format: str = "", show: bool = False) -> str:
    """
    Crack hashes with John the Ripper.
    Phase: Tool Execution
    Parameters:
      hash_file: Path to hash file (str)
      wordlist: Path to wordlist file (str) [default: '']
      format: Hash format for John (str) [default: '']
      show: Show cracked passwords (bool) [default: False]
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect
    """
    from modules.tool_wrappers import john_crack
    r = _run(john_crack, hash_file=hash_file, wordlist=wordlist,
             format=format, show=show)
    if r.get("error"):
        return f"Error: {r['error']}"
    if show and r.get("cracked"):
        return f"Cracked ({len(r['cracked'])}):\n" + "\n".join(r["cracked"][:30])
    return _fmt(r)


@mcp.tool()
def tool_metasploit_module(module: str, payload: str, target: str,
                           lhost: str = "", lport: int = 4444,
                           timeout: int = 120) -> str:
    """
    Run a Metasploit module with a payload against a target.
    Phase: Tool Execution
    Parameters:
      module: Metasploit module path (str)
      payload: Metasploit payload name (str)
      target: Target hostname, IP, or URL (str)
      lhost: Lhost (str) [default: '']
      lport: Listen port (int) [default: 4444]
      timeout: Operation timeout in seconds (int) [default: 120]
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect
    """
    from modules.tool_wrappers import metasploit_module
    r = _run(metasploit_module, module=module, payload=payload, target=target,
             lhost=lhost, lport=lport, timeout=timeout)
    if r.get("error"):
        return f"Error: {r['error']}"
    return _fmt(r)


@mcp.tool()
def tool_metasploit_resource(resource_script: str) -> str:
    """
    Run a Metasploit resource script (.rc) via msfconsole -q -r.
    Phase: Tool Execution
    Parameters:
      resource_script: Metasploit resource script (.rc) path (str)
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect
    """
    from modules.tool_wrappers import metasploit_resource
    r = _run(metasploit_resource, resource_script=resource_script)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    return _fmt(r)


@mcp.tool()
def tool_sqlmap_detect(url: str, data: str = "", cookie: str = "",
                       level: int = 1, risk: int = 1) -> str:
    """
    Detect SQL injection vulnerabilities with SQLMap.
    Phase: Tool Execution
    Parameters:
      url: Full URL with scheme (str)
      data: POST data (str) [default: '']
      cookie: Cookie string (str) [default: '']
      level: SQLMap level (1-5) (int) [default: 1]
      risk: SQLMap risk (1-3) (int) [default: 1]
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect
    """
    from modules.tool_wrappers import sqlmap_detect
    r = _run(sqlmap_detect, url=url, data=data, cookie=cookie,
             level=level, risk=risk)
    if r.get("error"):
        return f"Error: {r['error']}"
    vulnerable = "VULNERABLE" if r.get("vulnerable") else "No injection detected"
    return f"SQLMap: {vulnerable}\n" + _fmt(r)


@mcp.tool()
def tool_sqlmap_exploit(url: str) -> str:
    """
    Exploit SQL injection with SQLMap (OS shell, dump DB, etc.).
    Phase: Tool Execution
    Parameters:
      url: Full URL with scheme (str)
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect
    """
    from modules.tool_wrappers import sqlmap_exploit
    r = _run(sqlmap_exploit, url=url)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    return _fmt(r)


# ---------------------------------------------------------------------------
# Nmap pipeline
# ---------------------------------------------------------------------------
@mcp.tool()
def nmap_initial_tcp(target: str, top_ports: int = 1000) -> str:
    """
    Run initial TCP SYN scan (top N ports).
    Phase: Nmap Scanning
    Parameters:
      target: Target hostname, IP, or URL (str)
      top_ports: Top Ports (int) [default: 1000]
    Related: nmap_initial_udp, nmap_full_tcp, nmap_pipeline, nmap_parse
    """
    from modules.nmap_wrapper import scan_initial_tcp
    r = _run(scan_initial_tcp, target=target, top_ports=top_ports)
    return _fmt(r)


@mcp.tool()
def nmap_initial_udp(target: str, top_ports: int = 1000) -> str:
    """
    Run initial UDP scan (top N ports).
    Phase: Nmap Scanning
    Parameters:
      target: Target hostname, IP, or URL (str)
      top_ports: Top Ports (int) [default: 1000]
    Related: nmap_initial_tcp, nmap_full_tcp, nmap_pipeline, nmap_parse
    """
    from modules.nmap_wrapper import scan_initial_udp
    r = _run(scan_initial_udp, target=target, top_ports=top_ports)
    return _fmt(r)


@mcp.tool()
def nmap_full_tcp(target: str) -> str:
    """
    Run full TCP port scan (1-65535).
    Phase: Nmap Scanning
    Parameters:
      target: Target hostname, IP, or URL (str)
    Related: nmap_initial_tcp, nmap_initial_udp, nmap_pipeline, nmap_parse
    """
    from modules.nmap_wrapper import scan_full_tcp
    r = _run(scan_full_tcp, target=target)
    return _fmt(r)


@mcp.tool()
def nmap_pipeline(target: str, skip_full: bool = False) -> str:
    """
    Run full nmap reconnaissance pipeline (nmaptest.sh workflow).
    Phase: Nmap Scanning
    Parameters:
      target: Target hostname, IP, or URL (str)
      skip_full: Skip Full (bool) [default: False]
    Related: nmap_initial_tcp, nmap_initial_udp, nmap_full_tcp, nmap_parse
    """
    from modules.nmap_wrapper import scan_pipeline
    r = _run(scan_pipeline, target=target, skip_full=skip_full)
    if r.get("error"):
        return f"Error: {r['error']}"
    phases = r.get("summary", {})
    lines = [f"Nmap pipeline for {target}:"]
    for name, status in phases.items():
        lines.append(f"  {name}: {status}")
    lines.append(f"Output: {r.get('output_dir', '')}")
    return "\n".join(lines)


@mcp.tool()
def nmap_parse(target: str) -> str:
    """
    Parse all nmap output files into structured JSON.
    Phase: Nmap Scanning
    Parameters:
      target: Target hostname, IP, or URL (str)
    Related: nmap_initial_tcp, nmap_initial_udp, nmap_full_tcp, nmap_pipeline
    """
    from modules.nmap_wrapper import parse_results
    r = _run(parse_results, target=target)
    if r.get("error"):
        return f"Error: {r['error']}"
    return json.dumps(r, indent=2)[:3000]


# ---------------------------------------------------------------------------
# Browser forensics — LevelDB / IndexedDB
# ---------------------------------------------------------------------------
@mcp.tool()
def browser_analyze_leveldb(path: str) -> str:
    """
    Analyze a LevelDB directory and classify key-value pairs.
    Phase: General
    Parameters:
      path: Path (str)
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
    Parameters:
      path: Path (str)
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
    Parameters:
      profile_path: Profile Path (str)
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
def impacket_secretsdump(target: str, username: str = "", password: str = "",
                         domain: str = "", hash: str = "",
                         just_dc: bool = False) -> str:
    """
    Dump SAM/LSA/AD secrets via Impacket secretsdump.
    Phase: Impacket Exploitation
    Parameters:
      target: Target hostname, IP, or URL (str)
      username: Username for authentication (str) [default: '']
      password: Password for authentication (str) [default: '']
      domain: Target domain (e.g., "example.local") (str) [default: '']
      hash: Hash (str) [default: '']
      just_dc: Just Dc (bool) [default: False]
    Related: impacket_wmiexec, impacket_ticketer, impacket_psexec, impacket_smbexec
    """
    from modules.tool_wrappers import impacket_secretsdump
    r = _run(impacket_secretsdump, target=target, username=username,
             password=password, domain=domain, hash=hash, just_dc=just_dc)
    return _fmt(r)


@mcp.tool()
def impacket_wmiexec(target: str, username: str = "", password: str = "",
                     domain: str = "", hash: str = "", command: str = "whoami") -> str:
    """
    Execute commands via WMI using Impacket wmiexec.
    Phase: Impacket Exploitation
    Parameters:
      target: Target hostname, IP, or URL (str)
      username: Username for authentication (str) [default: '']
      password: Password for authentication (str) [default: '']
      domain: Target domain (e.g., "example.local") (str) [default: '']
      hash: Hash (str) [default: '']
      command: Shell command to execute (str) [default: 'whoami']
    Related: impacket_secretsdump, impacket_ticketer, impacket_psexec, impacket_smbexec
    """
    from modules.tool_wrappers import impacket_wmiexec
    r = _run(impacket_wmiexec, target=target, username=username,
             password=password, domain=domain, hash=hash, command=command)
    return _fmt(r)


@mcp.tool()
def impacket_ticketer(domain: str, username: str, ntlm_hash: str,
                      domain_sid: str, krbtgt_hash: str = "",
                      duration_hours: int = 10) -> str:
    """
    Create a golden/silver Kerberos ticket via Impacket ticketer.
    Phase: Impacket Exploitation
    Parameters:
      domain: Target domain (e.g., "example.local") (str)
      username: Username for authentication (str)
      ntlm_hash: Ntlm Hash (str)
      domain_sid: Domain Sid (str)
      krbtgt_hash: Krbtgt Hash (str) [default: '']
      duration_hours: Duration Hours (int) [default: 10]
    Related: impacket_secretsdump, impacket_wmiexec, impacket_psexec, impacket_smbexec
    """
    from modules.tool_wrappers import impacket_ticketer
    r = _run(impacket_ticketer, domain=domain, username=username,
             ntlm_hash=ntlm_hash, domain_sid=domain_sid,
             krbtgt_hash=krbtgt_hash, duration_hours=duration_hours)
    if r.get("error"):
        return f"Error: {r['error']}"
    return f"Ticket created:\n{r.get('ticket', '')}\n{r.get('stdout', '')[:500]}"


@mcp.tool()
def impacket_psexec(target: str, username: str = "", password: str = "",
                    domain: str = "", hash: str = "",
                    command: str = "cmd.exe /c whoami") -> str:
    """
    Execute commands via SMB using Impacket psexec.
    Phase: Impacket Exploitation
    Parameters:
      target: Target hostname, IP, or URL (str)
      username: Username for authentication (str) [default: '']
      password: Password for authentication (str) [default: '']
      domain: Target domain (e.g., "example.local") (str) [default: '']
      hash: Hash (str) [default: '']
      command: Shell command to execute (str) [default: 'cmd.exe /c whoami']
    Related: impacket_secretsdump, impacket_wmiexec, impacket_ticketer, impacket_smbexec
    """
    from modules.tool_wrappers import impacket_psexec
    r = _run(impacket_psexec, target=target, username=username,
             password=password, domain=domain, hash=hash, command=command)
    return _fmt(r)


@mcp.tool()
def impacket_smbexec(target: str, username: str = "", password: str = "",
                     domain: str = "", hash: str = "",
                     command: str = "whoami") -> str:
    """
    Execute commands via SMB using Impacket smbexec (no service creation).
    Phase: Impacket Exploitation
    Parameters:
      target: Target hostname, IP, or URL (str)
      username: Username for authentication (str) [default: '']
      password: Password for authentication (str) [default: '']
      domain: Target domain (e.g., "example.local") (str) [default: '']
      hash: Hash (str) [default: '']
      command: Shell command to execute (str) [default: 'whoami']
    Related: impacket_secretsdump, impacket_wmiexec, impacket_ticketer, impacket_psexec
    """
    from modules.tool_wrappers import impacket_smbexec
    r = _run(impacket_smbexec, target=target, username=username,
             password=password, domain=domain, hash=hash, command=command)
    return _fmt(r)


# ---------------------------------------------------------------------------
# Web fuzzing
# ---------------------------------------------------------------------------
@mcp.tool()
def ffuf_directory(url: str, wordlist: str, extensions: str = "",
                   filter_size: str = "") -> str:
    """
    Run ffuf for directory/file fuzzing.
    Phase: Web Fuzzing
    Parameters:
      url: Full URL with scheme (str)
      wordlist: Path to wordlist file (str)
      extensions: Extensions (str) [default: '']
      filter_size: Filter Size (str) [default: '']
    """
    from modules.tool_wrappers import ffuf_fuzz
    r = _run(ffuf_fuzz, url=url, wordlist=wordlist, mode="dir",
             extensions=extensions, filter_size=filter_size)
    if r.get("error"):
        return f"Error: {r['error']}"
    total = r.get("total", 0)
    return f"ffuf: {total} results\nOutput: {r.get('output_file', '')}"


@mcp.tool()
def gobuster_directory(url: str, wordlist: str, extensions: str = "") -> str:
    """
    Run gobuster for directory brute-forcing.
    Phase: Web Brute-force
    Parameters:
      url: Full URL with scheme (str)
      wordlist: Path to wordlist file (str)
      extensions: Extensions (str) [default: '']
    """
    from modules.tool_wrappers import gobuster_dir
    r = _run(gobuster_dir, url=url, wordlist=wordlist, extensions=extensions)
    if r.get("error"):
        return f"Error: {r['error']}"
    out = r.get("output", r.get("stdout", ""))[:2000]
    return f"gobuster complete\n{out}"


# ---------------------------------------------------------------------------
# Hash cracking
# ---------------------------------------------------------------------------
@mcp.tool()
def hashcat_crack(hash_file: str, wordlist: str = "", hash_mode: int = 0) -> str:
    """
    Crack hashes with hashcat (GPU-accelerated).
    Phase: Hash Cracking
    Parameters:
      hash_file: Path to hash file (str)
      wordlist: Path to wordlist file (str) [default: '']
      hash_mode: Hashcat mode number (int) [default: 0]
    """
    from modules.tool_wrappers import hashcat_crack as _hc
    r = _run(_hc, hash_file=hash_file, wordlist=wordlist, hash_mode=hash_mode)
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
    Parameters:
      xml_file: Path to Burp Suite XML export (str)
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
    Parameters:
      json_file: Path to Caido JSON export file (str)
      case_id: Case ID to scope results (str) [default: '']
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect
    """
    from modules.tool_wrappers import caido_import_json
    r = _run(caido_import_json, json_file=json_file, case_id=case_id)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    findings = r.get("findings", [])
    return f"Caido import: {len(findings)} findings\n" + _fmt(r)


# ---------------------------------------------------------------------------
# Secret scanning
# ---------------------------------------------------------------------------
@mcp.tool()
def tool_trufflehog_org(org: str, output_dir: str = "") -> str:
    """
    Scan a GitHub org for secrets via TruffleHog Docker image.
    Phase: Tool Execution
    Parameters:
      org: GitHub organization name (str)
      output_dir: Directory for output files (str) [default: '']
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect
    """
    from modules.tool_wrappers import trufflehog_org
    from pathlib import Path
    od = Path(output_dir) if output_dir else None
    r = _run(trufflehog_org, org=org, output_dir=od)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    return f"TruffleHog org scan: {r.get('verified', 0)} verified, {r.get('unverified', 0)} unverified\nFile: {r.get('raw_file', '')}"


@mcp.tool()
def tool_trufflehog_local(path: str, output_dir: str = "") -> str:
    """
    Run TruffleHog on a local directory to find secrets.
    Phase: Tool Execution
    Parameters:
      path: Path (str)
      output_dir: Directory for output files (str) [default: '']
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect
    """
    from modules.tool_wrappers import trufflehog_local
    from pathlib import Path
    od = Path(output_dir) if output_dir else None
    r = _run(trufflehog_local, path=path, output_dir=od)
    if isinstance(r, dict) and r.get("error"):
        return f"Error: {r['error']}"
    return f"TruffleHog local scan: {r.get('verified', 0)} verified, {r.get('unverified', 0)} unverified\nFile: {r.get('raw_file', '')}"


# ---------------------------------------------------------------------------
# Privesc check (linpeas / winpeas)
# ---------------------------------------------------------------------------
@mcp.tool()
def linpeas_local() -> str:
    """Run linpeas.sh locally for privilege escalation checks."""
    from modules.tool_wrappers import linpeas_run
    r = _run(linpeas_run)
    if r.get("error"):
        return f"Error: {r['error']}"
    return f"linpeas complete\nOutput: {r.get('output_file', '')}"


@mcp.tool()
def tool_winpeas_run(target_host: str = "", target_user: str = "",
                     target_pass: str = "", local_path: str = "") -> str:
    """
    Execute winPEAS.exe on a remote target for Windows privesc checks.
    Phase: Tool Execution
    Parameters:
      target_host: Remote host for credential testing (str) [default: '']
      target_user: Target User (str) [default: '']
      target_pass: Target Pass (str) [default: '']
      local_path: Local path to winPEAS binary (str) [default: '']
    Related: tools_discover, tools_search, tools_run_in_dir, tool_ligolo_proxy, tool_ligolo_agent, tool_windapsearch_enum, tool_pspy_monitor, tool_bloodhound_py_ingest, tool_lazagne_run, tool_responder_analyze, tool_responder_poison, tool_evil_winrm_connect
    """
    from modules.tool_wrappers import winpeas_run
    r = _run(winpeas_run, target_host=target_host, target_user=target_user,
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
    Parameters:
      server: Target server address (IP or hostname) (str)
      remote_port: Remote port for tunnel (int) [default: 8080]
      local_port: Local port for tunnel (int) [default: 1080]
      socks: Enable SOCKS proxy (bool) [default: True]
      reverse: Reverse tunnel mode (bool) [default: False]
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
    Parameters:
      port: Port number (int) [default: 8080]
      socks: Enable SOCKS proxy (bool) [default: True]
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
    Parameters:
      domain: Target domain (e.g., "example.local") (str)
      config_dir: Configuration directory (str) [default: '']
      phishing_dir: Phishing template directory (str) [default: '']
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
    Parameters:
      campaign_file: Path to GoPhish campaign JSON (str)
      gophish_url: GoPhish API URL (str) [default: '']
      api_key: Api Key (str) [default: '']
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
    Parameters:
      target: Target hostname, IP, or URL (str)
      username: Username for authentication (str) [default: '']
      password: Password for authentication (str) [default: '']
      domain: Target domain (e.g., "example.local") (str) [default: '']
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
# Auto-recon pipeline
# ---------------------------------------------------------------------------
@mcp.tool()
def auto_recon(target: str) -> str:
    """
    Chain nmap → ffuf → nuclei in a single reconnaissance pipeline.
    Phase: Automated Recon
    Parameters:
      target: Target hostname, IP, or URL (str)
    """
    from modules.tool_wrappers import auto_recon
    r = _run(auto_recon, target=target)
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
    Store a credential in the loot database.
    Phase: Loot Database
    Parameters:
      source: Source of finding (str)
      target: Target hostname, IP, or URL (str)
      username: Username for authentication (str)
      password: Password for authentication (str) [default: '']
      hash: Hash (str) [default: '']
      hash_type: Hash Type (str) [default: '']
      domain: Target domain (e.g., "example.local") (str) [default: '']
      protocol: Network protocol (str) [default: '']
      port: Port number (int) [default: 0]
    Related: loot_search
    """
    from modules.tool_wrappers import LootDB
    db = LootDB()
    cid = db.add_credential(source=source, target=target, username=username,
                            password=password, hash=hash, hash_type=hash_type,
                            domain=domain, protocol=protocol, port=port)
    db.close()
    return f"Credential stored (id={cid})"


@mcp.tool()
def loot_search(query: str) -> str:
    """
    Search the loot database for credentials, tokens, sessions.
    Phase: Loot Database
    Parameters:
      query: Query (str)
    Related: loot_add_credential
    """
    from modules.tool_wrappers import LootDB
    db = LootDB()
    results = db.search(query)
    db.close()
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


# ---------------------------------------------------------------------------
# pypykatz — LSASS dump parsing
# ---------------------------------------------------------------------------
@mcp.tool()
def pypykatz_parse(dump_file: str) -> str:
    """
    Parse a LSASS minidump with pypykatz to extract credentials.
    Phase: Credential Extraction
    Parameters:
      dump_file: Path to LSASS minidump file (str)
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

def _run_bin_noargs(fn):
    """_run helper for wrapper functions that take no args."""
    fut = _POOL.submit(fn)
    try:
        return _bin_result(fut.result(timeout=_TIMEOUT))
    except concurrent.futures.TimeoutError:
        return f"Error: Timed out after {_TIMEOUT}s"

def _run_bin_binary(fn, binary_path: str):
    """_run helper for wrapper functions that take (binary)."""
    fut = _POOL.submit(fn, binary_path)
    try:
        return _bin_result(fut.result(timeout=_TIMEOUT))
    except concurrent.futures.TimeoutError:
        return f"Error: Timed out after {_TIMEOUT}s"

def _run_bin_kwargs(fn, *args, **kwargs):
    """_run helper that passes through args/kwargs."""
    fut = _POOL.submit(fn, *args, **kwargs)
    try:
        return _bin_result(fut.result(timeout=_TIMEOUT))
    except concurrent.futures.TimeoutError:
        return f"Error: Timed out after {_TIMEOUT}s"

@mcp.tool()
def binary_check() -> str:
    """Check what binary exploitation / reverse engineering tools are available on this system. Reports 40+ tools across 9 categories."""
    from modules.bin_wrapper import check as _bc
    return _run_bin_noargs(_bc)

@mcp.tool()
def binary_analyze(binary_path: str) -> str:
    """
    Run a full binary exploitation analysis on a target binary (ELF/PE/Mach-O). Returns file info, security mitigations, vulnerability scan, exploitability scoring, and tool-specific deep analysis (angr, pwntools, r2).
    Phase: Binary Exploitation
    Parameters:
      binary_path: Path to the binary file (str)
    Related: binary_check, binary_summary, binary_vulns, binary_checksec, binary_gadgets, binary_exploit_strategy, binary_functions, binary_strings, binary_fmtstr, binary_heap, binary_angr, binary_fuzz
    """
    from modules.bin_wrapper import analyze as _ba
    return _run_bin_binary(_ba, binary_path)

@mcp.tool()
def binary_summary(binary_path: str) -> str:
    """
    Get a concise markdown summary of a binary's security posture and exploitability. Optimized for AI consumption — includes mitigation status, vulnerability list, and exploitation strategy.
    Phase: Binary Exploitation
    Parameters:
      binary_path: Path to the binary file (str)
    Related: binary_check, binary_analyze, binary_vulns, binary_checksec, binary_gadgets, binary_exploit_strategy, binary_functions, binary_strings, binary_fmtstr, binary_heap, binary_angr, binary_fuzz
    """
    from modules.bin_wrapper import summary as _bs
    return _run_bin_binary(_bs, binary_path)

@mcp.tool()
def binary_vulns(binary_path: str) -> str:
    """
    Scan a binary for common vulnerability patterns: dangerous functions (gets/strcpy/system), format strings, command injection, insecure APIs, packer detection, anti-debug, and suspicious strings.
    Phase: Binary Exploitation
    Parameters:
      binary_path: Path to the binary file (str)
    Related: binary_check, binary_analyze, binary_summary, binary_checksec, binary_gadgets, binary_exploit_strategy, binary_functions, binary_strings, binary_fmtstr, binary_heap, binary_angr, binary_fuzz
    """
    from modules.bin_wrapper import vulns as _bv
    return _run_bin_binary(_bv, binary_path)

@mcp.tool()
def binary_checksec(binary_path: str) -> str:
    """
    Check binary security mitigations: NX (no-execute), Stack Canary, RELRO (GOT protection), PIE (position-independent), and PE-specific (ASLR, CFG, SafeSEH).
    Phase: Binary Exploitation
    Parameters:
      binary_path: Path to the binary file (str)
    Related: binary_check, binary_analyze, binary_summary, binary_vulns, binary_gadgets, binary_exploit_strategy, binary_functions, binary_strings, binary_fmtstr, binary_heap, binary_angr, binary_fuzz
    """
    from modules.bin_wrapper import checksec as _bc
    return _run_bin_binary(_bc, binary_path)

@mcp.tool()
def binary_gadgets(binary_path: str) -> str:
    """
    Search for ROP gadgets in a binary using ropper or ROPgadget. Returns categorized gadgets: pop rdi/ret, pop rsi/ret, syscall, ret, etc.
    Phase: Binary Exploitation
    Parameters:
      binary_path: Path to the binary file (str)
    Related: binary_check, binary_analyze, binary_summary, binary_vulns, binary_checksec, binary_exploit_strategy, binary_functions, binary_strings, binary_fmtstr, binary_heap, binary_angr, binary_fuzz
    """
    from modules.bin_wrapper import gadgets as _bg
    return _run_bin_binary(_bg, binary_path)

@mcp.tool()
def binary_exploit_strategy(binary_path: str) -> str:
    """
    Generate an exploitation strategy for a binary. Scores exploitability (0-100), recommends techniques (shellcode injection, ret2libc, ROP chain), and lists available gadgets.
    Phase: Binary Exploitation
    Parameters:
      binary_path: Path to the binary file (str)
    Related: binary_check, binary_analyze, binary_summary, binary_vulns, binary_checksec, binary_gadgets, binary_functions, binary_strings, binary_fmtstr, binary_heap, binary_angr, binary_fuzz
    """
    from modules.bin_wrapper import exploit as _be
    return _run_bin_binary(_be, binary_path)

@mcp.tool()
def binary_functions(binary_path: str) -> str:
    """
    List all exported and visible functions in a binary using nm/objdump/pwntools.
    Phase: Binary Exploitation
    Parameters:
      binary_path: Path to the binary file (str)
    Related: binary_check, binary_analyze, binary_summary, binary_vulns, binary_checksec, binary_gadgets, binary_exploit_strategy, binary_strings, binary_fmtstr, binary_heap, binary_angr, binary_fuzz
    """
    from modules.bin_wrapper import functions as _bf
    return _run_bin_binary(_bf, binary_path)

@mcp.tool()
def binary_strings(binary_path: str) -> str:
    """
    Extract printable strings from a binary. Useful for finding hardcoded paths, credentials, format strings, and suspicious keywords.
    Phase: Binary Exploitation
    Parameters:
      binary_path: Path to the binary file (str)
    Related: binary_check, binary_analyze, binary_summary, binary_vulns, binary_checksec, binary_gadgets, binary_exploit_strategy, binary_functions, binary_fmtstr, binary_heap, binary_angr, binary_fuzz
    """
    from modules.bin_wrapper import strings as _bs
    return _run_bin_binary(_bs, binary_path)

@mcp.tool()
def binary_fmtstr(binary_path: str) -> str:
    """
    Analyze format string vulnerabilities. Reports detected printf-family imports, read/write primitives (%p/%n/%hn/%hhn), offset finding guide, and exploitation techniques per mitigation level.
    Phase: Binary Exploitation
    Parameters:
      binary_path: Path to the binary file (str)
    Related: binary_check, binary_analyze, binary_summary, binary_vulns, binary_checksec, binary_gadgets, binary_exploit_strategy, binary_functions, binary_strings, binary_heap, binary_angr, binary_fuzz
    """
    from modules.bin_wrapper import fmtstr as _bf
    return _run_bin_binary(_bf, binary_path)

@mcp.tool()
def binary_heap(binary_path: str) -> str:
    """
    Analyze heap usage and suggest exploitation techniques. Detects allocator (glibc ptmalloc/Windows Heap), identifies heap functions, and provides technique guides (tcache poisoning, fastbin, unsafe unlink, House of Force).
    Phase: Binary Exploitation
    Parameters:
      binary_path: Path to the binary file (str)
    Related: binary_check, binary_analyze, binary_summary, binary_vulns, binary_checksec, binary_gadgets, binary_exploit_strategy, binary_functions, binary_strings, binary_fmtstr, binary_angr, binary_fuzz
    """
    from modules.bin_wrapper import heap as _bh
    return _run_bin_binary(_bh, binary_path)

@mcp.tool()
def binary_angr(binary_path: str, target_func: str = "system") -> str:
    """
    Run angr symbolic execution on a binary to find execution paths. Optionally find path to a target function (default: system). Returns function list, CFG stats, and path info.
    Phase: Binary Exploitation
    Parameters:
      binary_path: Path to the binary file (str)
      target_func: Target function for path finding (str) [default: 'system']
    Related: binary_check, binary_analyze, binary_summary, binary_vulns, binary_checksec, binary_gadgets, binary_exploit_strategy, binary_functions, binary_strings, binary_fmtstr, binary_heap, binary_fuzz
    """
    from modules.bin_wrapper import angr as _ba
    return _run_bin_kwargs(_ba, binary_path, target_func=target_func)

@mcp.tool()
def binary_fuzz(binary_path: str) -> str:
    """
    Generate a fuzzing harness for a binary. Creates AFL++ harness.c and Python fuzz.py in a fuzz_harness/ directory with instructions.
    Phase: Binary Exploitation
    Parameters:
      binary_path: Path to the binary file (str)
    Related: binary_check, binary_analyze, binary_summary, binary_vulns, binary_checksec, binary_gadgets, binary_exploit_strategy, binary_functions, binary_strings, binary_fmtstr, binary_heap, binary_angr
    """
    from modules.bin_wrapper import fuzz as _bf
    return _run_bin_binary(_bf, binary_path)

@mcp.tool()
def binary_cyclic(length: int) -> str:
    """
    Generate a de Bruijn cyclic pattern of the given length for overflow offset discovery.
    Phase: Binary Exploitation
    Parameters:
      length: Length of cyclic pattern (int)
    Related: binary_check, binary_analyze, binary_summary, binary_vulns, binary_checksec, binary_gadgets, binary_exploit_strategy, binary_functions, binary_strings, binary_fmtstr, binary_heap, binary_angr
    """
    from modules.bin_wrapper import cyclic as _bc
    return _run_bin_kwargs(_bc, length=length)

@mcp.tool()
def binary_pattern_offset(value: str) -> str:
    """
    Find the offset of a value (hex like 0x61616171 or ASCII) in the cyclic pattern. Used after a crash to determine buffer overflow offset.
    Phase: Binary Exploitation
    Parameters:
      value: Value to set (str)
    Related: binary_check, binary_analyze, binary_summary, binary_vulns, binary_checksec, binary_gadgets, binary_exploit_strategy, binary_functions, binary_strings, binary_fmtstr, binary_heap, binary_angr
    """
    from modules.bin_wrapper import pattern_offset as _bp
    return _run_bin_kwargs(_bp, value=value)


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
    Parameters:
      case_id: Case ID to scope results (str)
      body: Note body text (str)
      tags: Comma-separated tags (str) [default: '']
    Related: case_notes_list, case_info, case_list
    """
    from modules.case_manager import CaseManager
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
    Parameters:
      case_id: Case ID to scope results (str)
    Related: case_notes_add, case_info, case_list
    """
    from modules.case_manager import CaseManager
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
    Parameters:
      case_id: Case ID to scope results (str)
    Related: case_evidence_add, case_evidence_verify, case_info
    """
    from modules.case_manager import CaseManager
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
    Parameters:
      case_id: Case ID to scope results (str)
      filepath: Path to file on disk (str)
      category: Evidence category (str) [default: 'evidence']
      description: Evidence description (str) [default: '']
    Related: case_evidence_add, case_evidence_list, case_evidence_verify, case_info
    """
    from modules.case_manager import CaseManager
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
                  case_id: str = "") -> str:
    """
    List findings across all cases, optionally filtered by severity, search text, or case.
    Phase: Case Management
    Parameters:
      severity: Filter by severity (critical/high/medium/low/info) (str) [default: '']
      search: Free text search in title/cve/description (str) [default: '']
      case_id: Limit to a specific case ID (str) [default: '']
    Related: findings_stats, case_finding_add, case_finding_detail, case_finding_update, case_findings_bulk_update, case_findings_bulk_delete
    """
    from modules.case_manager import CaseManager
    from modules.findings_db import FindingsDB
    from pathlib import Path
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
        ctitle = c.get("client", cid)
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
                    continue
            f["_case_id"] = cid
            f["_case_title"] = ctitle
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
    Parameters:
      (none)
    Related: findings_list, case_findings_list, case_info
    """
    from modules.case_manager import CaseManager
    from modules.findings_db import FindingsDB
    cm = CaseManager()
    cases = _run(cm.list_cases)
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    status_counts = {}
    total = 0
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
    lines = [f"Findings Stats ({total} total):"]
    lines.append("  By severity: " + ", ".join(f"{k}={v}" for k, v in sorted(severity_counts.items()) if v))
    lines.append("  By status: " + ", ".join(f"{k}={v}" for k, v in sorted(status_counts.items())))
    return "\n".join(lines)


@mcp.tool()
def case_finding_detail(case_id: str, finding_id: str) -> str:
    """
    Get full detail of a single finding.
    Phase: Case Management
    Parameters:
      case_id: Case ID containing the finding (str)
      finding_id: Finding ID to retrieve (str)
    Related: case_finding_add, case_finding_update, findings_list, case_info
    """
    from modules.case_manager import CaseManager
    from modules.findings_db import FindingsDB
    cm = CaseManager()
    info = _run(cm.info, case_id)
    if not info:
        return "Case not found"
    db = FindingsDB(cm._case_path(case_id))
    finding = _run(db.get, finding_id)
    if not finding:
        return "Finding not found"
    lines = [f"Finding: {finding.get('title','')}"]
    for k in ("id", "severity", "status", "cve", "cwe", "source", "created", "updated"):
        v = finding.get(k, "")
        if v:
            lines.append(f"  {k}: {v}")
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
    Parameters:
      case_id: Case containing the finding (str)
      finding_id: ID of finding to delete (str)
    Related: case_finding_add, case_finding_update, case_finding_detail, findings_list
    """
    from modules.case_manager import CaseManager
    from modules.findings_db import FindingsDB
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
                              poc: str = "") -> str:
    """
    Bulk update multiple findings in a case. Provide comma-separated finding_ids.
    Only non-empty fields are updated.
    Phase: Case Management
    Parameters:
      case_id: Case containing the findings (str)
      finding_ids: Comma-separated finding IDs (str)
      status: New status (unvalidated/validated/remediated/closed_other) (str) [default: '']
      severity: New severity (critical/high/medium/low/info) (str) [default: '']
      title: New title (str) [default: '']
      description: New description (str) [default: '']
      remediation: New remediation (str) [default: '']
      impact: New impact (str) [default: '']
      poc: New PoC (str) [default: '']
    Related: case_finding_update, case_findings_bulk_delete, findings_list
    """
    from modules.case_manager import CaseManager
    from modules.findings_db import FindingsDB
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
    Parameters:
      case_id: Case containing the findings (str)
      finding_ids: Comma-separated finding IDs to delete (str)
    Related: case_finding_delete, case_findings_bulk_update, findings_list
    """
    from modules.case_manager import CaseManager
    from modules.findings_db import FindingsDB
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
                        status: str = "") -> str:
    """
    Create a new finding in a case. Returns the created finding summary.
    Phase: Case Management
    Parameters:
      case_id: Case to add the finding to (str)
      title: Finding title (str)
      severity: Severity (critical/high/medium/low/info) (str) [default: 'medium']
      description: Description of vulnerability (str) [default: '']
      remediation: Remediation steps (str) [default: '']
      source: Source of finding (str) [default: 'manual']
      cve: CVE identifier (str) [default: '']
      cwe: CWE identifier (str) [default: '']
      impact: Business/technical impact (str) [default: '']
      poc: Proof of concept (str) [default: '']
      status: Initial status (unvalidated/validated/remediated/closed_other) (str) [default: '']
    Related: case_finding_detail, case_finding_update, case_finding_delete, findings_list
    """
    from modules.case_manager import CaseManager
    from modules.findings_db import FindingsDB
    cm = CaseManager()
    info = _run(cm.info, case_id)
    if not info:
        return "Case not found"
    db = FindingsDB(cm._case_path(case_id))
    finding = _run(db.add, title=title, severity=severity, description=description,
                   remediation=remediation, source=source, cve=cve, cwe=cwe,
                   impact=impact, poc=poc)
    if status and status != "unvalidated":
        _run(db.update, finding["id"], status=status)
    return f"Finding created: {finding.get('id','')} ({severity}) — {title[:60]}"


# ---------------------------------------------------------------------------
# Prompts Library
# ---------------------------------------------------------------------------
@mcp.tool()
def prompts_list() -> str:
    """
    List all available prompt templates.
    Phase: Case Management
    Parameters:
      (none)
    Related: prompts_get
    """
    from pathlib import Path
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
    Parameters:
      name: Prompt name (without .yaml extension) (str)
    Related: prompts_list
    """
    from pathlib import Path
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
    Parameters:
      (none)
    Related: flashcards_deck
    """
    from pathlib import Path
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
    Parameters:
      name: Deck name (without .yaml extension) (str)
    Related: flashcards_list
    """
    from pathlib import Path
    import yaml
    path = _HERE / "flashcards" / f"{name}.yaml"
    if not path.is_file():
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
    Parameters:
      case_id: Case ID containing the task (str)
      task_id: Task ID to mark done (str)
    Related: case_task_add, case_task_list, case_task_delete
    """
    from modules.case_manager import CaseManager
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
    Parameters:
      case_id: Case containing the task (str)
      task_id: Task ID to delete (str)
    Related: case_task_add, case_task_list, case_task_toggle
    """
    from modules.case_manager import CaseManager
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
    Parameters:
      case_id: Case to modify (str)
      index: Index of strength to remove (0-based) (int)
    Related: case_strength_add, case_strength_list, case_weakness_add, case_weakness_list
    """
    from modules.case_manager import CaseManager
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
    Parameters:
      case_id: Case to modify (str)
      index: Index of weakness to remove (0-based) (int)
    Related: case_weakness_add, case_weakness_list, case_strength_add, case_strength_list
    """
    from modules.case_manager import CaseManager
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
    Parameters:
      case_id: Case to browse (str)
      path: Subdirectory path within the case (str) [default: '']
    Related: case_files_preview, case_info
    """
    from modules.case_manager import CaseManager
    from pathlib import Path
    cm = CaseManager()
    info = _run(cm.info, case_id)
    if not info:
        return "Case not found"
    case_dir = cm._case_path(case_id)
    target = (case_dir / path).resolve()
    if not str(target).startswith(str(case_dir.resolve()) + "\\") and target != case_dir:
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
    Parameters:
      case_id: Case containing the file (str)
      file_path: Relative path within the case (e.g. "scans/scan.nmap") (str)
      max_chars: Maximum characters to return (int) [default: 2000]
    Related: case_files_list, case_info
    """
    from modules.case_manager import CaseManager
    from pathlib import Path
    cm = CaseManager()
    info = _run(cm.info, case_id)
    if not info:
        return "Case not found"
    case_dir = cm._case_path(case_id)
    target = (case_dir / file_path).resolve()
    if not str(target).startswith(str(case_dir.resolve()) + "\\"):
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


# ---------------------------------------------------------------------------
# Dashboard Stats
# ---------------------------------------------------------------------------
@mcp.tool()
def dashboard_stats() -> str:
    """
    Get aggregated dashboard statistics across all cases and findings.
    Phase: Case Management
    Parameters:
      (none)
    Related: findings_stats, case_list, projects_board_data
    """
    from modules.case_manager import CaseManager
    from modules.findings_db import FindingsDB
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
    Parameters:
      (none)
    Related: projects_board_update, dashboard_stats, case_list
    """
    from modules.case_manager import CaseManager
    from modules.findings_db import FindingsDB
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
    Parameters:
      case_id: Case to update (str)
      status: New status (open/pending/on-hold/closed) (str)
    Related: projects_board_data, case_update_meta
    """
    from modules.case_manager import CaseManager
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
    Parameters:
      (none)
    Related: job_status, job_create, job_cancel
    """
    from modules.job_manager import get_job_manager
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
    Parameters:
      job_id: Job ID (str)
    Related: jobs_list, job_create, job_cancel
    """
    from modules.job_manager import get_job_manager
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
               total_steps: int = 100) -> str:
    """
    Create a new job in the job queue.
    Phase: Case Management
    Parameters:
      job_type: Type of job (str) [default: 'custom']
      title: Human-readable title (str) [default: 'Untitled Job']
      total_steps: Total steps for progress tracking (int) [default: 100]
    Related: jobs_list, job_status, job_cancel
    """
    from modules.job_manager import get_job_manager
    jm = get_job_manager()
    job_id = _run(jm.create, job_type, title, total_steps)
    return f"Job created: {job_id}"


@mcp.tool()
def job_cancel(job_id: str) -> str:
    """
    Cancel a running job.
    Phase: Case Management
    Parameters:
      job_id: Job ID to cancel (str)
    Related: jobs_list, job_status, job_create
    """
    from modules.job_manager import get_job_manager
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
    Parameters:
      customer_id: Filter by customer (str) [default: '']
      kind: Filter by asset kind (host/domain/cidr/url/email) (str) [default: '']
      tag: Filter by tag (str) [default: '']
      search: Free text search (str) [default: '']
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
    Parameters:
      kind: Asset kind (host/domain/cidr/url/email) (str)
      address: IP address or domain (str)
      customer_id: Associate with a customer (str) [default: '']
      label: Human-readable label (str) [default: '']
      fqdn: Fully qualified domain name (str) [default: '']
      os_info: Operating system info (str) [default: '']
      tags: Comma-separated tags (str) [default: '']
      notes: Notes about the asset (str) [default: '']
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
    Parameters:
      asset_id: Asset ID to delete (str)
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
    Parameters:
      (none)
    Related: assets_list, assets_create, assets_delete
    """
    from modules.asset_tracker import AssetTracker
    stats = _run(AssetTracker().get_stats)
    if not stats:
        return "No assets."
    lines = [f"Asset Stats:"]
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
    Parameters:
      xml: Nmap XML content (str)
      customer_id: Associate assets with a customer (str) [default: '']
      case_id: Associate assets with a case (str) [default: '']
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
    Parameters:
      (none)
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
    Parameters:
      name: Customer name (str)
      notes: Notes about customer (str) [default: '']
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
    Parameters:
      customer_id: Customer ID to delete (str)
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
    List credentials in the asset inventory, optionally filtered by asset.
    Phase: Utility / Infrastructure
    Parameters:
      asset_id: Filter by asset (str) [default: '']
    Related: credentials_create, credentials_get, credentials_delete, assets_list
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
    Store a credential for an asset.
    Phase: Utility / Infrastructure
    Parameters:
      asset_id: Asset to associate credential with (str)
      kind: Credential type (password/key/certificate/token) (str)
      username: Username (str)
      secret: Password/key/secret value (str)
      service: Service name (str) [default: '']
      url: URL (str) [default: '']
      notes: Notes (str) [default: '']
    Related: credentials_list, credentials_get, credentials_delete, assets_list
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
    Get credential details (optionally decrypt the secret).
    Phase: Utility / Infrastructure
    Parameters:
      cred_id: Credential ID (str)
      decrypt: Set to True to decrypt and show the secret (bool) [default: false]
    Related: credentials_list, credentials_create, credentials_delete
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
    Delete a credential.
    Phase: Utility / Infrastructure
    Parameters:
      cred_id: Credential ID to delete (str)
    Related: credentials_list, credentials_create, credentials_get
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
    Parameters:
      case_id: Case to analyze (str)
    Related: case_info, case_files_list, nmap_initial_tcp, nmap_full_tcp
    """
    from modules.case_manager import CaseManager
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
    Parameters:
      (none)
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
    Parameters:
      session_id: Session ID (str) [default: '']
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
    lines = [f"WiFi Monitor Status:"]
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
    Parameters:
      session_id: Session ID (str) [default: '']
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
    Parameters:
      (none)
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


# ---------------------------------------------------------------------------
# DNS Monitor
# ---------------------------------------------------------------------------
@mcp.tool()
def dns_resolve(domain: str, types: str = "") -> str:
    """
    Resolve DNS records for a domain.
    Phase: DNS / Network
    Parameters:
      domain: Domain name to resolve (str)
      types: Comma-separated record types (A,AAAA,MX,NS,TXT,CNAME) (str) [default: '']
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
    Parameters:
      (none)
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
    Parameters:
      domain: Domain name to monitor (str)
      record_types: Comma-separated record types (str) [default: '']
      interval: Polling interval in seconds (int) [default: 300]
      duration: Total duration in seconds (0 = indefinite) (int) [default: 0]
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
    Parameters:
      domain: Domain name to stop monitoring (str)
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
    Parameters:
      domain: Domain name (str)
      limit: Maximum records to return (int) [default: 100]
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




def _fmt(r: dict, fmt: str = "default") -> str:
    if r.get("error"):
        return f"Error: {r['error']}"
    if fmt == "nuclei":
        cnt = r.get("finding_count", 0)
        out = r.get("output_file", "")
        return f"Nuclei scan complete: {cnt} findings\nOutput: {out}"
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


def main():
    mcp.run()


if __name__ == "__main__":
    main()
