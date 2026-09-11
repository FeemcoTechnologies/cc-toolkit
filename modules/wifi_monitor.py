import logging
"""WiFi monitoring engine — runs airodump-ng, parses CSV live, tracks time-series data."""

import csv
import datetime
import json
import os
import re
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, Optional

from .config import CC_DIR
logger = logging.getLogger(__name__)


class AirodumpCSVParser:
    """Parse airodump-ng CSV output into structured AP and client lists."""

    @staticmethod
    def parse(csv_text: str) -> dict:
        aps = []
        clients = []
        lines = csv_text.strip().splitlines()
        if not lines:
            return {"aps": aps, "clients": clients}
        try:
            reader = csv.reader(lines)
            rows = list(reader)
        except Exception:
            return {"aps": aps, "clients": clients}

        # Find the separator line (empty or "Station MAC" boundary)
        sep_idx = None
        for i, row in enumerate(rows):
            if not row or (len(row) > 0 and row[0].strip().upper() == "STATION MAC"):
                sep_idx = i
                break

        ap_rows = rows[:sep_idx] if sep_idx is not None else rows
        client_rows = rows[sep_idx + 1:] if sep_idx is not None else []

        # Parse AP rows (skip header)
        for row in ap_rows[1:]:
            if len(row) < 14:
                continue
            try:
                bssid = row[0].strip()
                if not bssid or bssid.count(":") < 5:
                    continue
                power_raw = row[8].strip() if len(row) > 8 else ""
                power = int(power_raw) if power_raw.lstrip("-").isdigit() else None
                beacon_raw = row[9].strip() if len(row) > 9 else "0"
                beacons = int(beacon_raw) if beacon_raw.isdigit() else 0
                channel = row[3].strip() if len(row) > 3 else "?"
                enc = row[5].strip() if len(row) > 5 else ""
                cipher = row[6].strip() if len(row) > 6 else ""
                auth = row[7].strip() if len(row) > 7 else ""
                essid = row[13].strip() if len(row) > 13 else ""
                # Extract WPS flag from ESSID or extra columns
                has_wps = "WPS" in essid.upper() or "WPS" in str(row)
                aps.append({
                    "bssid": bssid,
                    "essid": essid or "(hidden)",
                    "channel": channel,
                    "signal": power,
                    "encryption": enc,
                    "cipher": cipher,
                    "auth": auth,
                    "beacons": beacons,
                    "wps": has_wps,
                    "first_seen": row[1].strip() if len(row) > 1 else "",
                    "last_seen": row[2].strip() if len(row) > 2 else "",
                })
            except (ValueError, IndexError):
                continue

        # Parse client rows
        for row in client_rows:
            if len(row) < 7:
                continue
            try:
                mac = row[0].strip()
                if not mac or mac.count(":") < 5:
                    continue
                power_raw = row[3].strip() if len(row) > 3 else ""
                power = int(power_raw) if power_raw.lstrip("-").isdigit() else None
                packets_raw = row[4].strip() if len(row) > 4 else "0"
                packets = int(packets_raw) if packets_raw.isdigit() else 0
                bssid = row[5].strip() if len(row) > 5 else ""
                probes_raw = row[6].strip() if len(row) > 6 else ""
                probes = [p.strip() for p in probes_raw.split(",") if p.strip()] if probes_raw else []
                clients.append({
                    "mac": mac,
                    "signal": power,
                    "packets": packets,
                    "bssid": bssid if bssid and bssid != "(not associated)" else "",
                    "probed_essids": probes,
                    "first_seen": row[1].strip() if len(row) > 1 else "",
                    "last_seen": row[2].strip() if len(row) > 2 else "",
                })
            except (ValueError, IndexError):
                continue

        return {"aps": aps, "clients": clients}


class PcapAnalyzer:
    """Parse PCAP for EAPOL handshakes, PMKID, EAP identities."""

    # Cache for validated field names (version-specific)
    _EAPOL_KEY_INFO_FIELDS = ["eapol.key_info", "eapol.keydes.key_info"]
    _EAPOL_NONCE_FIELDS = ["eapol.wpa.nonce", "eapol.keydes.nonce"]
    _RSN_IE_FIELDS = ["wlan.tag.48", "wlan_rsn.ie", "wlan.rsn.ie"]

    @staticmethod
    def find_handshakes(pcap_path: Path) -> list:
        """Find 4-way handshake completions in PCAP using hcxpcapngtool or tshark."""
        results = []
        if not pcap_path.exists():
            return results

        # Prefer hcxpcapngtool (standard on Kali, detects both PMKID + handshakes)
        hs = PcapAnalyzer._find_handshakes_hcxpcapngtool(pcap_path)
        if hs:
            return hs

        # Fall back to tshark
        tshark = PcapAnalyzer._find_tshark()
        if not tshark:
            return results

        try:
            key_info_field = PcapAnalyzer._first_valid_field(
                tshark, pcap_path, PcapAnalyzer._EAPOL_KEY_INFO_FIELDS)
            nonce_field = PcapAnalyzer._first_valid_field(
                tshark, pcap_path, PcapAnalyzer._EAPOL_NONCE_FIELDS)
            if not key_info_field:
                return results

            cmd = [
                tshark, "-r", str(pcap_path),
                "-Y", "eapol",
                "-T", "fields",
                "-e", "frame.time_epoch",
                "-e", "wlan.sa",
                "-e", "wlan.da",
                "-e", key_info_field,
            ]
            if nonce_field:
                cmd += ["-e", nonce_field]
            cmd += ["-E", "separator=|"]

            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            results = PcapAnalyzer._detect_4way_handshakes(r.stdout, bool(nonce_field))
        except Exception:

            logger.debug("Exception in wifi_monitor.py", exc_info=True)
        return results

    @staticmethod
    def _find_handshakes_hcxpcapngtool(pcap_path: Path) -> list:
        """Use hcxpcapngtool to extract handshake info."""
        bssid_pat = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
        try:
            r = subprocess.run(
                ["hcxpcapngtool", "-o", "/dev/stdout", str(pcap_path)],
                capture_output=True, text=True, timeout=30)
            # hcxpcapngtool outputs hashcat lines; count unique AP BSSIDs
            aps = set()
            for line in r.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("!"):
                    continue
                # Hashcat PMKID format: pmkid_hash*bssid*essid
                # Hashcat EAPOL format: hash*bssid*station*essid
                parts = line.split("*")
                if len(parts) >= 2 and bssid_pat.match(parts[1]):
                    aps.add(parts[1])
            if aps:
                return [{"ap": ap, "client": "", "ts": "", "messages": 0}
                        for ap in sorted(aps)]
        except FileNotFoundError:
            pass
        except Exception:

            logger.debug("Exception in wifi_monitor.py", exc_info=True)
        return []

    @staticmethod
    def find_pmkid(pcap_path: Path) -> list:
        """Find PMKID using hcxpcapngtool or tshark."""
        bssid_pat = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
        results = []

        # Prefer hcxpcapngtool
        try:
            r = subprocess.run(
                ["hcxpcapngtool", "-o", "/dev/stdout", str(pcap_path)],
                capture_output=True, text=True, timeout=30)
            for line in r.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("!"):
                    continue
                # PMKID hashcat mode 16800: pmkid_hash*bssid*essid
                parts = line.split("*")
                if len(parts) >= 2 and bssid_pat.match(parts[1]) and len(parts[0]) == 64:
                    results.append({
                        "ts": "",
                        "ap": parts[1],
                        "client": parts[2] if len(parts) > 2 else "",
                        "pmkid": parts[0][:16],
                    })
            if results:
                return results
        except FileNotFoundError:
            pass
        except Exception:

            logger.debug("Exception in wifi_monitor.py", exc_info=True)

        # Fallback: tshark — extract RSN IE from beacons
        tshark = PcapAnalyzer._find_tshark()
        if not tshark:
            return results

        rsn_field = PcapAnalyzer._first_valid_field(
            tshark, pcap_path, PcapAnalyzer._RSN_IE_FIELDS)
        if not rsn_field:
            return results

        try:
            cmd = [
                tshark, "-r", str(pcap_path),
                "-Y", f"wlan.fc.type_subtype == 0x08 && {rsn_field}",
                "-T", "fields",
                "-e", "frame.time_epoch",
                "-e", "wlan.sa",
                "-e", rsn_field,
                "-E", "separator=|",
            ]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            for line in r.stdout.strip().splitlines():
                if not line.strip():
                    continue
                parts = line.split("|")
                if len(parts) >= 3 and parts[2].strip():
                    results.append({
                        "ts": parts[0],
                        "ap": parts[1],
                        "client": "",
                        "rsn_ie": parts[2][:60],
                    })
        except Exception:

            logger.debug("Exception in wifi_monitor.py", exc_info=True)
        return results

    @staticmethod
    def find_eap_identities(pcap_path: Path) -> list:
        """Find EAP identity responses using hcxpcapngtool or tshark."""
        mac_pat = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
        results = []

        # Prefer hcxpcapngtool
        try:
            r = subprocess.run(
                ["hcxpcapngtool", "-E", "/dev/stdout", str(pcap_path)],
                capture_output=True, text=True, timeout=30)
            for line in r.stdout.splitlines():
                line = line.strip()
                if not line or ":" not in line:
                    continue
                # Format: MAC_ADDRESS:identity
                mac, _, identity = line.partition(":")
                mac = mac.strip()
                if mac and identity and mac_pat.match(mac):
                    results.append({
                        "ts": "",
                        "mac": mac,
                        "identity": identity.strip(),
                    })
            if results:
                return results
        except FileNotFoundError:
            pass
        except Exception:

            logger.debug("Exception in wifi_monitor.py", exc_info=True)

        # Fallback: tshark
        tshark = PcapAnalyzer._find_tshark()
        if not tshark:
            return results

        try:
            cmd = [
                tshark, "-r", str(pcap_path),
                "-Y", "eap.code == 2 && eap.type == 1",
                "-T", "fields",
                "-e", "frame.time_epoch",
                "-e", "wlan.sa",
                "-e", "eap.identity",
                "-E", "separator=|",
            ]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            for line in r.stdout.strip().splitlines():
                if not line.strip():
                    continue
                parts = line.split("|")
                if len(parts) >= 3 and parts[2].strip():
                    results.append({
                        "ts": parts[0],
                        "mac": parts[1],
                        "identity": parts[2].strip(),
                    })
        except Exception:

            logger.debug("Exception in wifi_monitor.py", exc_info=True)
        return results

    @staticmethod
    def find_packet_strings(pcap_path: Path) -> list:
        """Extract printable strings from unencrypted data frames (HTTP, DHCP, ARP, DNS)."""
        results = []
        if not pcap_path.exists():
            return results
        tshark = PcapAnalyzer._find_tshark()
        if not tshark:
            # Fallback: use strings command directly
            try:
                r = subprocess.run(["strings", str(pcap_path)],
                                   capture_output=True, text=True, timeout=15)
                seen = set()
                for line in r.stdout.splitlines():
                    line = line.strip()
                    if len(line) >= 6 and line.isprintable() and line not in seen:
                        seen.add(line)
                        results.append({"src": "strings", "text": line})
            except Exception:

                logger.debug("Exception in wifi_monitor.py", exc_info=True)
            return results

        try:
            # 1. DNS queries
            cmd = [tshark, "-r", str(pcap_path),
                   "-Y", "dns.flags.response == 0",
                   "-T", "fields",
                   "-e", "frame.time_epoch",
                   "-e", "ip.src",
                   "-e", "dns.qry.name",
                   "-E", "separator=|"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            for line in r.stdout.strip().splitlines():
                if not line.strip():
                    continue
                parts = line.split("|")
                if len(parts) >= 3 and parts[2].strip():
                    results.append({
                        "ts": parts[0],
                        "src": "dns",
                        "text": f"DNS {parts[1]} -> {parts[2]}",
                    })

            # 2. DHCP hostnames and vendor info
            cmd = [tshark, "-r", str(pcap_path),
                   "-Y", "dhcp",
                   "-T", "fields",
                   "-e", "frame.time_epoch",
                   "-e", "ip.src",
                   "-e", "dhcp.option.hostname",
                   "-e", "dhcp.option.vendor_id",
                   "-E", "separator=|"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            for line in r.stdout.strip().splitlines():
                if not line.strip():
                    continue
                parts = line.split("|")
                text_parts = []
                if len(parts) >= 3 and parts[2].strip():
                    text_parts.append(f"hostname={parts[2].strip()}")
                if len(parts) >= 4 and parts[3].strip():
                    text_parts.append(f"vendor={parts[3].strip()}")
                if text_parts:
                    results.append({
                        "ts": parts[0],
                        "src": "dhcp",
                        "text": f"DHCP {parts[1] if len(parts) > 1 else '?'} {' '.join(text_parts)}",
                    })

            # 3. ARP requests/replies
            cmd = [tshark, "-r", str(pcap_path),
                   "-Y", "arp",
                   "-T", "fields",
                   "-e", "frame.time_epoch",
                   "-e", "arp.src.proto_ipv4",
                   "-e", "arp.src.hw_mac",
                   "-e", "arp.dst.proto_ipv4",
                   "-E", "separator=|"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            for line in r.stdout.strip().splitlines():
                if not line.strip():
                    continue
                parts = line.split("|")
                if len(parts) >= 3 and parts[1].strip():
                    results.append({
                        "ts": parts[0],
                        "src": "arp",
                        "text": f"ARP {parts[1]} ({parts[2]}) -> {parts[3] if len(parts) > 3 else '?'}",
                    })

            # 4. HTTP requests (Host + URI)
            cmd = [tshark, "-r", str(pcap_path),
                   "-Y", "http.request",
                   "-T", "fields",
                   "-e", "frame.time_epoch",
                   "-e", "ip.src",
                   "-e", "http.host",
                   "-e", "http.request.uri",
                   "-e", "http.user_agent",
                   "-E", "separator=|"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            for line in r.stdout.strip().splitlines():
                if not line.strip():
                    continue
                parts = line.split("|")
                if len(parts) >= 4 and parts[3].strip():
                    host = parts[2] if len(parts) > 2 else ""
                    uri = parts[3]
                    ua = parts[4] if len(parts) > 4 else ""
                    text = f"HTTP {parts[1]} -> http://{host}{uri}"
                    if ua:
                        text += f" [{ua[:60]}]"
                    results.append({
                        "ts": parts[0],
                        "src": "http",
                        "text": text,
                    })
        except Exception:

            logger.debug("Exception in wifi_monitor.py", exc_info=True)

        # Deduplicate by text content
        seen = set()
        deduped = []
        for r in results:
            if r["text"] not in seen:
                seen.add(r["text"])
                deduped.append(r)
        return deduped

    @staticmethod
    def _find_tshark() -> Optional[str]:
        for candidate in ["tshark", "/usr/bin/tshark"]:
            if os.path.exists(candidate):
                return candidate
        for p in ["/usr/bin/tshark", "/usr/local/bin/tshark"]:
            if os.path.exists(p):
                return p
        return None

    @staticmethod
    def _first_valid_field(tshark: str, pcap_path: Path, candidates: list) -> Optional[str]:
        """Try each field name against a real pcap, return first that works."""
        for field in candidates:
            try:
                cmd = [tshark, "-r", str(pcap_path),
                       "-T", "fields", "-e", field,
                       "-c", "1", "-E", "separator=|"]
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if r.returncode == 0 and "isn't valid" not in r.stderr:
                    return field
            except Exception:
                continue
        return None

    @staticmethod
    def _detect_4way_handshakes(tshark_output: str, has_nonce: bool = False) -> list:
        """Parse tshark EAPOL output and detect completed 4-way handshakes."""
        from collections import defaultdict

        pairs: Dict = defaultdict(lambda: {"messages": set(), "ts": ""})

        for line in tshark_output.strip().splitlines():
            if not line.strip():
                continue
            parts = line.split("|")
            min_parts = 5 if has_nonce else 4
            if len(parts) < min_parts:
                continue
            ts = parts[0]
            sa = parts[1]
            da = parts[2]
            key_info = parts[3]
            pair_key = tuple(sorted([sa, da]))
            pairs[pair_key]["messages"].add(key_info.strip())
            if not pairs[pair_key]["ts"] or ts > pairs[pair_key]["ts"]:
                pairs[pair_key]["ts"] = ts

        results = []
        for (sa, da), data in pairs.items():
            if len(data["messages"]) >= 2:
                results.append({
                    "ap": sa,
                    "client": da,
                    "ts": data["ts"],
                    "messages": len(data["messages"]),
                })
        return results


class WifiMonitorSession:
    """Manages a single airodump-ng monitoring session with live data tracking."""

    SESSIONS_DIR = CC_DIR / "data" / "wifi_sessions"

    def __init__(self, session_id: str, iface: str, band: str = "abg",
                 target_bssid: str = "", target_essid: str = ""):
        self.session_id = session_id
        self.iface = iface
        self.band = band
        self.target_bssid = target_bssid
        self.target_essid = target_essid
        self.status = "stopped"
        self.proc: Optional[subprocess.Popen] = None
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self.output_dir = self.SESSIONS_DIR / session_id
        self.csv_path = self.output_dir / "wifi-01.csv"
        self.pcap_path = self.output_dir / "wifi-01.cap"
        self.data_path = self.output_dir / "data.json"
        self.started: Optional[str] = None
        self.stopped: Optional[str] = None
        self.mon_iface = ""

        # Data store
        self.aps: Dict[str, dict] = {}
        self.clients: Dict[str, dict] = {}
        self.signal_history: Dict[str, list] = {}
        self.captures: Dict = {"handshakes": [], "pmkids": [], "eap_identities": [], "packet_strings": []}
        self.stats: Dict = {"total_packets": 0, "beacons_total": 0, "probe_requests": 0}
        self._csv_mtime: float = 0
        self._pcap_mtime: float = 0
        self._parse_count: int = 0

    def _now(self) -> str:
        return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _parse_mon_iface(self, airmon_output: str) -> str:
        """Extract actual monitor interface from airmon-ng start output."""
        for line in airmon_output.splitlines():
            # Pattern: "monitor mode vif enabled for [phyX]IFACE on [phyX]MONIFACE"
            m = re.search(r"monitor mode vif enabled for.*?on\s+\[?(\w+)\]?", line, re.I)
            if m:
                return m.group(1)
            # Pattern: "monitor mode already enabled for IFACE"
            m = re.search(r"monitor mode (?:already )?enabled (?:mode )?(?:for|on)\s+\[?\w+\]?(\w+)", line, re.I)
            if m:
                return m.group(1)
        # Last resort: find interface name ending in 'mon' in the output
        for word in airmon_output.split():
            word = word.strip("[](),")
            if re.match(r"^\w+mon$", word) and word != "monitor":
                return word
        return self.iface  # Fallback: no rename occurred

    def start(self) -> dict:
        if self.status == "running":
            return {"error": "Session already running"}
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.started = self._now()
        self.status = "running"

        # Enable monitor mode and detect actual interface name
        self.mon_iface = self.iface
        try:
            r = subprocess.run(["airmon-ng", "start", self.iface],
                               capture_output=True, text=True, timeout=10)
            self.mon_iface = self._parse_mon_iface(r.stdout + r.stderr)
        except Exception:

            logger.debug("Exception in wifi_monitor.py", exc_info=True)  # Use self.iface as fallback

        # Verify the interface actually exists
        try:
            r = subprocess.run(["iwconfig"], capture_output=True,
                               text=True, timeout=5)
            if self.mon_iface not in r.stdout and "Mode:Monitor" not in r.stdout:
                pass  # Warn but continue
        except Exception:

            logger.debug("Exception in wifi_monitor.py", exc_info=True)

        # Build airodump-ng command — interface LAST (positional arg)
        cmd = [
            "airodump-ng",
            "--write", str(self.output_dir / "wifi"),
            "--output-format", "csv,pcap",
            "--band", self.band,
            "--write-interval", "1",
            self.mon_iface,
        ]
        if self.target_bssid:
            cmd += ["--bssid", self.target_bssid]
        if self.target_essid:
            cmd += ["--essid", self.target_essid]

        try:
            self.proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                preexec_fn=lambda: os.setsid() if hasattr(os, "setsid") else None,
            )
        except FileNotFoundError:
            self.status = "stopped"
            return {"error": "airodump-ng not found. Install aircrack-ng suite."}

        # Wait briefly and verify process is still alive
        time.sleep(1)
        if self.proc.poll() is not None:
            self.status = "stopped"
            return {"error": "airodump-ng exited immediately. Check interface availability."}

        # Start polling thread
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

        return {"status": "running", "session_id": self.session_id}

    def stop(self) -> dict:
        if self.status != "running":
            # Already stopped — do cleanup anyway
            self._cleanup()
            return {"status": "stopped", "session_id": self.session_id}
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._kill_proc(force=False)
        self._cleanup()
        self.stopped = self._now()
        self.status = "stopped"
        self._save_data()
        return {"status": "stopped", "session_id": self.session_id}

    def force_kill(self) -> dict:
        """Hard kill — sends SIGKILL, restores interface immediately."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)
        self._kill_proc(force=True)
        self._cleanup()
        self.stopped = self._now()
        self.status = "stopped"
        self._save_data()
        return {"status": "force_killed", "session_id": self.session_id}

    def _kill_proc(self, force: bool = False):
        if not self.proc:
            # Check if process already exited
            return
        try:
            ret = self.proc.poll()
            if ret is not None:
                self.proc = None
                return  # Already exited
            if force:
                self.proc.kill()
                self.proc.wait(timeout=5)
            else:
                if hasattr(os, "getpgid"):
                    try:
                        pgid = os.getpgid(self.proc.pid)
                        os.killpg(pgid, signal.SIGTERM)
                    except (ProcessLookupError, PermissionError):
                        pass
                else:
                    self.proc.terminate()
                try:
                    self.proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait(timeout=5)
        except Exception:
            try:
                self.proc.kill()
                self.proc.wait(timeout=3)
            except Exception:

                logger.debug("Exception in wifi_monitor.py", exc_info=True)
        self.proc = None

    def _cleanup(self):
        """Restore wireless interface from monitor mode (only our interface)."""
        target = self.mon_iface if self.mon_iface else self.iface
        if not target:
            return
        # Try airmon-ng stop first
        try:
            subprocess.run(["airmon-ng", "stop", target],
                           capture_output=True, timeout=5)
        except Exception:

            logger.debug("Exception in wifi_monitor.py", exc_info=True)
        # Fallback: use iw directly (needed on some mac80211 drivers)
        try:
            subprocess.run(["ip", "link", "set", target, "down"],
                           capture_output=True, timeout=5)
            subprocess.run(["iw", "dev", target, "set", "type", "managed"],
                           capture_output=True, timeout=5)
            subprocess.run(["ip", "link", "set", target, "up"],
                           capture_output=True, timeout=5)
        except Exception:

            logger.debug("Exception in wifi_monitor.py", exc_info=True)

    def status_info(self) -> dict:
        with self._lock:
            running = self.status == "running"
            uptime = ""
            if running and self.started:
                try:
                    start = datetime.datetime.fromisoformat(self.started)
                    delta = datetime.datetime.now(datetime.timezone.utc) - start.replace(tzinfo=datetime.timezone.utc)
                    uptime = f"{int(delta.total_seconds())}s"
                except Exception:

                    logger.debug("Exception in wifi_monitor.py", exc_info=True)
            return {
                "session_id": self.session_id,
                "status": self.status,
                "iface": self.iface,
                "mon_iface": self.mon_iface,
                "target_bssid": self.target_bssid,
                "target_essid": self.target_essid,
                "started": self.started,
                "stopped": self.stopped,
                "uptime": uptime,
                "aps_count": len(self.aps),
                "clients_count": len(self.clients),
                "captures": {
                    "handshakes": len(self.captures["handshakes"]),
                    "pmkids": len(self.captures["pmkids"]),
                    "eap_identities": len(self.captures["eap_identities"]),
                    "packet_strings": len(self.captures["packet_strings"]),
                },
                "stats": self.stats,
            }

    def get_data(self) -> dict:
        with self._lock:
            return {
                "aps": list(self.aps.values()),
                "clients": list(self.clients.values()),
                "signal_history": self.signal_history,
                "captures": self.captures,
                "stats": self.stats,
            }

    def deauth(self, bssid: str, client: str = "", count: int = 5) -> dict:
        """Send deauth packets to force client reconnection and trigger 4-way handshake capture."""
        import shutil
        if self.status != "running":
            return {"error": "Session not running"}
        aireplay = shutil.which("aireplay-ng")
        if not aireplay:
            return {"error": "aireplay-ng not found. Install aircrack-ng suite."}
        iface = self.mon_iface if self.mon_iface and self.mon_iface != self.iface else self.iface
        if not bssid:
            return {"error": "BSSID is required"}
        try:
            cmd = [aireplay, "-0", str(count), "-a", bssid]
            if client:
                cmd += ["-c", client]
            cmd.append(iface)
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            sent = 0
            for line in r.stdout.splitlines():
                m = re.search(r"(\d+)\s+deauth", line, re.I)
                if m:
                    sent = int(m.group(1))
                    break
            return {
                "status": "sent" if sent > 0 else ("done" if r.returncode == 0 else "error"),
                "packets_sent": sent,
                "target_bssid": bssid,
                "target_client": client or "(broadcast)",
                "output": r.stdout[:300],
            }
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "error": "aireplay-ng timed out (30s)"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def parse_pcap_now(self) -> dict:
        """Force re-parse of PCAP for handshakes/PMKID."""
        if not self.pcap_path.exists():
            return {"error": "PCAP not found"}
        handshakes = PcapAnalyzer.find_handshakes(self.pcap_path)
        pmkids = PcapAnalyzer.find_pmkid(self.pcap_path)
        eap = PcapAnalyzer.find_eap_identities(self.pcap_path)
        pstr = PcapAnalyzer.find_packet_strings(self.pcap_path)
        with self._lock:
            new_hs = [h for h in handshakes if h not in self.captures["handshakes"]]
            new_pm = [p for p in pmkids if p not in self.captures["pmkids"]]
            new_eap = [e for e in eap if e not in self.captures["eap_identities"]]
            existing_texts = {s["text"] for s in self.captures["packet_strings"]}
            new_pstr = [s for s in pstr if s["text"] not in existing_texts]
            self.captures["handshakes"].extend(new_hs)
            self.captures["pmkids"].extend(new_pm)
            self.captures["eap_identities"].extend(new_eap)
            self.captures["packet_strings"].extend(new_pstr)
        self._save_data()
        return {
            "handshakes": len(handshakes),
            "pmkids": len(pmkids),
            "eap_identities": len(eap),
            "packet_strings": len(pstr),
            "new_handshakes": len(new_hs),
            "new_pmkids": len(new_pm),
            "new_eap": len(new_eap),
            "new_packet_strings": len(new_pstr),
        }

    def _poll_loop(self):
        """Background thread: poll CSV every 2s, parse PCAP every 10s."""
        pcap_counter = 0
        while not self._stop_event.is_set():
            # Process health check
            if self.proc and self.proc.poll() is not None:
                self.status = "stopped"
                self.stopped = self._now()
                self._save_data()
                break
            self._poll_csv()
            pcap_counter += 1
            if pcap_counter >= 5:
                pcap_counter = 0
                self._poll_pcap()
            self._save_data()
            self._stop_event.wait(2)

    def _poll_csv(self):
        """Parse airodump CSV for APs and clients."""
        if not self.csv_path.exists():
            return
        try:
            mtime = self.csv_path.stat().st_mtime
            if mtime <= self._csv_mtime:
                return
            self._csv_mtime = mtime
            text = self.csv_path.read_text(encoding="utf-8", errors="replace")
            parsed = AirodumpCSVParser.parse(text)
        except Exception:
            return

        with self._lock:
            now = self._now()
            # Update APs
            for ap in parsed.get("aps", []):
                bssid = ap["bssid"]
                if bssid in self.aps:
                    old = self.aps[bssid]
                    ap["first_seen"] = old.get("first_seen", now)
                else:
                    ap["first_seen"] = now
                    # Initialize signal history
                    if bssid not in self.signal_history:
                        self.signal_history[bssid] = []
                ap["last_seen"] = now
                self.aps[bssid] = ap
                # Track signal over time
                if ap["signal"] is not None:
                    self.signal_history[bssid].append({
                        "ts": now,
                        "signal": ap["signal"],
                    })
                    # Keep last 200 data points
                    if len(self.signal_history[bssid]) > 200:
                        self.signal_history[bssid] = self.signal_history[bssid][-200:]

            # Update clients
            for cl in parsed.get("clients", []):
                mac = cl["mac"]
                if mac in self.clients:
                    old = self.clients[mac]
                    cl["first_seen"] = old.get("first_seen", now)
                else:
                    cl["first_seen"] = now
                cl["last_seen"] = now
                self.clients[mac] = cl

            # Update stats
            self.stats["beacons_total"] = sum(
                ap.get("beacons", 0) for ap in self.aps.values()
            )
            self.stats["probe_requests"] = sum(
                len(cl.get("probed_essids", [])) for cl in self.clients.values()
            )
            self.stats["total_packets"] = sum(
                cl.get("packets", 0) for cl in self.clients.values()
            )

    def _poll_pcap(self):
        """Periodically parse PCAP for captures."""
        if not self.pcap_path.exists():
            return
        try:
            mtime = self.pcap_path.stat().st_mtime
            if mtime <= self._pcap_mtime:
                return
            self._pcap_mtime = mtime
        except Exception:
            return

        try:
            hs = PcapAnalyzer.find_handshakes(self.pcap_path)
            pm = PcapAnalyzer.find_pmkid(self.pcap_path)
            eap = PcapAnalyzer.find_eap_identities(self.pcap_path)
            pstr = PcapAnalyzer.find_packet_strings(self.pcap_path)
        except Exception:
            return

        with self._lock:
            for h in hs:
                if h not in self.captures["handshakes"]:
                    self.captures["handshakes"].append(h)
            for p in pm:
                if p not in self.captures["pmkids"]:
                    self.captures["pmkids"].append(p)
            for e in eap:
                if e not in self.captures["eap_identities"]:
                    self.captures["eap_identities"].append(e)
            existing_texts = {s["text"] for s in self.captures["packet_strings"]}
            for s in pstr:
                if s["text"] not in existing_texts:
                    self.captures["packet_strings"].append(s)
                    existing_texts.add(s["text"])

    def _save_data(self):
        with self._lock:
            self.data_path.write_text(json.dumps({
                "session_id": self.session_id,
                "started": self.started,
                "stopped": self.stopped,
                "iface": self.iface,
                "target_bssid": self.target_bssid,
                "target_essid": self.target_essid,
                "status": self.status,
                "aps": list(self.aps.values()),
                "clients": list(self.clients.values()),
                "signal_history": self.signal_history,
                "captures": self.captures,
                "stats": self.stats,
            }, indent=2, default=str))

    def load(self) -> bool:
        """Reload session data from disk."""
        if not self.data_path.exists():
            return False
        try:
            data = json.loads(self.data_path.read_text())
            self.aps = {a["bssid"]: a for a in data.get("aps", [])}
            self.clients = {c["mac"]: c for c in data.get("clients", [])}
            self.signal_history = data.get("signal_history", {})
            self.captures = data.get("captures", self.captures)
            self.stats = data.get("stats", self.stats)
            self.status = data.get("status", "stopped")
            self.started = data.get("started")
            self.stopped = data.get("stopped")
            self.iface = data.get("iface", self.iface)
            self.target_bssid = data.get("target_bssid", "")
            self.target_essid = data.get("target_essid", "")
            return True
        except Exception:
            return False


class WifiMonitorManager:
    """Manages multiple WiFi monitoring sessions."""

    def __init__(self):
        self._sessions: Dict[str, WifiMonitorSession] = {}
        self._lock = threading.Lock()
        WifiMonitorSession.SESSIONS_DIR.mkdir(parents=True, exist_ok=True)

    def start_session(self, session_id: str, iface: str, band: str = "abg",
                      target_bssid: str = "", target_essid: str = "") -> dict:
        with self._lock:
            if session_id in self._sessions and self._sessions[session_id].status == "running":
                return {"error": f"Session '{session_id}' is already running"}
            sess = WifiMonitorSession(session_id, iface, band, target_bssid, target_essid)
            self._sessions[session_id] = sess
            r = sess.start()
            return r

    def stop_session(self, session_id: str) -> dict:
        with self._lock:
            if session_id not in self._sessions:
                return {"error": f"Session '{session_id}' not found"}
            return self._sessions[session_id].stop()

    def get_session(self, session_id: str) -> Optional[WifiMonitorSession]:
        with self._lock:
            sess = self._sessions.get(session_id)
            if sess:
                return sess
            # Try loading from disk
            sess = WifiMonitorSession(session_id, "", "")
            if sess.load():
                self._sessions[session_id] = sess
                return sess
            return None

    def list_sessions(self) -> list:
        sessions = []
        # Load from disk
        if WifiMonitorSession.SESSIONS_DIR.exists():
            for d in sorted(WifiMonitorSession.SESSIONS_DIR.iterdir(), reverse=True):
                if d.is_dir() and (d / "data.json").exists():
                    try:
                        data = json.loads((d / "data.json").read_text())
                        ap_count = len(data.get("aps", []))
                        cl_count = len(data.get("clients", []))
                        hs = len(data.get("captures", {}).get("handshakes", []))
                        sessions.append({
                            "session_id": d.name,
                            "started": data.get("started", ""),
                            "stopped": data.get("stopped", ""),
                            "status": data.get("status", "stopped"),
                            "iface": data.get("iface", "?"),
                            "aps": ap_count,
                            "clients": cl_count,
                            "handshakes": hs,
                        })
                    except Exception:

                        logger.debug("Exception in wifi_monitor.py", exc_info=True)
        return sessions

    def get_active_session(self) -> Optional[WifiMonitorSession]:
        for sess in self._sessions.values():
            if sess.status == "running":
                return sess
        return None


# Global manager instance
_manager: Optional[WifiMonitorManager] = None


def get_monitor_manager() -> WifiMonitorManager:
    global _manager
    if _manager is None:
        _manager = WifiMonitorManager()
    return _manager