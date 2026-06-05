"""Doctor — health checks for tools, wordlists, services, and dependencies."""

import json
import shutil
import subprocess
from pathlib import Path
from shutil import which
from typing import Dict, List, Optional, Tuple

from .config import CONFIG_DIR, OBSIDIAN_DIR, YARA_RULES_DIR, SIGMA_RULES_DIR, SEMGREP_RULES_DIR, NUCLEI_TEMPLATES_DIR
from .tool_wrappers import (
    nuclei_scan,
    semgrep_scan,
    trufflehog_org,
    yara_scan,
)


class Doctor:
    """Check tool availability, wordlist integrity, and service health."""

    ALT_BIN_DIRS = [
        Path("/share/tools"),
    ]

    CRITICAL_TOOLS = [
        "nmap", "whatweb", "nuclei", "ffuf", "gobuster",
        "msfconsole", "searchsploit", "sqlmap", "hashcat",
        "john", "hydra", "aircrack-ng", "airodump-ng",
        "netexec", "impacket-secretsdump", "responder", "evil-winrm",
    ]

    FORENSIC_TOOLS = [
        "volatility", "binwalk", "foremost", "strings",
        "sleuthkit", "bulk_extractor", "yara",
    ]

    WIFI_TOOLS = [
        "airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng",
        "reaver", "wash", "kismet", "bettercap", "iwconfig",
        "eaphammer", "hcxdumptool", "hcxpcapngtool",
    ]

    AD_TOOLS = [
        "bloodyad", "certipy", "ldapnomnom",
        "kerbrute", "impacket-secretsdump", "netexec",
    ]

    API_TOOLS = [
        "jwt_tool", "graphw00f",
    ]

    FORENSIC_WIN_TOOLS = [
        "kape",
    ]

    MISC_TOOLS = [
        "wsgidav", "swaks",
    ]

    WORDLISTS = [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/rockyou.txt.gz",
        "/wordlists/rockyou.txt",
        "/wordlists/dns-top-10000.txt",
        "/wordlists/webcontent-top-10000.txt",
        "/wordlists",
        "/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt",
    ]

    def __init__(self):
        self.results: Dict[str, list] = {
            "tool_checks": [],
            "wordlist_checks": [],
            "service_checks": [],
            "config_checks": [],
        }

    def _check_tool(self, name: str) -> Tuple[bool, str]:
        fp = which(name)
        if not fp:
            for d in self.ALT_BIN_DIRS:
                for candidate in [d / name, d / name / name, d / name / f"{name}.py"]:
                    if candidate.is_file():
                        fp = str(candidate)
                        break
                if fp:
                    break
        if fp:
            try:
                r = subprocess.run([fp, "--version"], capture_output=True,
                                   text=True, timeout=10)
                ver = r.stdout.strip()[:60] + r.stderr.strip()[:60]
                version = ver[:80].replace("\n", "; ")
                return True, f"{fp} ({version})"
            except Exception:
                return True, fp
        return False, "not found"

    def check_tools(self, categories: Optional[Dict[str, list]] = None) -> None:
        if categories is None:
            categories = {
                "critical": self.CRITICAL_TOOLS,
                "forensics": self.FORENSIC_TOOLS,
                "wifi": self.WIFI_TOOLS,
                "active_directory": self.AD_TOOLS,
                "api_testing": self.API_TOOLS,
                "forensics_windows": self.FORENSIC_WIN_TOOLS,
                "misc": self.MISC_TOOLS,
            }
        for cat, tools in categories.items():
            for tool in tools:
                ok, info = self._check_tool(tool)
                self.results["tool_checks"].append({
                    "tool": tool,
                    "category": cat,
                    "ok": ok,
                    "info": info,
                })

    def check_wordlists(self) -> None:
        for wl in self.WORDLISTS:
            p = Path(wl)
            if p.exists():
                size = p.stat().st_size
                size_str = f"{size / 1024 / 1024:.1f}M" if size > 1024**2 else f"{size / 1024:.1f}K"
                self.results["wordlist_checks"].append({
                    "path": wl,
                    "ok": True,
                    "info": f"{size_str} ({size:,} bytes)",
                })
            else:
                self.results["wordlist_checks"].append({
                    "path": wl,
                    "ok": False,
                    "info": "not found",
                })

    def check_services(self) -> None:
        for svc in ["jupyter", "podman", "docker", "ssh"]:
            try:
                r = subprocess.run(
                    ["systemctl", "is-active", svc],
                    capture_output=True, text=True, timeout=5
                )
                active = r.stdout.strip() == "active"
                self.results["service_checks"].append({
                    "service": svc,
                    "ok": active,
                    "info": r.stdout.strip(),
                })
            except Exception:
                self.results["service_checks"].append({
                    "service": svc,
                    "ok": False,
                    "info": "could not check",
                })

    def check_config(self) -> None:
        cfg_file = CONFIG_DIR / "config.json"
        self.results["config_checks"].append({
            "check": "config_file",
            "ok": cfg_file.exists(),
            "info": str(cfg_file) if cfg_file.exists() else "not created yet",
        })
        self.results["config_checks"].append({
            "check": "obsidian_vault",
            "ok": OBSIDIAN_DIR.exists(),
            "info": str(OBSIDIAN_DIR) if OBSIDIAN_DIR.exists() else "not mounted",
        })
        for label, d in [("yara_rules", YARA_RULES_DIR), ("sigma_rules", SIGMA_RULES_DIR),
                          ("semgrep_rules", SEMGREP_RULES_DIR), ("nuclei_templates", NUCLEI_TEMPLATES_DIR)]:
            self.results["config_checks"].append({
                "check": label,
                "ok": d.exists(),
                "info": str(d) if d.exists() else "not found",
            })

    def run_all(self) -> Dict[str, list]:
        self.check_tools()
        self.check_wordlists()
        self.check_services()
        self.check_config()
        return self.results

    def summary(self) -> str:
        lines = ["Doctor Summary:\n"]
        for section, checks in self.results.items():
            total = len(checks)
            passed = sum(1 for c in checks if c.get("ok"))
            label = section.replace("_", " ").title()
            lines.append(f"  {label:<20} {passed}/{total} passed")
            for c in checks:
                icon = "\u2713" if c.get("ok") else "\u2717"
                name = c.get("tool") or c.get("path") or c.get("service") or c.get("check", "")
                lines.append(f"    {icon} {name:<30} {c.get('info', '')}")
            lines.append("")
        return "\n".join(lines)
