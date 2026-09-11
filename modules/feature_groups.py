"""Feature groups for the CC Toolkit MCP.

Maps human-readable feature groups to the MCP tool-name prefixes each group
controls, plus helpers that turn the persisted ``features`` config (in
config.json) into an MCP allowlist.

The MCP server registers every tool at import time, then at startup removes
any tool whose name doesn't match the effective allowlist (see
``_apply_tool_allowlist`` in cc_mcp_server.py). Disabling feature groups keeps
the tool surface lightweight and tailored to the current engagement.

Persisted config shape (``config.json`` -> ``features``)::

    {
      "enabled_groups": ["case", "recon", ...],   # groups that are ON
      "enabled_tools":  ["tool_caido", ...],       # prefixes forced ON
      "disabled_tools": ["burp_scan_start", ...]   # prefixes forced OFF
    }

``enabled_tools`` / ``disabled_tools`` are per-tool overrides: any tool name
or prefix. ``doctor_run`` (the capability/health check) is always exposed.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

CC_DIR = Path(__file__).resolve().parent.parent
TOOL_INDEX_PATH = CC_DIR / "cc_tool_index.json"

# Always exposed regardless of feature config (capability / health checks).
ALWAYS_ON = ["doctor"]

# ---------------------------------------------------------------------------
# Feature groups: name -> {label, desc, prefixes}
# Prefixes are matched with `name == prefix or name.startswith(prefix)`.
# Prefixes may overlap across groups (the allowlist is the union).
# ---------------------------------------------------------------------------
FEATURE_GROUPS = {
    "case": {
        "label": "Case Management",
        "desc": "Cases, evidence, findings, IR, runbooks/playbooks, jobs, prompts, flashcards, reports",
        "prefixes": ["case", "evidence", "findings", "ir_", "projects", "job", "jobs",
                     "flashcards", "prompts", "playbook", "runbook", "papermill", "dashboard"],
    },
    "recon": {
        "label": "Recon & Assets",
        "desc": "Port scanning, DNS, asset inventory, credentials & loot store, dir fuzzing, ProjectDiscovery subdomain/probe/crawl stack",
        "prefixes": ["nmap", "auto_recon", "dns", "enum4linux", "assets", "customers",
                     "credentials", "loot", "ffuf", "gobuster", "pd"],
    },
    "web": {
        "label": "Web App Testing",
        "desc": "Web DAST: nuclei, JWT, GraphQL, sqlmap, caido import, gophish/evilginx",
        "prefixes": ["web", "ffuf", "gobuster", "tool_sqlmap", "tool_caido",
                     "tool_gophish", "tool_evilginx"],
    },
    "appsec": {
        "label": "AppSec (DAST/SAST/SCA)",
        "desc": "DAST engines (Burp Pro, OWASP ZAP, Caido) + SBOM/SCA (syft, trivy, grype) + secret scanning (gitleaks) + SAST + OSV deps + CDN libs + existing-SBOM ingest + combined appsec audit",
        "prefixes": ["burp", "zap", "caido", "tool_caido", "sbom", "sca_",
                     "secret_scan", "sast", "osv", "cdn", "appsec_scan"],
    },
    "ad": {
        "label": "Active Directory",
        "desc": "AD security: bloodyAD, certipy, kerbrute, impacket, kerberos, windapsearch, responder",
        "prefixes": ["ad", "enum4linux", "impacket", "kerberos", "pypykatz",
                     "tool_bloodhound", "tool_windapsearch", "tool_evil_winrm",
                     "tool_responder"],
    },
    "wifi": {
        "label": "WiFi / Wireless",
        "desc": "Wireless attacks: monitor, deauth, evil twin, rogue AP, handshake capture",
        "prefixes": ["wifi", "tool_responder"],
    },
    "binary": {
        "label": "Binary Exploitation",
        "desc": "Reverse engineering & exploitation analysis: angr, checksec, ROP, gadgets, fuzz harnesses, CLI-surface scanning",
        "prefixes": ["binary", "bin_surface"],
    },
    "bb": {
        "label": "Bug Bounty",
        "desc": "Program discovery/sync, platform credentials, report management (HackerOne, Bugcrowd, Immunefi, YesWeHack)",
        "prefixes": ["bb"],
    },
    "forensics": {
        "label": "Forensics & Creds",
        "desc": "Forensics, browser data, pypykatz, lazagne, trufflehog, john, hashcat, winpeas/linpeas",
        "prefixes": ["forensics", "browser", "pypykatz", "tool_lazagne", "tool_trufflehog",
                     "tool_john", "tool_pspy", "tool_winpeas", "hashcat", "linpeas"],
    },
    "rules": {
        "label": "Rule Engine & Reference",
        "desc": "Semgrep/Sigma/YARA/Suricata/Nuclei rule management + CVE/ATT&CK/CWE reference lookups",
        "prefixes": ["rules", "ref", "tags"],
    },
    "tool-exec": {
        "label": "Tool Execution",
        "desc": "Generic launchers: metasploit, hydra, chisel, ligolo, /share/tools runner",
        "prefixes": ["tools", "chisel", "tool_chisel", "tool_ligolo",
                     "tool_metasploit", "tool_hydra"],
    },
    "util": {
        "label": "Utility",
        "desc": "MITM proxy, swaks SMTP, WebDAV, route scan, sigma convert",
        "prefixes": ["util"],
    },
}

DEFAULT_FEATURES = {
    "enabled_groups": sorted(FEATURE_GROUPS),
    "enabled_tools": [],
    "disabled_tools": [],
}


def normalize_prefixes(prefixes) -> list:
    out, seen = [], set()
    for p in prefixes or []:
        p = str(p).strip().lower()
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def build_prefix_list(features: dict | None) -> list:
    """Effective prefix list from a ``features`` config dict.

    An explicit empty ``enabled_groups`` means "nothing on" (only always-on
    tools survive); a missing key means "all groups on" (backwards compatible
    with configs saved before the feature system existed).
    """
    features = features or {}
    enabled_groups = features.get("enabled_groups")
    if enabled_groups is None:
        enabled_groups = list(FEATURE_GROUPS)
    enabled_groups = set(enabled_groups)
    prefixes = []
    for group in FEATURE_GROUPS:
        if group in enabled_groups:
            prefixes.extend(FEATURE_GROUPS[group]["prefixes"])
    prefixes.extend(features.get("enabled_tools") or [])
    prefixes = normalize_prefixes(prefixes)
    disabled = set(normalize_prefixes(features.get("disabled_tools") or []))
    prefixes = [p for p in prefixes if p not in disabled]
    return normalize_prefixes(prefixes + list(ALWAYS_ON))


def build_allowlist(features: dict | None) -> str:
    """Comma-separated allowlist string consumable by CC_MCP_TOOLS."""
    return ",".join(build_prefix_list(features))


def build_denylist(features: dict | None) -> str:
    """Comma-separated force-off prefix list from ``disabled_tools``.

    Unlike build_allowlist, this is matched directly against each tool name at
    MCP startup, so a specific tool (e.g. "burp_scan_start") is excluded even
    when a broader group prefix (e.g. "burp") would otherwise keep it.
    """
    return ",".join(normalize_prefixes((features or {}).get("disabled_tools") or []))


def _matches(name: str, prefixes) -> bool:
    low = name.lower()
    return any(low == p or low.startswith(p) for p in prefixes)


# ---------------------------------------------------------------------------
# Tool index (list of every registered MCP tool name)
# ---------------------------------------------------------------------------
def load_tool_index() -> list:
    """Tool names written by cc_mcp_server at startup (empty if unavailable)."""
    try:
        if TOOL_INDEX_PATH.exists():
            data = json.loads(TOOL_INDEX_PATH.read_text(encoding="utf-8"))
            return list(data.get("tools", []))
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    return []


def save_tool_index(tool_names: list) -> None:
    try:
        TOOL_INDEX_PATH.write_text(
            json.dumps({"tools": sorted(set(tool_names)),
                        "saved_at": None,
                        "generated_by": "cc_mcp_server"},
                       indent=2),
            encoding="utf-8")
    except OSError:
        pass


def index_age_seconds() -> float | None:
    try:
        if TOOL_INDEX_PATH.exists():
            import time
            return time.time() - TOOL_INDEX_PATH.stat().st_mtime
    except OSError:
        return None
    return None


# ---------------------------------------------------------------------------
# Summary used by the CLI and web dashboard
# ---------------------------------------------------------------------------
def summarize(features: dict | None = None, tool_names: list | None = None) -> dict:
    features = features or {}
    enabled_groups = features.get("enabled_groups")
    if enabled_groups is None:
        enabled_groups = sorted(FEATURE_GROUPS)
    enabled_set = set(enabled_groups)
    known_enabled = sorted(enabled_set & set(FEATURE_GROUPS))
    unknown_groups = sorted(enabled_set - set(FEATURE_GROUPS))
    prefixes = build_prefix_list(features)
    tool_names = list(tool_names) if tool_names is not None else load_tool_index()

    groups = {}
    for name, meta in FEATURE_GROUPS.items():
        members = [t for t in tool_names if _matches(t, meta["prefixes"])]
        groups[name] = {
            "label": meta["label"],
            "desc": meta["desc"],
            "enabled": name in enabled_groups,
            "prefixes": meta["prefixes"],
            "tool_count": len(members),
            "tools": members,
        }

    included, excluded = [], []
    denied = normalize_prefixes(features.get("disabled_tools") or [])
    for t in tool_names:
        if _matches(t, denied):
            excluded.append(t)
        elif _matches(t, prefixes):
            included.append(t)
        else:
            excluded.append(t)

    return {
        "groups": groups,
        "enabled_groups": known_enabled,
        "unknown_groups": unknown_groups,
        "enabled_tools": list(features.get("enabled_tools") or []),
        "disabled_tools": list(features.get("disabled_tools") or []),
        "allowlist": build_allowlist(features),
        "denylist": build_denylist(features),
        "always_on": list(ALWAYS_ON),
        "total_tools": len(tool_names),
        "included_count": len(included),
        "excluded_count": len(excluded),
        "included_tools": sorted(included),
        "excluded_tools": sorted(excluded),
        "all_tools": sorted(tool_names),
        "env_override": os.environ.get("CC_MCP_TOOLS", ""),
    }


def enable_group(features: dict, group: str) -> bool:
    if group not in FEATURE_GROUPS:
        return False
    enabled = features.get("enabled_groups")
    if enabled is None:
        enabled = list(FEATURE_GROUPS)
    enabled = set(enabled)
    enabled.add(group)
    features["enabled_groups"] = sorted(enabled)
    return True


def disable_group(features: dict, group: str) -> bool:
    if group not in FEATURE_GROUPS:
        return False
    enabled = features.get("enabled_groups")
    if enabled is None:
        enabled = list(FEATURE_GROUPS)
    enabled = set(enabled)
    enabled.discard(group)
    features["enabled_groups"] = sorted(enabled)
    return True
