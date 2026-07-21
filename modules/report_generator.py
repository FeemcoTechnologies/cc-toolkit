import logging
"""Report generator — parse case data into Obsidian-compatible Markdown + HTML.

Output matches the Obsidian pentest report template structure at:
  Templates/Pentest Templates/Pentest Report.md  with sections in Data/
"""

import base64
import datetime
import json
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional

from .config import COMPANY, TESTER, LOGO_RELPATH
logger = logging.getLogger(__name__)

# Inline script for terminal-styling PoC <pre> blocks in exported HTML
_POC_STYLE_SCRIPT = """<script>
(function(){var h=document.querySelectorAll('h4');for(var i=0;i<h.length;i++){if(h[i].textContent.indexOf('Proof of Concept')!==-1){var e=h[i].nextElementSibling;while(e&&e.tagName!=='PRE'){e=e.nextElementSibling;}if(e&&e.tagName==='PRE'){e.style.background='#000';e.style.color='#fff';e.style.border='1px solid #555';}}}}})();
</script>"""

# Sections in order (matches template Pentest Report.md)
ALL_SECTIONS = [
    "Confidentiality Statement",
    "Disclaimer",
    "Contact Information",
    "Engagement Contacts",
    "Assessment Overview",
    "Scope",
    "Executive Summary",
    "Strengths",
    "Weaknesses",
    "Findings",
    "Risk Assessment Matrix",
    "Methodology",
    "Appendix A – Flags Discovered",
]

# Case-type-specific section templates — controls which sections appear per case type.
# Keys match case_manager.py CASE_TYPES. Missing types fall back to "pentest".
CASE_TYPE_SECTIONS = {
    "pentest": ALL_SECTIONS,
    "pentest_web": ALL_SECTIONS,
    "pentest_external": ALL_SECTIONS,
    "pentest_internal_ad": ALL_SECTIONS,
    "pentest_cloud": [
        "Confidentiality Statement",
        "Disclaimer",
        "Contact Information",
        "Engagement Contacts",
        "Assessment Overview",
        "Scope",
        "Executive Summary",
        "Strengths",
        "Weaknesses",
        "Findings",
        "Risk Assessment Matrix",
        "Methodology",
        "Appendix A – Flags Discovered",
    ],
    "pentest_physical": [
        "Confidentiality Statement",
        "Disclaimer",
        "Contact Information",
        "Engagement Contacts",
        "Assessment Overview",
        "Scope",
        "Executive Summary",
        "Strengths",
        "Weaknesses",
        "Findings",
        "Risk Assessment Matrix",
        "Methodology",
        "Appendix A – Flags Discovered",
    ],
    "ir": [
        "Confidentiality Statement",
        "Disclaimer",
        "Contact Information",
        "Engagement Contacts",
        "Assessment Overview",
        "Scope",
        "Executive Summary",
        "Findings",
        "Methodology",
    ],
    "forensics": [
        "Confidentiality Statement",
        "Disclaimer",
        "Contact Information",
        "Engagement Contacts",
        "Assessment Overview",
        "Scope",
        "Executive Summary",
        "Findings",
        "Methodology",
    ],
    "osint": [
        "Confidentiality Statement",
        "Disclaimer",
        "Contact Information",
        "Engagement Contacts",
        "Assessment Overview",
        "Scope",
        "Executive Summary",
        "Strengths",
        "Weaknesses",
        "Findings",
        "Methodology",
        "Appendix A – Flags Discovered",
    ],
}

def _sections_for_case(case_type: str) -> List[str]:
    """Return the section list appropriate for a given case type."""
    return CASE_TYPE_SECTIONS.get(case_type, ALL_SECTIONS)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _html_escape(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _md_escape(text: str, table: bool = False) -> str:
    """Escape markdown special characters. Set table=True for table cell content."""
    if not text:
        return ""
    escaped = text
    escaped = escaped.replace("\\", "\\\\")
    escaped = escaped.replace("`", "\\`")
    escaped = escaped.replace("*", "\\*")
    escaped = escaped.replace("_", "\\_")
    escaped = escaped.replace("[", "\\[")
    escaped = escaped.replace("]", "\\]")
    escaped = escaped.replace("<", "&lt;")
    if table:
        escaped = escaped.replace("|", "\\|")
    return escaped


def _fmt_ts(ts: str) -> str:
    if not ts:
        return ""
    return ts[:19].replace("T", " ")


def _load_case(case_dir: Path) -> tuple:
    case_json = case_dir / "case.json"
    findings_json = case_dir / "findings.json"
    case_data = json.loads(case_json.read_text()) if case_json.exists() else {}
    findings_data = json.loads(findings_json.read_text()) if findings_json.exists() else {}
    return case_data, findings_data.get("findings", [])


# ---------------------------------------------------------------------------
# Section renderers  (return list of Markdown lines for each section)
# ---------------------------------------------------------------------------

def _section_confidentiality(client: str = "") -> List[str]:
    client_name = client or "CLIENT"
    return [
        "## Confidentiality Statement",
        "",
        f"This document is the exclusive property of **{COMPANY}** and **{client_name}**."
        " This document contains proprietary and confidential information."
        " Any duplication, redistribution, or use requires the written consent of both parties."
        " Further restrictions for this are outlined in any agreements made between"
        " these two parties and will be upheld based on that agreement.",
        "",
    ]


def _section_disclaimer(dates: str = "", client: str = "") -> List[str]:
    client_name = client or "CLIENT"
    return [
        "## Disclaimer",
        "",
        f"The Cyber Defense Penetration Testing performed by {COMPANY} for {client_name},"
        f" and the report prepared by the tester ({TESTER}),"
        " is intended to showcase identified security flaws found during testing"
        " of a point-in-time reference."
        " While it may be impossible to denote every possible exploitation,"
        " we've prepared this document to showcase the issues we found at the time of testing"
        " with priority on things likely to be or become identified by attackers."
        " This does not and cannot showcase things that weren't tested against,"
        " or from a time outside of the testing window.",
        "",
        "Due to this, and an ever changing threat landscape, we highly recommend"
        " retesting after remediation has been validated, to further identify issues.",
        "",
    ]


def _section_contact(case_data: dict = None) -> List[str]:
    cd = case_data or {}
    contacts = cd.get("contacts", "")
    lines = [
        "## Contact Information",
        "",
        "Sometimes when performing testing we come across issues, evidence of exploitation,"
        " or other concerns that merits immediate contact."
        " Sometimes that may also include several contacts depending on the severity type of concern."
        " Due to that, we have both a priority scale and a notes section filled out by the customer"
        " when agreeing to our services. Priority is ranked 1-3, under the basis of:",
        "1. Primary point of contact for all things",
        "2. Secondary contact, or contact for specific issues",
        "3. One of the others hasn't responded, and the issue is urgent, get these people on the phone.",
        "",
    ]
    if contacts:
        lines += [_normalize_pipe_table(contacts), ""]
    else:
        lines += [
            "",
            "| Contact Name | Number/Email | Priority | Notes |",
            "| ------------ | ------------ | -------- | ----- |",
            "| —            | —            | —        | —     |",
            "",
        ]
    return lines


def _normalize_pipe_table(text: str) -> str:
    """Add leading/trailing pipes to pipe-delimited lines if missing.
    Skips markdown block elements (headings, code fences, blockquotes, HRs)."""
    lines = text.split("\n")
    has_pipes = any("|" in line for line in lines)
    if not has_pipes:
        return text
    result = []
    for line in lines:
        s = line.strip()
        # Skip markdown block constructs and blank lines
        if not s or s.startswith("#") or s.startswith(">") or s.startswith("```") or s.startswith("---") or s.startswith("***"):
            result.append(s)
            continue
        if "|" in s:
            if not s.startswith("|"):
                s = "| " + s
            if not s.endswith("|"):
                s = s + " |"
        result.append(s)
    return "\n".join(result)


def _section_engagement_contacts(case_data: dict = None) -> List[str]:
    """Render formal Engagement Contacts section with client + assessor contact tables."""
    cd = case_data or {}
    lines = ["## Engagement Contacts", ""]

    # Client contacts from structured data or fallback
    client_contacts = cd.get("client_contacts", [])
    assessor_contacts = cd.get("assessor_contacts", [])

    # If no structured contacts exist, try to parse from contacts string
    if not client_contacts and not assessor_contacts:
        contacts_str = cd.get("contacts", "")
        if contacts_str:
            contacts_str = _normalize_pipe_table(contacts_str)
            lines += ["### Client Contacts", "", contacts_str, ""]
            lines += ["### Assessor Contacts", "",
                       "| Name | Title | Email |",
                       "| ---- | ----- | ----- |",
                       f"| {TESTER} | Security Consultant | — |",
                       ""]
        else:
            lines += ["### Client Contacts", "",
                       "| Name | Title | Email |",
                       "| ---- | ----- | ----- |",
                       "| —    | —     | —     |",
                       "",
                       "### Assessor Contacts", "",
                       "| Name | Title | Email |",
                       "| ---- | ----- | ----- |",
                       f"| {TESTER} | Security Consultant | — |",
                       ""]
        return lines

    # Render structured client contacts table
    lines += ["### Client Contacts", "",
              "| Name | Title | Email |",
              "| ---- | ----- | ----- |"]
    for c in client_contacts:
        lines.append(f"| {_md_escape(c.get('name', ''), table=True)} "
                     f"| {_md_escape(c.get('title', ''), table=True)} "
                     f"| {_md_escape(c.get('email', ''), table=True)} |")
    lines.append("")

    # Render structured assessor contacts table
    lines += ["### Assessor Contacts", "",
              "| Name | Title | Email |",
              "| ---- | ----- | ----- |"]
    for c in assessor_contacts:
        lines.append(f"| {_md_escape(c.get('name', ''), table=True)} "
                     f"| {_md_escape(c.get('title', ''), table=True)} "
                     f"| {_md_escape(c.get('email', ''), table=True)} |")
    lines.append("")

    return lines


def _section_assessment_overview(client: str = "", dates: str = "",
                                 case_data: dict = None) -> List[str]:
    cd = case_data or {}
    assessment_dates = cd.get("assessment_dates", "") or dates
    name = client or cd.get("client", "") or "COMPANY"
    return [
        "## Assessment Overview",
        "",
        f"{COMPANY} was engaged to perform a general security posture assessment"
        f" of internal and external infrastructure compared to industry standards"
        f" and best practices. The assessment took place between ({assessment_dates or 'DATES'}).",
        "",
        "This process was acted on in phases, which can be explained by the following:",
        "- **Planning** — Customer goals are gathered, scope defined, and rules of"
        " engagement confirmed prior to any other activities.",
        "- **Discovery** — This can be broken down further into Reconnaissance,"
        " Scanning, and general assessment of potential vulnerabilities.",
        "  - **Reconnaissance** — Developing a general idea of items in scope's"
        " attack surface, can be considered intelligence gathering.",
        "  - **Scanning** — Performing checks to confirm, validate, or find further"
        " information not previously found.",
        "  - **Assessment** — Take what's found and attempt to bring possible"
        " exploits to light.",
        "- **Exploitation** — Validate the exploitability of discovered vectors.",
        "- **Reporting** — Documenting vulnerabilities and proven exploits found"
        " as well as steps taken. Provide strengths and weaknesses found within the environment.",
        "",
    ]


def _section_scope(case_dir: Path, case_data: dict) -> List[str]:
    """Render scope table. Loads from scope.json if it exists, falls back to case_data."""
    # Try loading from scope.json first (separate file written by CaseManager.scope_add)
    scope_file = case_dir / "scope.json"
    if scope_file.exists():
        try:
            raw = json.loads(scope_file.read_text())
        except Exception as _e:
            print(f"[report] Scope parse error: {_e}", flush=True)
            raw = case_data.get("scope", [])
    else:
        raw = case_data.get("scope", [])
    lines = [
        "## Scope",
        "",
        "The agreed scope of this engagement is defined by the following:",
        "",
        "| Asset | Type | Restrictions |",
        "| ----- | ---- | ------------ |",
    ]
    entries = []
    if isinstance(raw, dict):
        for t in raw.get("in_scope", []):
            entries.append((t, "IP address" if t.count(".") >= 3 else "Hostname", ""))
        for t in raw.get("out_of_scope", []):
            entries.append((t, "IP address" if t.count(".") >= 3 else "Hostname", "Out of scope"))
    elif isinstance(raw, list):
        for s in raw:
            if isinstance(s, str):
                entries.append((s, "IP address" if s.count(".") >= 3 else "Hostname", ""))
            elif isinstance(s, dict):
                target = s.get("target", "?")
                in_scope = s.get("in_scope", True)
                entries.append((target, "IP address" if target.count(".") >= 3 else "Hostname",
                                "" if in_scope else "Out of scope"))
    if entries:
        for target, typ, rest in entries:
            lines.append(f"| {_md_escape(target, table=True)} | {typ} | {rest} |")
    else:
        lines.append("| TBD | TBD | TBD |")
    lines.append("")
    return lines


def _section_executive_summary(case_data: dict, findings: List[dict]) -> List[str]:
    client = case_data.get("client", "COMPANY")
    case_id = case_data.get("case_id", "?")
    created = case_data.get("created", "")[:10]
    assessment_dates = case_data.get("assessment_dates", created)
    exec_summary_text = case_data.get("executive_summary", "")
    key_obs_text = case_data.get("key_observations", "")
    recommendations_text = case_data.get("recommendations", "")

    total = len(findings)
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = f.get("severity", "info").lower()
        by_sev[s] = by_sev.get(s, 0) + 1
    sev_str = ", ".join(f"{k}={v}" for k, v in sorted(by_sev.items()))

    lines = [
        "## Executive Summary",
        "",
        f"{COMPANY} was engaged to evaluate {client}'s security posture through"
        f" defense penetration testing from ({assessment_dates}). The assessment"
        f" identified {total} findings ({by_sev['critical']} critical,"
        f" {by_sev['high']} high, {by_sev['medium']} medium, {by_sev['low']} low,"
        f" {by_sev['info']} informational) spanning credential management, RBAC"
        " configuration, network segmentation, and secrets storage.",
        "",
    ]

    if exec_summary_text:
        lines += [exec_summary_text, ""]

    # Build attack chain narrative from findings
    critical_findings = [f for f in findings if f.get("severity", "").lower() == "critical"]
    high_findings = [f for f in findings if f.get("severity", "").lower() == "high"]
    if critical_findings or high_findings:
        lines += ["### Attack Chain Narrative", ""]
        lines += ["The following represents a plausible attack path chaining together"
                   " identified findings to achieve full cluster compromise:", ""]
        step = 1
        for f in critical_findings[:4]:
            title = f.get("title", "?")
            lines.append(f"{step}. **{title}** — {f.get('impact', '')[:200]}")
            step += 1
        for f in high_findings[:4]:
            title = f.get("title", "?")
            lines.append(f"{step}. **{title}** — {f.get('impact', '')[:200]}")
            step += 1
        lines.append("")

    lines += [
        "### Testing Summary",
        "",
        f"- **Case ID:** {case_id}",
        f"- **Client:** {client}",
        f"- **Assessment Dates:** {assessment_dates}",
        f"- **Total Findings:** {total}",
        f"- **By Severity:** {sev_str or 'None'}",
        "",
    ]

    if key_obs_text:
        lines += ["### Key Observations", "", key_obs_text, ""]
    else:
        lines += [
            "### Key Observations",
            "",
            "| Finding | Severity | Status |",
            "| ------- | -------- | ------ |",
        ]
        for f in findings[:15]:
            lines.append(
                f"| {_md_escape(f.get('title', '?'), table=True)} "
                f"| {f.get('severity', '?')} "
                f"| {f.get('status', 'open')} |"
            )
        if len(findings) > 15:
            lines.append(f"| _... and {len(findings) - 15} more findings_ | | |")

    if recommendations_text:
        lines += ["### Recommendations", "", recommendations_text, ""]
    else:
        lines += [
            "### Recommendations",
            "",
            "Prioritize remediation of Critical and High severity findings first."
            " See the Findings section for detailed remediation steps for each finding.",
            "",
        ]
    return lines


def _section_strengths(case_data: dict) -> List[str]:
    strengths = case_data.get("strengths", [])
    lines = ["## Strengths", ""]
    if strengths:
        for s in strengths:
            lines.append(f"- {s}")
    else:
        lines.append("_No strengths documented yet._")
    lines.append("")
    return lines


def _section_weaknesses(case_data: dict) -> List[str]:
    weaknesses = case_data.get("weaknesses", [])
    lines = ["## Weaknesses", ""]
    if weaknesses:
        for w in weaknesses:
            lines.append(f"- {w}")
    else:
        lines.append("_No weaknesses documented yet._")
    lines.append("")
    return lines


_TEXT_EXTENSIONS = {".txt", ".log", ".csv", ".json", ".xml", ".yaml", ".yml",
                     ".py", ".sh", ".ps1", ".bat", ".conf", ".cfg", ".ini",
                     ".md", ".html", ".sql", ".rb", ".go", ".java", ".js", ".ts",
                     ".c", ".h", ".cpp", ".hpp", ".env", ".toml", ".lock"}
_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".webp"}

def _render_evidence(evidence_records: List[dict], case_dir: Path) -> List[str]:
    """Render evidence records as code blocks / image embeds / file links."""
    lines = []
    by_filename = {e.get("filename", ""): e for e in evidence_records}
    for filename in sorted(by_filename):
        ev = by_filename[filename]
        stored = Path(ev.get("stored_path", ""))
        ext = Path(filename).suffix.lower()
        desc = ev.get("description", "")

        if not stored.exists():
            lines.append(f"\n> **Evidence:** `{filename}` — file not found at `{stored}`")
            continue

        if ext in _IMAGE_EXTENSIONS:
            try:
                rel = stored.relative_to(case_dir)
            except ValueError:
                rel = stored
            lines += [
                "",
                f"**Evidence — {filename}**" + (f" ({desc})" if desc else ""),
                f"![[{rel}]]",
            ]
        elif ext in _TEXT_EXTENSIONS:
            try:
                content = stored.read_text(encoding="utf-8", errors="replace")[:2000]
                escaped = _html_escape(content)
                lines += [
                    "",
                    f"**Evidence — {filename}**" + (f" ({desc})" if desc else ""),
                    "<pre><code>",
                    escaped,
                    "</code></pre>",
                ]
            except Exception as e:
                lines.append(f"\n> **Evidence:** `{filename}` — read error: {e}")
        else:
            lines.append(f"\n> **Evidence:** `{filename}` ({stored.stat().st_size} bytes)"
                         + (f" — {desc}" if desc else ""))
    return lines


def _section_findings(case_data: dict, findings: List[dict], case_dir: Optional[Path] = None) -> List[str]:
    lines = ["## Pentest Findings", ""]
    if not findings:
        lines.append("_No findings documented._")
        lines.append("")
        return lines

    evidence_records = case_data.get("evidence", [])

    for i, f in enumerate(findings, 1):
        title = f.get("title", "Untitled Finding")
        sev = f.get("severity", "info")
        cve = f.get("cve", "")
        cwe = f.get("cwe", "")
        desc = f.get("description", "")
        impact = f.get("impact", "")
        remediation = f.get("remediation", "")
        references = f.get("references", [])
        source = f.get("source", "")
        poc = f.get("poc", "")
        command_output = f.get("command_output", "")
        status = f.get("status", "unvalidated")
        affected_hosts = f.get("affected_hosts", source)

        me = _md_escape
        lines += [
            f"### #{i} — {me(title)} {{#finding-{i}}}",
            "",
            f"**Severity:** {sev.upper()} &nbsp;&nbsp; **Status:** {status}",
            "",
            "| Field | Value |",
            "| ----- | ----- |",
        ]
        # CWE row
        cwe_str = cwe if cwe else "N/A"
        lines.append(f"| **CWE** | {me(cwe_str, table=True)} |")
        # CVSS row
        cvss_score = f.get("cvss_score")
        cvss_vector = f.get("cvss_vector", "")
        if cvss_score is not None:
            cvss_display = f"{cvss_score}"
            if cvss_vector:
                cvss_display += f" (`{cvss_vector}`)"
            lines.append(f"| **CVSS 3.1 Score** | {cvss_display} |")
        else:
            lines.append(f"| **CVSS 3.1 Score** | N/A |")
        # Description (Incl. Root Cause)
        lines.append(f"| **Description (Incl. Root Cause)** | {me(desc or 'N/A', table=True)} |")
        # Security Impact
        lines.append(f"| **Security Impact** | {me(impact or 'N/A', table=True)} |")
        # Affected Host(s)
        hosts = affected_hosts or "N/A"
        lines.append(f"| **Affected Host(s)** | {me(hosts, table=True)} |")
        # Remediation
        lines.append(f"| **Remediation** | {me(remediation or 'N/A', table=True)} |")
        # External References
        if references:
            ref_str = "; ".join(me(r, table=True) for r in references[:5])
            lines.append(f"| **External References** | {ref_str} |")
        else:
            lines.append(f"| **External References** | N/A |")

        # Tags (optional)
        ftags = f.get("tags", [])
        if ftags:
            lines.append(f"| **Tags** | {', '.join(me(t) for t in ftags)} |")

        # Proof of Concept section — uses ```poc language tag for terminal styling
        has_poc = bool(poc or command_output)
        if has_poc:
            lines += ["", "---", "", "#### Proof of Concept", ""]
            if poc:
                lines += [
                    "",
                    "```poc",
                    poc[:2000],
                    "```",
                ]
            if command_output:
                lines += [
                    "",
                    "**Command Output:**",
                    "```poc",
                    command_output[:4000],
                    "```",
                ]

        # Render linked evidence
        evidence_refs = f.get("evidence_refs", [])
        if evidence_refs:
            linked = [e for e in evidence_records if e.get("filename") in evidence_refs]
            if linked:
                lines += ["", "---", "", "**Finding Evidence:**"]
                lines += _render_evidence(linked, case_dir)

        lines.append("")
    return lines


def _section_risk_matrix() -> List[str]:
    return [
        "## Risk Assessment Matrix",
        "",
        "### Vulnerability Risk Scoring",
        "",
        "| Criticality | Score | Description | Examples |",
        "|-------------|-------|-------------|----------|",
        "| Critical | 9-10 | Immediate threat, system compromise, data breach | Remote code execution, domain admin access |",
        "| High | 7-8 | Significant impact, lateral movement possible | Local admin access, sensitive data exposure |",
        "| Medium | 4-6 | Limited impact, requires conditions | Information disclosure, privilege escalation |",
        "| Low | 1-3 | Minimal impact, difficult to exploit | Information disclosure, minor misconfigurations |",
        "",
        "### Risk Calculation Formula",
        "",
        "**Risk = (Impact × Likelihood) ÷ 10**",
        "",
        "| Impact Level | Score | Examples |",
        "|--------------|-------|----------|",
        "| Catastrophic | 5 | Complete system compromise, data breach |",
        "| High | 4 | Significant service disruption, data exposure |",
        "| Medium | 3 | Partial service impact, limited data exposure |",
        "| Low | 2 | Minor functionality impact, no data exposure |",
        "",
        "| Likelihood Level | Score | Examples |",
        "|------------------|-------|----------|",
        "| Almost Certain | 5 | Exploit publicly available, no auth |",
        "| Likely | 4 | Known vuln, weak controls |",
        "| Possible | 3 | Conditions required, moderate controls |",
        "| Unlikely | 2 | Difficult conditions, strong controls |",
        "",
        "### Risk Treatment Options",
        "",
        "| Treatment | Description | When to Use |",
        "|-----------|-------------|-------------|",
        "| Mitigate | Reduce likelihood/impact through controls | When risk is acceptable with controls |",
        "| Transfer | Shift risk to third party (insurance, contracts) | When risk is too high to retain |",
        "| Accept | Document and monitor risk | When cost of treatment exceeds risk |",
        "| Avoid | Eliminate risk by changing approach | When risk cannot be adequately treated |",
        "",
    ]


def _section_methodology(case_data: dict = None) -> List[str]:
    cd = case_data or {}
    tools_str = cd.get("methodology_tools", "")
    tools_list = [t.strip() for t in tools_str.split(",") if t.strip()] if tools_str else [
        "Nmap", "Nuclei", "Burp Suite/Caido", "Certipy", "BloodHound",
        "Kerbrute", "NetExec", "Mimikatz", "LaZagne", "Wireshark",
    ]
    return [
        "## Methodology",
        "",
        "The assessment followed industry-standard penetration testing methodology:",
        "",
        "1. **Planning** — Scope definition, rules of engagement, customer goals.",
        "2. **Reconnaissance** — Passive and active intelligence gathering.",
        "3. **Scanning & Enumeration** — Port scanning, service detection, vulnerability scanning.",
        "4. **Exploitation** — Validating identified vulnerabilities.",
        "5. **Post-Exploitation** — Pivoting, lateral movement, privilege escalation.",
        "6. **Reporting** — Documentation of findings, evidence, and recommendations.",
        "",
        "Tools used during this assessment include but are not limited to:",
        ", ".join(tools_list) + ".",
        "",
    ]


def _section_appendix_flags(case_dir: Path, case_data: dict = None) -> List[str]:
    """Render Appendix A – Flags Discovered table from case data or flags.json."""
    cd = case_data or {}
    flags = cd.get("flags", [])

    # Try loading from flags.json if not in case.json
    if not flags:
        flags_file = case_dir / "flags.json"
        if flags_file.exists():
            try:
                flags = json.loads(flags_file.read_text())
                if isinstance(flags, dict):
                    flags = flags.get("flags", [])
            except Exception:
                flags = []

    lines = ["## Appendix A – Flags Discovered", ""]
    if not flags:
        lines.append("_No flags or artifacts were captured during this assessment._")
        lines.append("")
        return lines

    lines += [
        "The following flags and artifacts were discovered during the assessment:",
        "",
        "| # | Application | Flag Value | Location | Method |",
        "|---|-------------|------------|----------|--------|",
    ]
    for i, f in enumerate(flags, 1):
        number = f.get("flag_number", str(i))
        app = _md_escape(str(f.get("application", "")), table=True)
        val = _md_escape(str(f.get("flag_value", "")), table=True)
        loc = _md_escape(str(f.get("flag_location", "")), table=True)
        method = _md_escape(str(f.get("method_used", "")), table=True)
        lines.append(f"| {number} | {app} | {val} | {loc} | {method} |")
    lines.append("")
    return lines


# ---------------------------------------------------------------------------
# Main report assemblers
# ---------------------------------------------------------------------------

def _heading_anchor(text: str) -> str:
    """Convert a heading title to an HTML anchor ID."""
    return text.lower().replace(" ", "-").replace("/", "").replace("&", "and")


def _generate_toc(sections: List[str], findings: List[dict]) -> List[str]:
    """Generate a table of contents from sections + findings.

    Uses a numbered list that renders cleanly across all formats (MD, HTML, DOCX, PDF).
    HTML anchors are generated by the heading renderer itself; the TOC uses simple numbering.
    """
    lines = ["## Table of Contents", ""]
    section_num = 0
    for name in sections:
        section_num += 1
        lines.append(f"{section_num}. {name}")
        if name == "Findings" and findings:
            for i, f in enumerate(findings, 1):
                sev = f.get("severity", "info").upper()
                title = f.get("title", "?")
                lines.append(f"    - **{section_num}.{i}** {sev}: {title}")
    lines.append("")
    lines.append("---")
    lines.append("")
    return lines


def _generate_screenshots_section(case_dir: Path) -> List[str]:
    """Embed evidence screenshots found in the case directory."""
    lines = ["## Evidence Screenshots", ""]
    evidence_dir = case_dir / "evidence"
    img_count = 0
    if evidence_dir.exists():
        for ext in ("*.png", "*.jpg", "*.jpeg", "*.gif"):
            for img in sorted(evidence_dir.glob(ext)):
                try:
                    rel = img.relative_to(case_dir)
                except ValueError:
                    rel = img
                lines += [
                    "",
                    f"### {img.stem}",
                    f"![[{rel}]]",
                    "",
                ]
                img_count += 1
    if img_count == 0:
        lines.append("_No evidence screenshots available._")
    lines.append("")
    return lines


def _render_report_markdown(case_data: dict, findings: List[dict],
                             case_dir: Optional[Path] = None,
                             report_version: str = "1.0") -> str:
    """Build the full Markdown report from sections. Pure Markdown — no HTML tags."""
    case_id = case_data.get("case_id", "?")
    client = case_data.get("client", "") or "COMPANY"
    dates = case_data.get("created", "")[:10] or "DATES"
    cd = case_dir or Path()
    case_type = case_data.get("case_type", "pentest")
    sections = _sections_for_case(case_type)
    assessment_dates = case_data.get("assessment_dates", dates)

    lines = [
        "# Private Web Application",
        "# Security Assessment",
        "",
        "## Report of Findings",
        "",
        f"**{client}**",
        "",
        f"**{assessment_dates}**",
        "",
        f"**Version {report_version}**",
        "",
        f"*Confidential — {COMPANY}*",
        "",
        "---",
        "",
        "",
    ]

    # Generate Table of Contents
    lines += _generate_toc(sections, findings)

    for section_name in sections:
        if section_name == "Confidentiality Statement":
            lines += _section_confidentiality(client)
        elif section_name == "Disclaimer":
            lines += _section_disclaimer(dates, client)
        elif section_name == "Contact Information":
            lines += _section_contact(case_data)
        elif section_name == "Engagement Contacts":
            lines += _section_engagement_contacts(case_data)
        elif section_name == "Assessment Overview":
            lines += _section_assessment_overview(client, dates, case_data)
        elif section_name == "Scope":
            lines += _section_scope(cd, case_data)
        elif section_name == "Executive Summary":
            lines += _section_executive_summary(case_data, findings)
        elif section_name == "Strengths":
            lines += _section_strengths(case_data)
        elif section_name == "Weaknesses":
            lines += _section_weaknesses(case_data)
        elif section_name == "Findings":
            lines += _section_findings(case_data, findings, case_dir=cd)
        elif section_name == "Risk Assessment Matrix":
            lines += _section_risk_matrix()
        elif section_name == "Methodology":
            lines += _section_methodology(case_data)
        elif section_name == "Appendix A – Flags Discovered":
            lines += _section_appendix_flags(cd, case_data)
        lines.append("")

    # Add evidence screenshots section (looks in case_dir/evidence/ for images)
    lines += _generate_screenshots_section(cd)

    lines += [
        "---",
        "",
        f"*Report generated by {COMPANY} — {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC*",
        "",
    ]
    raw = "\n".join(lines)
    # Convert Obsidian ![[path]] embeds to standard Markdown image syntax
    raw = re.sub(r'!\[\[([^\]]+\.(png|jpg|jpeg|gif|bmp|svg|webp))\]\]',
                 r'![\1](\1)', raw, flags=re.IGNORECASE)
    # Non-image Obsidian embeds → plain file references
    raw = re.sub(r'!\[\[([^\]]+)\]\]', r'[\1](\1)', raw)
    # Strip remaining HTML divs (pandoc leak)
    raw = re.sub(r'<div[^>]*>', '', raw)
    raw = re.sub(r'</div>', '', raw)
    return raw


def _render_report_html(case_data: dict, findings: List[dict],
                         case_dir: Optional[Path] = None) -> str:
    """Build an HTML version of the same report with full styling (cover page, badges, page nums)."""
    md = _render_report_markdown(case_data, findings, case_dir=case_dir)
    md = re.sub(r'!\[([^\]]*)\]\(evidence/', r'![\1](../evidence/', md)
    case_id = case_data.get("case_id", "?")
    # Prepend logo to markdown so it appears on the cover page
    logo_tag = _logo_base64_tag(case_dir)
    if logo_tag:
        md = f"{logo_tag}\n\n{md}"
    return _md_to_html_full(md, f"Engagement Report — {case_id}")


def _inline_md_to_html(text: str) -> str:
    """Convert inline markdown (**bold**, *italic*, `code`) to HTML."""
    text = _html_escape(text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"\*(.+?)\*", r"<em>\1</em>", text)
    text = re.sub(r"`(.+?)`", r"<code>\1</code>", text)
    return text


def _md_to_html_simple(md: str) -> str:
    """Convert Markdown to clean HTML with proper tables, lists, emphasis, code."""
    html = []
    in_code = False
    in_ul = False
    in_ol = False
    in_table = False
    table_header = False
    page_break_active = False

    def close_ul():
        nonlocal in_ul
        if in_ul:
            html.append("</ul>")
            in_ul = False

    def close_ol():
        nonlocal in_ol
        if in_ol:
            html.append("</ol>")
            in_ol = False

    def close_table():
        nonlocal in_table, table_header
        if in_table:
            if table_header:
                html.append("</thead>")
                table_header = False
            html.append("</tbody></table>")
            in_table = False

    in_pre = False
    in_table_html = False

    for line in md.split("\n"):
        stripped = line.strip()

        # Safety: close raw HTML table passthrough if we hit a heading, code fence, or hr mark
        if in_table_html and (stripped.startswith("```") or stripped.startswith("#") or stripped in ("---", "***", "___")):
            html.append("</table>\n")
            in_table_html = False

        # Raw HTML <pre> pass-through (used by evidence rendering)
        if stripped.startswith("<pre"):
            close_ul()
            close_ol()
            close_table()
            html.append(stripped)
            in_pre = True
            continue
        if in_pre:
            html.append(line + "\n")
            if "</pre>" in stripped:
                in_pre = False
            continue

        # Raw HTML <table> pass-through (turndown may emit raw table HTML from Quill's non-standard format)
        if stripped.startswith("<table"):
            close_ul()
            close_ol()
            close_table()
            html.append(stripped)
            in_table_html = "</table>" not in stripped
            continue
        if in_table_html:
            html.append(line + "\n")
            if "</table>" in stripped:
                in_table_html = False
            continue

        # Code blocks (supports info strings like ```poc for terminal styling)
        if stripped.startswith("```"):
            close_ul()
            close_ol()
            close_table()
            in_code = not in_code
            if in_code:
                info = stripped[3:].strip()
                if info == "poc":
                    html.append('<pre class="poc-shell"><code>')
                else:
                    html.append("<pre><code>")
            else:
                html.append("</code></pre>")
            continue
        if in_code:
            html.append(_html_escape(line) + "\n")
            continue

        # Horizontal rule
        if stripped in ("---", "***", "___") and len(stripped) >= 3:
            close_ul()
            close_ol()
            close_table()
            html.append("<hr>")
            continue

        # HTML div (page breaks)
        if stripped.startswith("<div"):
            close_ul()
            close_ol()
            close_table()
            html.append(stripped)
            continue
        if stripped.startswith("</div>"):
            html.append(stripped)
            continue

        # Tables
        if stripped.startswith("|"):
            cells = [c.strip() for c in stripped.split("|")[1:-1]]
            # Skip separator rows (|---|---|---|)
            if cells and all(re.sub(r"[-:\s]", "", c) == "" for c in cells):
                continue
            if not in_table:
                html.append("<table>")
                in_table = True
                table_header = True
                html.append("<thead><tr>")
                for c in cells:
                    html.append(f"<th>{_inline_md_to_html(c)}</th>")
                html.append("</tr></thead><tbody>")
                table_header = False
            else:
                html.append("<tr>")
                for c in cells:
                    html.append(f"<td>{_inline_md_to_html(c)}</td>")
                html.append("</tr>")
            continue

        # End table if we hit non-table content
        if in_table:
            html.append("</tbody></table>")
            in_table = False

        # Headings
        if stripped.startswith("#### "):
            close_ul()
            close_ol()
            html.append(f"<h4>{_inline_md_to_html(stripped[5:])}</h4>")
            continue
        if stripped.startswith("### "):
            close_ul()
            close_ol()
            name = stripped[4:]
            anchor = ""
            attr_match = re.match(r'(.+?)\s+\{#([^}]+)\}$', name)
            if attr_match:
                name = attr_match.group(1)
                anchor = f' id="{attr_match.group(2)}"'
            html.append(f"<h3{anchor}>{_inline_md_to_html(name)}</h3>")
            continue
        if stripped.startswith("## "):
            close_ul()
            close_ol()
            name = stripped[3:]
            anchor = _heading_anchor(name)
            html.append(f'<h2 id="{anchor}">{_inline_md_to_html(name)}</h2>')
            continue
        if stripped.startswith("# "):
            close_ul()
            close_ol()
            html.append(f"<h1>{_inline_md_to_html(stripped[2:])}</h1>")
            continue

        # Unordered lists (support both - and * markers)
        ul_match = re.match(r"^(\s*)[-*]\s+(.+)", stripped)
        if ul_match:
            close_table()
            close_ol()
            if not in_ul:
                html.append("<ul>")
                in_ul = True
            html.append(f"<li>{_inline_md_to_html(ul_match.group(2))}</li>")
            continue

        # Ordered lists (handle any number for continuation, including indented sub-items)
        ol_match = re.match(r"^(\s*)(\d+(?:\.\d+)*)\.\s+(.+)", stripped)
        if ol_match:
            close_table()
            close_ul()
            num = ol_match.group(2)
            content = f"{num}. {ol_match.group(3)}"
            if not in_ol:
                html.append("<ol>")
                in_ol = True
            html.append(f"<li value=\"{num}\">{_inline_md_to_html(content)}</li>")
            continue

        # Blank line — close lists and table
        if stripped == "":
            close_ul()
            close_ol()
            close_table()
            continue

        # Image (Markdown ![]())
        img_match = re.match(r'^!\[(.*)\]\((.+)\)$', stripped)
        if img_match:
            close_table()
            close_ul()
            close_ol()
            alt = _html_escape(img_match.group(1))
            src = _html_escape(img_match.group(2))
            html.append(f'<img src="{src}" alt="{alt}" style="max-width:100%;height:auto;" />')
            continue

        # Regular paragraph
        close_ul()
        close_ol()
        if stripped:
            html.append(f"<p>{_inline_md_to_html(stripped)}</p>")
        else:
            html.append("<br>")

    # Close any open tags
    close_ul()
    close_ol()
    close_table()
    if in_code:
        html.append("</code></pre>")

    return "\n".join(html)


# ---------------------------------------------------------------------------
# Public API — called by CLI and MCP server
# ---------------------------------------------------------------------------

def generate_engagement_report(case_dir: Path) -> str:
    """Generate both HTML and Markdown engagement reports.

    Returns path to the HTML report (for backward compatibility).
    """
    case_data, findings = _load_case(case_dir)
    reports_dir = case_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    logo_tag = _logo_base64_tag(case_dir)

    # Generate Markdown report with base64 logo
    md = _render_report_markdown(case_data, findings, case_dir=case_dir)
    md = re.sub(r'!\[([^\]]*)\]\(evidence/', r'![\1](../evidence/', md)
    if logo_tag:
        md = f"{logo_tag}\n\n{md}"
    md_path = reports_dir / "engagement-report.md"
    md_path.write_text(md, encoding="utf-8")

    # Generate HTML report with full styling
    html = _render_report_html(case_data, findings, case_dir=case_dir)
    html_path = reports_dir / "engagement-report.html"
    html_path.write_text(html, encoding="utf-8")

    return html_path.as_posix()


def generate_obsidian_report(
    case_dir: Path,
    output_dir: Optional[Path] = None,
    write_sections: bool = True,
    formats: Optional[List[str]] = None,
    report_version: str = "1.0",
) -> Dict[str, str]:
    """Generate an Obsidian-compatible pentest report matching the template structure.

    Generates .md (always), plus .html, .docx, .pdf if converters are available.

    Args:
        case_dir: Case directory (contains case.json, findings.json)
        output_dir: Where to write the report (defaults to vault's Pentests/c-reports/{case_id}/)
        write_sections: If True, also write individual section files in Data/ subdir
        formats: List of formats to generate (default: ['md','html','docx','pdf'])
        report_version: Version string for the report (default: "1.0")

    Returns:
        Dict mapping format extension to file path, e.g. {'md': '/path/to/file.md', ...}
    """
    from .constants import PENTEST_NOTES_DIR
    case_data, findings = _load_case(case_dir)
    case_id = case_data.get("case_id", "?")
    case_type = case_data.get("case_type", "pentest")
    out = Path(output_dir or PENTEST_NOTES_DIR / case_id)
    out.mkdir(parents=True, exist_ok=True)

    version = case_data.get("report_version", report_version)
    assessment_dates = case_data.get("assessment_dates", case_data.get("created", "")[:10])

    data_dir = out / "Data"
    if write_sections:
        data_dir.mkdir(exist_ok=True)

    formats = formats or ["md", "html", "docx", "pdf"]

    sections = _sections_for_case(case_type)

    # Render sections
    section_bodies = {}
    for section_name in sections:
        lines = []
        if section_name == "Confidentiality Statement":
            lines = _section_confidentiality(case_data.get("client", ""))
        elif section_name == "Disclaimer":
            lines = _section_disclaimer(case_data.get("created", "")[:10], case_data.get("client", ""))
        elif section_name == "Contact Information":
            lines = _section_contact(case_data)
        elif section_name == "Engagement Contacts":
            lines = _section_engagement_contacts(case_data)
        elif section_name == "Assessment Overview":
            lines = _section_assessment_overview(case_data.get("client", ""),
                                                 case_data.get("created", "")[:10],
                                                 case_data)
        elif section_name == "Scope":
            lines = _section_scope(case_dir, case_data)
        elif section_name == "Executive Summary":
            lines = _section_executive_summary(case_data, findings)
        elif section_name == "Strengths":
            lines = _section_strengths(case_data)
        elif section_name == "Weaknesses":
            lines = _section_weaknesses(case_data)
        elif section_name == "Findings":
            lines = _section_findings(case_data, findings, case_dir=case_dir)
        elif section_name == "Risk Assessment Matrix":
            lines = _section_risk_matrix()
        elif section_name == "Methodology":
            lines = _section_methodology(case_data)
        elif section_name == "Appendix A – Flags Discovered":
            lines = _section_appendix_flags(case_dir, case_data)
        section_bodies[section_name] = "".join(f"{l}\n" for l in lines)
        if write_sections:
            (data_dir / f"{section_name}.md").write_text(section_bodies[section_name], encoding="utf-8")

    # Main report note with embeds (Obsidian template style) — no HTML tags
    client = case_data.get("client", "") or "COMPANY"
    report_lines = [
        "",
        "![[./Data/Logo Try 2.png]]",
        "",
        "# Private Web Application",
        "# Security Assessment",
        "",
        "## Report of Findings",
        "",
        f"**{client}**",
        "",
        f"**{assessment_dates}**",
        "",
        f"**Version {version}**",
        "",
        "",
        "",
        "",
        "",
        "",
        "### Business Confidential",
        "",
        "---",
        "",
    ]
    for section_name in sections:
        report_lines.append(f"![[./Data/{section_name}]]\n")

    # Self-contained Markdown (for conversion to docx/pdf, no HTML tags)
    flat = _render_report_markdown(case_data, findings, case_dir=case_dir)

    # Copy logo to Data/ for Obsidian vault embeds
    logo_tag = _logo_base64_tag(case_dir)
    if logo_tag and write_sections:
        logo_src = _find_logo(case_dir)
        if logo_src:
            try:
                shutil.copy2(str(logo_src), str(data_dir / "Logo Try 2.png"))
            except Exception:
                logger.debug("Exception copying logo", exc_info=True)

    # Prepend base64 logo to flat markdown so HTML/DOCX/PDF also get it.
    flat_with_logo = f"{logo_tag}\n\n{flat}" if logo_tag else flat

    # Copy case evidence into Data/ so Obsidian can embed images
    evidence_dir = case_dir / "evidence"
    if evidence_dir.exists() and write_sections:
        for ev_file in evidence_dir.iterdir():
            if ev_file.is_file():
                try:
                    shutil.copy2(str(ev_file), str(data_dir / ev_file.name))
                except Exception:

                    logger.debug("Exception in report_generator.py", exc_info=True)

    # Write files
    results = {}
    base_name = f"pentest-report-{case_id}"

    if "md" in formats:
        (out / f"{base_name}.md").write_text("\n".join(report_lines), encoding="utf-8")
        results["md"] = (out / f"{base_name}.md").as_posix()

    if "html" in formats:
        html = _md_to_html_full(flat_with_logo, f"Pentest Report — {case_id}")
        html_path = out / f"{base_name}.html"
        html_path.write_text(html, encoding="utf-8")
        results["html"] = html_path.as_posix()

    if "docx" in formats:
        docx_path = _convert_md_to_docx(flat_with_logo, out / f"{base_name}.docx", case_id, work_dir=out, case_dir=case_dir)
        if docx_path:
            results["docx"] = docx_path.as_posix()

    if "pdf" in formats:
        html_for_pdf = out / f"{base_name}.html"
        # Ensure HTML is generated first (may not be if pdf was requested alone)
        if not html_for_pdf.exists() and "html" not in formats:
            html_for_pdf.write_text(
                _md_to_html_full(flat_with_logo, f"Pentest Report — {case_id}"),
                encoding="utf-8",
            )
        pdf_path = _convert_html_to_pdf(html_for_pdf, out / f"{base_name}.pdf", case_id, case_dir=case_dir)
        if pdf_path:
            results["pdf"] = pdf_path.as_posix()

    return results


def _embed_images_as_base64(html: str, case_dir: Path) -> str:
    """Replace relative <img src='...'> paths with base64 data URIs so pandoc/weasyprint
    can render images without needing the filesystem path to exist at conversion time."""
    def _replacer(match):
        tag = match.group(0)
        src_m = re.search(r'src="([^"]+)"', tag)
        if not src_m:
            return tag
        src = src_m.group(1)
        if src.startswith('data:') or src.startswith('http://') or src.startswith('https://'):
            return tag
        # Try resolving relative to case_dir
        candidates = [
            case_dir / src,
            case_dir / src.replace('../evidence/', 'evidence/'),
            case_dir / 'evidence' / Path(src).name,
        ]
        for cand in candidates:
            try:
                cand = cand.resolve()
                if cand.exists():
                    data = cand.read_bytes()
                    ext = cand.suffix.lower().lstrip('.')
                    mime = {'png': 'image/png', 'jpg': 'image/jpeg', 'jpeg': 'image/jpeg',
                            'gif': 'image/gif', 'bmp': 'image/bmp', 'svg': 'image/svg+xml',
                            'webp': 'image/webp'}.get(ext, 'application/octet-stream')
                    b64data = base64.b64encode(data).decode('ascii')
                    new_src = f'data:{mime};base64,{b64data}'
                    return tag.replace(f'src="{src}"', f'src="{new_src}"')
            except Exception:
                pass
        return tag
    return re.sub(r'<img[^>]+>', _replacer, html, flags=re.IGNORECASE)


_POC_INLINE_STYLE = 'background:#000;color:#fff;border:1px solid #555;'
_TABLE_TH_STYLE = 'background:#1a1a2e;color:#fff;font-weight:600;padding:6px 10px;text-align:left;border:1px solid #ccc;'


def _add_poc_inline_styles(html: str) -> str:
    """Add inline styles to PoC code blocks so pandoc/weasyprint render terminal boxes.

    Handles two cases:
    1. <pre class="poc-shell"> — explicit from _md_to_html_simple (```poc tag preserved)
    2. <h4>Proof of Concept</h4> … <pre> — context detection when tag was lost in Quill round-trip
    """
    # Case 1: explicit poc-shell class
    html = html.replace(
        '<pre class="poc-shell">',
        f'<pre class="poc-shell" style="{_POC_INLINE_STYLE}">'
    )
    # Case 2: <h4>…Proof of Concept…</h4> followed by <pre>
    result = []
    pos = 0
    for m in re.finditer(r'<h4[^>]*>.*?Proof\s*of\s*Concept.*?</h4>', html, re.IGNORECASE):
        result.append(html[pos:m.end()])
        pos = m.end()
        rest = html[pos:]
        # Find the next <pre> tag that isn't already styled
        pre_m = re.search(r'<pre(?:\s[^>]*)?>', rest)
        if pre_m and 'style=' not in pre_m.group():
            result.append(rest[:pre_m.start()])
            result.append(f'<pre style="{_POC_INLINE_STYLE}">')
            pos += pre_m.start() + len(pre_m.group())
        else:
            result.append(rest)
            pos = len(html)
            break
    result.append(html[pos:])
    return ''.join(result)


def _add_table_th_styles(html: str) -> str:
    """Add inline styles to <th> elements for pandoc HTML→DOCX compatibility.
    CSS class-based styles are ignored by pandoc's DOCX writer."""
    def _style_th(m):
        tag = m.group(0)
        if 'style=' in tag:
            return tag
        return f'<th style="{_TABLE_TH_STYLE}">'
    return re.sub(r'<th(?:\s[^>]*?)?>', _style_th, html)


def _convert_md_to_docx(md_text: str, out_path: Path, title: str = "",
                         work_dir: Optional[Path] = None,
                         case_dir: Optional[Path] = None) -> Optional[Path]:
    """Convert Markdown text to DOCX using pandoc (HTML→docx preferred).

    Writes to work_dir if provided so relative image paths resolve.
    """
    if work_dir:
        work_dir.mkdir(parents=True, exist_ok=True)
    else:
        import tempfile
        work_dir = Path(tempfile.mkdtemp())

    cleanup_files = []

    try:
        # Convert md → html first for better CSS→DOCX style mapping
        html_content = _md_to_html_full(md_text, title)
        # Embed images as base64 so pandoc finds them regardless of working directory
        if case_dir:
            html_content = _embed_images_as_base64(html_content, case_dir)
        # Add inline styles for PoC terminal blocks and table headers (pandoc strips CSS classes)
        html_content = _add_poc_inline_styles(html_content)
        html_content = _add_table_th_styles(html_content)
        html_path = work_dir / "_convert_temp.html"
        html_path.write_text(html_content, encoding="utf-8")
        cleanup_files.append(html_path)

        # Try pandoc with HTML source (best style preservation)
        try:
            subprocess.run(
                ["pandoc", str(html_path), "-o", str(out_path),
                 "--metadata", f"title={title}", "--from", "html"],
                capture_output=True, text=True, timeout=60,
            )
            if out_path.exists():
                for p in cleanup_files:
                    p.unlink(missing_ok=True)
                if work_dir and str(work_dir).endswith("_convert_temp"):
                    import shutil
                    shutil.rmtree(str(work_dir), ignore_errors=True)
                return out_path
        except Exception:
            logger.debug("pandoc HTML→docx failed", exc_info=True)

        # Fallback: pandoc md → docx
        md_path = work_dir / "_convert_temp.md"
        md_path.write_text(md_text, encoding="utf-8")
        cleanup_files.append(md_path)
        try:
            subprocess.run(
                ["pandoc", str(md_path), "-o", str(out_path),
                 "--metadata", f"title={title}", "--from", "markdown"],
                capture_output=True, text=True, timeout=60,
            )
            if out_path.exists():
                for p in cleanup_files:
                    p.unlink(missing_ok=True)
                if work_dir and str(work_dir).endswith("_convert_temp"):
                    import shutil
                    shutil.rmtree(str(work_dir), ignore_errors=True)
                return out_path
        except Exception:
            logger.debug("pandoc md→docx failed", exc_info=True)

        # Last resort: python-docx
        try:
            from docx import Document
            doc = Document()
            doc.add_heading(title or "Pentest Report", level=1)
            for line in md_text.split("\n"):
                if line.startswith("## "):
                    doc.add_heading(line[3:], level=2)
                elif line.startswith("### "):
                    doc.add_heading(line[4:], level=3)
                elif line.startswith("|"):
                    doc.add_paragraph(line)
                elif line.strip():
                    doc.add_paragraph(line.strip())
            doc.save(str(out_path))
            if out_path.exists():
                for p in cleanup_files:
                    p.unlink(missing_ok=True)
                if work_dir and str(work_dir).endswith("_convert_temp"):
                    import shutil
                    shutil.rmtree(str(work_dir), ignore_errors=True)
                return out_path
        except Exception:
            logger.debug("python-docx fallback failed", exc_info=True)
    finally:
        for p in cleanup_files:
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass
        if work_dir and str(work_dir).endswith("_convert_temp"):
            import shutil
            shutil.rmtree(str(work_dir), ignore_errors=True)
    return None


def _convert_html_to_pdf(html_path: Path, out_path: Path, title: str = "",
                          case_dir: Optional[Path] = None) -> Optional[Path]:
    """Convert an HTML file directly to PDF via weasyprint.

    This is preferred over pandoc-based conversion because it preserves
    all CSS styling (code blocks, tables, colors, page breaks).
    """
    if not html_path.exists():
        return None
    try:
        # Read, enhance with inline styles, and embed images as base64 so weasyprint finds them
        html_content = html_path.read_text(encoding="utf-8")
        html_content = _add_poc_inline_styles(html_content)
        html_content = _add_table_th_styles(html_content)
        if case_dir:
            html_content = _embed_images_as_base64(html_content, case_dir)
        html_path.write_text(html_content, encoding="utf-8")
        from weasyprint import HTML
        HTML(filename=str(html_path)).write_pdf(str(out_path))
        if out_path.exists():
            return out_path
    except Exception:

        logger.debug("Exception in report_generator.py", exc_info=True)
    return None


def _convert_md_to_pdf(md_text: str, out_path: Path, title: str = "",
                         work_dir: Optional[Path] = None,
                         case_dir: Optional[Path] = None) -> Optional[Path]:
    """Convert Markdown text to PDF using pandoc+wkhtmltopdf or weasyprint.

    If work_dir is provided, the markdown is written there so relative
    image paths resolve correctly during pandoc conversion.
    """
    if work_dir:
        work_dir.mkdir(parents=True, exist_ok=True)
        md_path = work_dir / "_convert_temp.md"
        md_path.write_text(md_text, encoding="utf-8")
        cleanup = lambda: md_path.unlink(missing_ok=True)
    else:
        import tempfile
        tmp = tempfile.NamedTemporaryFile(suffix=".md", delete=False, mode="w", encoding="utf-8")
        tmp.write(md_text)
        md_path = Path(tmp.name)
        tmp.close()
        cleanup = lambda: md_path.unlink(missing_ok=True)

    # Try pandoc with weasyprint or wkhtmltopdf
    for engine in ("weasyprint", "wkhtmltopdf", "pdflatex"):
        try:
            cmd = ["pandoc", str(md_path), "-o", str(out_path),
                   "--metadata", f"title={title}", "--from", "markdown",
                   "--pdf-engine", engine]
            subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if out_path.exists():
                cleanup()
                return out_path
        except Exception as _e:
            print(f"[report] PDF engine failed: {_e}", flush=True)
            continue

    # Fallback: try weasyprint directly from HTML
    try:
        from weasyprint import HTML
        html = _md_to_html_full(md_text, title)
        if case_dir:
            html = _embed_images_as_base64(html, case_dir)
        html = _add_poc_inline_styles(html)
        html = _add_table_th_styles(html)
        HTML(string=html).write_pdf(str(out_path))
        if out_path.exists():
            cleanup()
            return out_path
    except Exception:

        logger.debug("Exception in report_generator.py", exc_info=True)

    cleanup()
    return None


def _md_to_html_body(md_text: str, title: str = "") -> str:
    """Convert full markdown report to HTML with branding, cover page, and professional styling."""
    body = _md_to_html_simple(md_text)

    # Split on first <hr> to separate cover content from body
    parts = body.split("<hr>", 1)
    cover = parts[0] if len(parts) > 1 else ""
    rest = parts[1] if len(parts) > 1 else parts[0]

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{_html_escape(title)}</title>
<style>
  @page {{
    size: letter;
    margin: 2.5cm 2cm 2cm 2cm;
    @bottom-center {{
      content: counter(page);
      font-family: 'Segoe UI', Arial, sans-serif;
      font-size: 9pt;
      color: #888;
    }}
  }}
  @page:first {{
    @bottom-center {{ content: none; }}
  }}
  body {{
    font-family: 'Segoe UI', Arial, Helvetica, sans-serif;
    color: #222;
    line-height: 1.6;
    font-size: 10.5pt;
    word-break: break-word;
    overflow-wrap: break-word;
  }}
  /* Cover page */
  .cover-page {{
    page-break-after: always;
    text-align: center;
    padding-top: 6cm;
  }}
  .cover-page img {{
    max-width: 300px;
    margin-bottom: 2cm;
  }}
  .cover-page h1 {{
    font-size: 24pt;
    color: #1a1a2e;
    border: none;
    margin-bottom: 0.5cm;
  }}
  .cover-page h3 {{
    font-size: 14pt;
    color: #555;
    font-weight: normal;
    border: none;
    margin-top: 0;
  }}
  .cover-page .version {{
    margin-top: 0.5cm;
    font-size: 11pt;
    color: #555;
  }}
  .cover-page .confidential {{
    margin-top: 4cm;
    font-size: 11pt;
    color: #888;
    font-style: italic;
  }}
  /* Headings */
  h1 {{
    color: #1a1a2e;
    border-bottom: 3px solid #e94560;
    padding-bottom: 0.3em;
    font-size: 18pt;
    margin-top: 1.5em;
  }}
  h2 {{
    color: #16213e;
    margin-top: 1.5em;
    border-bottom: 1px solid #ddd;
    padding-bottom: 0.2em;
    font-size: 14pt;
  }}
  h3 {{
    color: #0f3460;
    font-size: 12pt;
    margin-top: 1.2em;
  }}
  h4 {{
    color: #333;
    font-size: 11pt;
    margin-top: 1em;
  }}
  /* Tables */
  table {{
    border-collapse: collapse;
    width: 100%;
    margin: 0.8em 0;
    font-size: 9.5pt;
  }}
  td {{
    border: 1px solid #ccc;
    padding: 6px 10px;
    text-align: left;
    vertical-align: top;
    word-break: break-word;
    overflow-wrap: break-word;
  }}
  thead th {{
    background: #1a1a2e;
    color: #fff;
    font-weight: 600;
  }}
  tr:nth-child(even) {{
    background: #f8f8f8;
  }}
  /* Finding tables - vertical key/value style */
  h3 + table thead th:first-child {{
    width: 140px;
    background: #f0f0f0;
    color: #333;
    font-weight: 600;
  }}
  /* Code */
  pre {{
    background: #1e1e2e;
    color: #cdd6f4;
    padding: 0.8em 1em;
    border-radius: 4px;
    overflow-x: auto;
    font-size: 9pt;
    line-height: 1.4;
    word-break: break-word;
    overflow-wrap: break-word;
    white-space: pre-wrap;
  }}
  /* Terminal-style boxes for Proof of Concept sections */
  pre.poc-shell {{
    background: #000;
    color: #fff;
    border: 1px solid #555;
  }}
  code {{
    background: #eee;
    padding: 1px 4px;
    border-radius: 3px;
    font-size: 9pt;
  }}
  pre code {{
    background: transparent;
    padding: 0;
  }}
  /* Lists */
  ul, ol {{
    margin: 0.4em 0;
    padding-left: 1.5em;
  }}
  li {{
    margin-bottom: 0.2em;
  }}
  /* Severity badges */
  .sev-critical {{
    display: inline-block;
    background: #e94560;
    color: #fff;
    font-weight: bold;
    padding: 2px 10px;
    border-radius: 3px;
    font-size: 9pt;
    text-transform: uppercase;
  }}
  .sev-high {{
    display: inline-block;
    background: #d35400;
    color: #fff;
    font-weight: bold;
    padding: 2px 10px;
    border-radius: 3px;
    font-size: 9pt;
    text-transform: uppercase;
  }}
  .sev-medium {{
    display: inline-block;
    background: #e6a817;
    color: #fff;
    font-weight: bold;
    padding: 2px 10px;
    border-radius: 3px;
    font-size: 9pt;
    text-transform: uppercase;
  }}
  .sev-low {{
    display: inline-block;
    background: #3498db;
    color: #fff;
    padding: 2px 10px;
    border-radius: 3px;
    font-size: 9pt;
    text-transform: uppercase;
  }}
  .sev-info {{
    display: inline-block;
    background: #95a5a6;
    color: #fff;
    padding: 2px 10px;
    border-radius: 3px;
    font-size: 9pt;
    text-transform: uppercase;
  }}
  /* Page breaks */
  .page-break {{
    page-break-after: always;
  }}
  /* Horizontal rule */
  hr {{
    border: none;
    border-top: 1px solid #ddd;
    margin: 2em 0;
  }}
  /* Footer */
  .report-footer {{
    margin-top: 3em;
    padding-top: 1em;
    border-top: 1px solid #ddd;
    font-size: 8.5pt;
    color: #888;
    text-align: center;
  }}
  /* Paragraph spacing */
  p {{
    margin: 0.5em 0;
  }}
</style>
</head>
<body>
<div class="cover-page">
{cover}
</div>
{rest}
<div class="report-footer">
  Generated by {COMPANY} — {datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")} UTC
</div>
{_POC_STYLE_SCRIPT}
</body>
</html>"""


def _md_to_html_full(md_text: str, title: str = "") -> str:
    """Wrap Markdown text in a full HTML document with proper styling."""
    return _md_to_html_body(md_text, title)


def _find_logo(case_dir: Optional[Path] = None) -> Optional[Path]:
    """Search for the company logo in known template locations or case directory."""
    from .constants import OBSIDIAN_DIR
    candidates = [
        OBSIDIAN_DIR / "Templates" / "Pentest Templates" / "Data" / "Logo Try 2.png",
        OBSIDIAN_DIR / "Templates" / "Pentest Templates" / "Data" / "Logo Try 2.jpg",
        OBSIDIAN_DIR / "Templates" / "Pentest Templates" / "Data" / "Logo.png",
        OBSIDIAN_DIR / "Templates" / "Pentest Templates" / "Data" / "Logo.jpg",
        OBSIDIAN_DIR / "Malware Report Templates" / "Data" / "Logo Try 2.png",
        OBSIDIAN_DIR / "Detection Templates" / "Data" / "Logo.png",
    ]
    for c in candidates:
        if c.exists():
            return c
    # Fallback: glob any logo file in any template Data/ directory
    templates_dir = OBSIDIAN_DIR / "Templates"
    if templates_dir.is_dir():
        try:
            for d in templates_dir.iterdir():
                data_dir = d / "Data"
                if data_dir.is_dir():
                    for f in data_dir.iterdir():
                        if f.name.lower().startswith("logo"):
                            return f
        except Exception:
            pass
    # Last fallback: check case directory for logo.png
    if case_dir:
        case_logo = case_dir / "logo.png"
        if case_logo.exists():
            return case_logo
    return None


def _logo_base64_tag(case_dir: Optional[Path] = None) -> str:
    """Return a Markdown image tag with the logo as a base64 data URI, or empty string."""
    logo_src = _find_logo(case_dir)
    if not logo_src:
        return ""
    try:
        import base64
        logo_ext = logo_src.suffix.lower().lstrip(".")
        mime_map = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
                     "gif": "image/gif", "svg": "image/svg+xml"}
        mime = mime_map.get(logo_ext, "image/png")
        b64 = base64.b64encode(logo_src.read_bytes()).decode()
        return f"![Logo](data:{mime};base64,{b64})"
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Legacy / other report generators  (kept for backward compat)
# ---------------------------------------------------------------------------

def generate_nmap_report(xml_path: Path, title: str = "Nmap Scan Report") -> str:
    html = [_html_header(title)]
    try:
        tree = ET.parse(str(xml_path))
        root = tree.getroot()
        html.append(f"<h1>{_html_escape(title)}</h1>")
        html.append(f"<p>Command: <code>{_html_escape(root.get('args', ''))}</code></p>")
        html.append(_nmap_table(tree))
    except Exception as e:
        html.append(f"<p class='critical'>Error parsing nmap XML: {e}</p>")
    html.append(_html_footer())
    return "\n".join(html)


def generate_nuclei_report(json_path: Path, title: str = "Nuclei Scan Report") -> str:
    html = [_html_header(title), f"<h1>{_html_escape(title)}</h1>"]
    try:
        findings = []
        for line in json_path.read_text().strip().splitlines():
            try:
                findings.append(json.loads(line))
            except Exception:

                logger.debug("Exception in report_generator.py", exc_info=True)
        if not findings:
            html.append("<p>No findings.</p>")
        else:
            html.append(f"<p>Total findings: {len(findings)}</p>")
            html.append("<table><tr><th>Template</th><th>Name</th><th>Severity</th>"
                        "<th>Matched</th><th>Extracted</th></tr>")
            for f in findings:
                info = f.get("info", {})
                tid = f.get("template-id", "?")
                name = info.get("name", "?")
                sev = info.get("severity", "?")
                matched = f.get("matched-at", "")
                extracted = f.get("extracted-results", [])
                ext_str = "; ".join(str(e) for e in extracted[:3])
                cls = "critical" if sev == "critical" else "info"
                html.append(f"<tr class='{cls}'><td>{_html_escape(tid)}</td>"
                            f"<td>{_html_escape(name)}</td>"
                            f"<td>{_html_escape(sev)}</td>"
                            f"<td>{_html_escape(matched)}</td>"
                            f"<td>{_html_escape(ext_str)}</td></tr>")
            html.append("</table>")
    except Exception as e:
        html.append(f"<p class='critical'>Error: {e}</p>")
    html.append(_html_footer())
    return "\n".join(html)


def generate_markdown_report(sections: Dict[str, str],
                              title: str = "Engagement Report") -> str:
    lines = [
        f"# {title}",
        f"Generated: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n",
        "---\n",
    ]
    for heading, body in sections.items():
        lines.append(f"## {heading}\n")
        lines.append(body)
        lines.append("")
    return "\n".join(lines)


def generate_case_summary_markdown(case_data: dict) -> str:
    cid = case_data.get("case_id", "unknown")
    client = case_data.get("client", "")
    desc = case_data.get("description", "")
    status = case_data.get("status", "open")
    created = case_data.get("created", "")
    evidence_count = len(case_data.get("evidence", []))
    note_count = len(case_data.get("notes", []))

    lines = [
        f"# Case: {cid}\n",
        f"- **Client:** {client or 'N/A'}",
        f"- **Status:** {status}",
        f"- **Created:** {created}",
        f"- **Description:** {desc}",
        f"- **Evidence Items:** {evidence_count}",
        f"- **Notes:** {note_count}\n",
        "---\n",
        "## Evidence Chain of Custody\n",
    ]
    for ev in case_data.get("evidence", []):
        lines.append(f"- **{ev.get('filename', '?')}**")
        lines.append(f"  - SHA256: `{ev.get('sha256', '?')}`")
        lines.append(f"  - MD5: `{ev.get('md5', '?')}`")
        lines.append(f"  - Size: {ev.get('size', 0):,} bytes")
        lines.append(f"  - Category: {ev.get('category', '?')}")
        lines.append(f"  - Acquired: {ev.get('timestamp', '?')}\n")

    return "\n".join(lines)


def generate_timeline_html(case_dir: Path) -> str:
    """Generate an HTML timeline visualization from case activity."""
    events = []

    case_json = case_dir / "case.json"
    if case_json.exists():
        cd = json.loads(case_json.read_text())
        for e in cd.get("evidence", []):
            events.append({
                "ts": e.get("timestamp", cd.get("created", "")),
                "title": f"Evidence added: {e.get('filename', '?')}",
                "detail": f"SHA256: {e.get('sha256', '?')[:16]}...  Category: {e.get('category', '?')}",
                "icon": "evidence",
            })
        for n in cd.get("notes", []):
            events.append({
                "ts": n.get("timestamp", ""),
                "title": "Note added",
                "detail": n.get("body", "")[:200],
                "icon": "note",
            })

    for rf in sorted(case_dir.glob("runbook-log.json")):
        try:
            rl = json.loads(rf.read_text())
            events.append({
                "ts": rl.get("start", ""),
                "title": f"Runbook: {rl.get('runbook', '?')}",
                "detail": f"{rl.get('steps', 0)} steps, {len(rl.get('artifacts', []))} artifacts",
                "icon": "runbook",
            })
        except Exception:

            logger.debug("Exception in report_generator.py", exc_info=True)

    findings_json = case_dir / "findings.json"
    if findings_json.exists():
        fd = json.loads(findings_json.read_text())
        for f in fd.get("findings", []):
            events.append({
                "ts": f.get("created", ""),
                "title": f"Finding: {f.get('title', '?')}",
                "detail": f"Severity: {f.get('severity', '?')}  Status: {f.get('status', '?')}",
                "icon": f"sev_{f.get('severity', 'info')}",
            })

    events.sort(key=lambda e: e.get("ts", ""))
    icons = {"evidence": "📁", "note": "📝", "runbook": "⚙️",
             "sev_critical": "🔴", "sev_high": "🟠", "sev_medium": "🟡",
             "sev_low": "🔵", "sev_info": "ℹ️"}

    items = []
    for e in events:
        icon = icons.get(e.get("icon", ""), "📌")
        try:
            ts_clean = e["ts"][:19].replace("T", " ")
        except Exception:
            ts_clean = e.get("ts", "")
        items.append(
            f'<div class="event">'
            f'<span class="ts">{ts_clean}</span> '
            f'<span class="icon">{icon}</span> '
            f'<strong>{_html_escape(e["title"])}</strong><br>'
            f'<span class="detail">{_html_escape(e["detail"])}</span>'
            f'</div>'
        )

    return f"""<!DOCTYPE html><html lang="en">
<head><meta charset="utf-8">
<title>Case Timeline — {_html_escape(case_dir.name)}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 2em; background: #f5f5f5; }}
  h1 {{ color: #1a1a2e; border-bottom: 3px solid #e94560; }}
  .event {{ background: #fff; margin: 0.5em 0; padding: 0.8em 1em;
            border-left: 4px solid #1a1a2e; border-radius: 4px; }}
  .ts {{ color: #666; font-size: 0.85em; }}
  .icon {{ font-size: 1.2em; margin: 0 0.5em; }}
  .detail {{ color: #888; font-size: 0.9em; }}
  .footer {{ margin-top: 2em; color: #999; font-size: 0.85em; }}
</style></head><body>
<h1>Timeline — {_html_escape(case_dir.name)}</h1>
<p>{len(events)} events</p>
{"".join(items)}
<div class="footer">Generated by {COMPANY} — {datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")} UTC</div>
</body></html>"""


# ---------------------------------------------------------------------------
# Internal helpers for legacy HTML generators
# ---------------------------------------------------------------------------

def _html_header(title: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8">
<title>{_html_escape(title)}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 2em; background: #f5f5f5; }}
  h1 {{ color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 0.3em; }}
  h2 {{ color: #16213e; margin-top: 1.5em; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1em 0; background: #fff; }}
  th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
  th {{ background: #000; color: #fff; }}
  tr:nth-child(even) {{ background: #f9f9f9; }}
  pre {{ background: #1e1e2e; color: #cdd6f4; padding: 1em; border-radius: 6px; overflow-x: auto; }}
  pre.poc-shell {{ background: #000; color: #fff; border: 1px solid #555; }}
  .critical {{ color: #e94560; font-weight: bold; }}
  .info {{ color: #0f3460; }}
  .footer {{ margin-top: 3em; font-size: 0.85em; color: #666; }}
</style>
</head><body>
"""


def _html_footer() -> str:
    return f"""<div class="footer">Generated by {COMPANY} &mdash; {datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")} UTC</div>
{_POC_STYLE_SCRIPT}
</body></html>
"""


def _nmap_table(tree: ET.ElementTree) -> str:
    rows = []
    for host in tree.findall("host"):
        ip = host.find("address")
        ip_str = ip.get("addr", "?") if ip is not None else "?"
        for port in host.findall("ports/port"):
            pid = port.get("portid", "?")
            state = port.find("state")
            svc = port.find("service")
            state_str = state.get("state", "?") if state is not None else "?"
            svc_name = svc.get("name", "?") if svc is not None else "?"
            prod = svc.get("product", "") if svc is not None else ""
            ver = svc.get("version", "") if svc is not None else ""
            banner = f"{prod} {ver}".strip() if prod or ver else ""
            rows.append(f"<tr><td>{ip_str}</td><td>{pid}</td>"
                        f"<td>{state_str}</td><td>{svc_name}</td>"
                        f"<td>{_html_escape(banner)}</td></tr>")
    if not rows:
        return "<p>No open ports found.</p>"
    return ("<table><tr><th>IP</th><th>Port</th><th>State</th>"
            "<th>Service</th><th>Banner</th></tr>" + "\n".join(rows) + "</table>")