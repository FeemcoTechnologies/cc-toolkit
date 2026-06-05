import logging
"""Report generator — parse case data into Obsidian-compatible Markdown + HTML.

Output matches the Obsidian pentest report template structure at:
  Templates/Pentest Templates/Pentest Report.md  with sections in Data/
"""

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

# Sections in order (matches template Pentest Report.md)
ALL_SECTIONS = [
    "Confidentiality Statement",
    "Disclaimer",
    "Contact Information",
    "Assessment Overview",
    "Scope",
    "Executive Summary",
    "Strengths",
    "Weaknesses",
    "Findings",
    "Risk Assessment Matrix",
    "Methodology",
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
        "Assessment Overview",
        "Scope",
        "Executive Summary",
        "Strengths",
        "Weaknesses",
        "Findings",
        "Risk Assessment Matrix",
        "Methodology",
    ],
    "pentest_physical": [
        "Confidentiality Statement",
        "Disclaimer",
        "Contact Information",
        "Assessment Overview",
        "Scope",
        "Executive Summary",
        "Strengths",
        "Weaknesses",
        "Findings",
        "Risk Assessment Matrix",
        "Methodology",
    ],
    "ir": [
        "Confidentiality Statement",
        "Disclaimer",
        "Contact Information",
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
        "Assessment Overview",
        "Scope",
        "Executive Summary",
        "Strengths",
        "Weaknesses",
        "Findings",
        "Methodology",
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

def _section_confidentiality() -> List[str]:
    return [
        "## Confidentiality Statement",
        "",
        f"This document is the exclusive property of **{COMPANY}** and **{COMPANY}**."
        " This document contains proprietary and confidential information."
        " Any duplication, redistribution, or use requires the written consent of both parties."
        " Further restrictions for this are outlined in any agreements made between"
        " these two parties and will be upheld based on that agreement.",
        "",
    ]


def _section_disclaimer(dates: str = "") -> List[str]:
    return [
        "## Disclaimer",
        "",
        f"The Cyber Defense Penetration Testing performed by {COMPANY},"
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
        lines += [contacts, ""]
    else:
        lines += [
            "",
            "| Contact Name | Number/Email | Priority | Notes |",
            "| ------------ | ------------ | -------- | ----- |",
            "| —            | —            | —        | —     |",
            "|              |              |          |       |",
            "",
        ]
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
        except Exception:
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
    by_sev = {}
    for f in findings:
        s = f.get("severity", "info").lower()
        by_sev[s] = by_sev.get(s, 0) + 1
    sev_str = ", ".join(f"{k}={v}" for k, v in sorted(by_sev.items()))

    lines = [
        "## Executive Summary",
        "",
        f"Evaluated {client}'s security posture through defense penetration testing"
        f" (PenTesting) from ({assessment_dates}). The following sections provide high level"
        " overview of vulnerabilities discovered, attempts made, and general recommendations.",
        "",
    ]

    if exec_summary_text:
        lines += [exec_summary_text, ""]

    lines += [
        "### Testing Summary",
        "",
        f"- **Case ID:** {case_id}",
        f"- **Client:** {client}",
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
        status = f.get("status", "unvalidated")

        me = _md_escape
        lines += [
            f"### #{i} — {me(title)}",
            "",
            "| Field | Value |",
            "| ----- | ----- |",
            f"| **Severity** | {sev} |",
            f"| **Status** | {status} |",
            f"| **CVE/CWE** | {me(cve or cwe or 'N/A', table=True)} |",
            f"| **System/Service** | {me(source or 'N/A', table=True)} |",
            f"| **Impact** | {me(impact or 'N/A', table=True)} |",
            f"| **Remediation** | {me(remediation or 'N/A', table=True)} |",
        ]
        if references:
            ref_str = "; ".join(me(r, table=True) for r in references[:5])
            lines.append(f"| **References** | {ref_str} |")
        if desc:
            lines += ["", "---", "", desc, ""]
        if poc:
            lines += [
                "",
                "**Proof of Concept:**",
                "```",
                poc[:1000],
                "```",
            ]
        # Render linked evidence
        evidence_refs = f.get("evidence_refs", [])
        if evidence_refs:
            # Filter evidence records to only those referenced by this finding
            linked = [e for e in evidence_records if e.get("filename") in evidence_refs]
            if linked:
                lines += ["", "---", "", "**Linked Evidence:**"]
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


# ---------------------------------------------------------------------------
# Main report assemblers
# ---------------------------------------------------------------------------

def _render_report_markdown(case_data: dict, findings: List[dict],
                             case_dir: Optional[Path] = None) -> str:
    """Build the full Markdown report from sections. Pure Markdown — no HTML tags."""
    case_id = case_data.get("case_id", "?")
    client = case_data.get("client", "") or "COMPANY"
    dates = case_data.get("created", "")[:10] or "DATES"
    cd = case_dir or Path()
    case_type = case_data.get("case_type", "pentest")
    sections = _sections_for_case(case_type)

    lines = [
        "# Security Assessment & Findings Report",
        "",
        f"**Created for {client}**",
        "",
        f"*Confidential — {COMPANY}*",
        "",
        "---",
        "",
        "",
    ]

    for section_name in sections:
        if section_name == "Confidentiality Statement":
            lines += _section_confidentiality()
        elif section_name == "Disclaimer":
            lines += _section_disclaimer(dates)
        elif section_name == "Contact Information":
            lines += _section_contact(case_data)
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
        lines.append("")

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


def _render_report_html(case_data: dict, findings: List[dict]) -> str:
    """Build an HTML version of the same report."""
    case_id = case_data.get("case_id", "?")
    client = case_data.get("client", "") or "COMPANY"

    def h(text):
        return _html_escape(text)

    lines = [
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>",
        f"<title>Engagement Report — {h(case_id)}</title>",
        "<style>",
        "  body { font-family: 'Segoe UI', Arial, sans-serif; margin: 2em; background: #fff; color: #222; }",
        "  h1 { color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 0.3em; }",
        "  h2 { color: #16213e; margin-top: 1.5em; border-bottom: 1px solid #ddd; }",
        "  h3 { color: #0f3460; }",
        "  table { border-collapse: collapse; width: 100%; margin: 1em 0; }",
        "  th, td { border: 1px solid #ccc; padding: 8px 12px; text-align: left; }",
        "  th { background: #1a1a2e; color: #fff; }",
        "  tr:nth-child(even) { background: #f9f9f9; }",
        "  pre { background: #1e1e2e; color: #cdd6f4; padding: 1em; border-radius: 6px; overflow-x: auto; }",
        "  .critical { color: #e94560; font-weight: bold; }",
        "  .high { color: #d35400; }",
        "  .footer { margin-top: 3em; font-size: 0.85em; color: #666; }",
        "  .page-break { page-break-after: always; }",
        "</style></head><body>",
        f"<h1>Security Assessment & Findings Report</h1>",
        f"<h3>Created for {h(client)}</h3><hr>",
    ]

    # Render sections as HTML tables/blocks
    md = _render_report_markdown(case_data, findings)
    html_body = _md_to_html_simple(md)
    lines.append(html_body)

    lines.append(f"<div class='footer'>Generated by {COMPANY} — "
                 f"{datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC</div>")
    lines.append("</body></html>")
    return "\n".join(lines)


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
        nonlocal in_table
        if in_table:
            if table_header:
                html.append("</tbody>")
            html.append("</table>")
            in_table = False

    in_pre = False

    for line in md.split("\n"):
        stripped = line.strip()

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

        # Code blocks
        if stripped.startswith("```"):
            close_ul()
            close_ol()
            close_table()
            in_code = not in_code
            if in_code:
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
                tag = "th"
                html.append("<thead><tr>")
                for c in cells:
                    html.append(f"<{tag}>{_inline_md_to_html(c)}</{tag}>")
                html.append("</tr></thead><tbody>")
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
            html.append(f"<h3>{_inline_md_to_html(stripped[4:])}</h3>")
            continue
        if stripped.startswith("## "):
            close_ul()
            close_ol()
            html.append(f"<h2>{_inline_md_to_html(stripped[3:])}</h2>")
            continue
        if stripped.startswith("# "):
            close_ul()
            close_ol()
            html.append(f"<h1>{_inline_md_to_html(stripped[2:])}</h1>")
            continue

        # Unordered lists
        if stripped.startswith("- "):
            close_ol()
            if not in_ul:
                html.append("<ul>")
                in_ul = True
            html.append(f"<li>{_inline_md_to_html(stripped[2:])}</li>")
            continue

        # Ordered lists (handle any number for continuation)
        if re.match(r"^\d+\. ", stripped):
            close_ul()
            content = re.sub(r"^\d+\.\s*", "", stripped)
            if not in_ol:
                html.append("<ol>")
                in_ol = True
            html.append(f"<li>{_inline_md_to_html(content)}</li>")
            continue

        # Blank line — close lists
        if stripped == "":
            close_ul()
            close_ol()
            continue

        # Image (Markdown ![]())
        img_match = re.match(r'^!\[(.*)\]\((.+)\)$', stripped)
        if img_match:
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
    """Generate both HTML and Obsidian Markdown engagement reports.

    Returns path to the HTML report (for backward compatibility).
    Callers that expect HTML can write the result string to disk.
    """
    case_data, findings = _load_case(case_dir)
    case_id = case_data.get("case_id", "?")
    reports_dir = case_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    # Generate Markdown report
    md = _render_report_markdown(case_data, findings)
    md_path = reports_dir / "engagement-report.md"
    md_path.write_text(md, encoding="utf-8")

    # Generate HTML report
    html = _render_report_html(case_data, findings)
    html_path = reports_dir / "engagement-report.html"
    html_path.write_text(html, encoding="utf-8")

    return html_path.as_posix()


def generate_obsidian_report(
    case_dir: Path,
    output_dir: Optional[Path] = None,
    write_sections: bool = True,
    formats: Optional[List[str]] = None,
) -> Dict[str, str]:
    """Generate an Obsidian-compatible pentest report matching the template structure.

    Generates .md (always), plus .html, .docx, .pdf if converters are available.

    Args:
        case_dir: Case directory (contains case.json, findings.json)
        output_dir: Where to write the report (defaults to vault's Pentests/c-reports/{case_id}/)
        write_sections: If True, also write individual section files in Data/ subdir
        formats: List of formats to generate (default: ['md','html','docx','pdf'])

    Returns:
        Dict mapping format extension to file path, e.g. {'md': '/path/to/file.md', ...}
    """
    from .constants import PENTEST_NOTES_DIR
    case_data, findings = _load_case(case_dir)
    case_id = case_data.get("case_id", "?")
    case_type = case_data.get("case_type", "pentest")
    out = Path(output_dir or PENTEST_NOTES_DIR / case_id)
    out.mkdir(parents=True, exist_ok=True)

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
            lines = _section_confidentiality()
        elif section_name == "Disclaimer":
            lines = _section_disclaimer(case_data.get("created", "")[:10])
        elif section_name == "Contact Information":
            lines = _section_contact(case_data)
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
        section_bodies[section_name] = "".join(f"{l}\n" for l in lines)
        if write_sections:
            (data_dir / f"{section_name}.md").write_text(section_bodies[section_name], encoding="utf-8")

    # Main report note with embeds (Obsidian template style) — no HTML tags
    client = case_data.get("client", "") or "COMPANY"
    report_lines = [
        "",
        "![[./Data/Logo Try 2.png]]",
        "",
        "# Security Assessment & Findings Report",
        "",
        f"### Created for {client}",
        "",
        "",
        "",
        "",
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

    # Copy logo if found
    logo_src = _find_logo()
    if logo_src and write_sections:
        try:
            shutil.copy2(str(logo_src), str(data_dir / "Logo Try 2.png"))
        except Exception:

            logger.debug("Exception in report_generator.py", exc_info=True)

    # Prepend logo to flat markdown so HTML/DOCX/PDF also get it.
    # Use base64 data URI to avoid path-resolution issues with pandoc/weasyprint.
    flat_with_logo = flat
    if logo_src and write_sections:
        try:
            import base64
            logo_data = logo_src.read_bytes()
            logo_ext = logo_src.suffix.lower().lstrip(".")
            mime_map = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "gif": "image/gif", "svg": "image/svg+xml"}
            logo_mime = mime_map.get(logo_ext, "image/png")
            logo_b64 = base64.b64encode(logo_data).decode()
            flat_with_logo = f"![Logo](data:{logo_mime};base64,{logo_b64})\n\n{flat}"
        except Exception:
            flat_with_logo = f"![Logo](./Data/Logo Try 2.png)\n\n{flat}" if write_sections else flat

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
        docx_path = _convert_md_to_docx(flat_with_logo, out / f"{base_name}.docx", case_id, work_dir=out)
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
        pdf_path = _convert_html_to_pdf(html_for_pdf, out / f"{base_name}.pdf", case_id)
        if pdf_path:
            results["pdf"] = pdf_path.as_posix()

    return results


def _convert_md_to_docx(md_text: str, out_path: Path, title: str = "",
                         work_dir: Optional[Path] = None) -> Optional[Path]:
    """Convert Markdown text to DOCX using pandoc or python-docx.

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

    # Try pandoc first
    try:
        subprocess.run(
            ["pandoc", str(md_path), "-o", str(out_path),
             "--metadata", f"title={title}", "--from", "markdown"],
            capture_output=True, text=True, timeout=60,
        )
        if out_path.exists():
            cleanup()
            return out_path
    except Exception:

        logger.debug("Exception in report_generator.py", exc_info=True)

    # Fallback: try python-docx
    try:
        from docx import Document
        from docx.shared import Inches
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
        cleanup()
        return out_path
    except Exception:

        logger.debug("Exception in report_generator.py", exc_info=True)

    cleanup()
    return None


def _convert_html_to_pdf(html_path: Path, out_path: Path, title: str = "") -> Optional[Path]:
    """Convert an HTML file directly to PDF via weasyprint.

    This is preferred over pandoc-based conversion because it preserves
    all CSS styling (code blocks, tables, colors, page breaks).
    """
    if not html_path.exists():
        return None
    try:
        from weasyprint import HTML
        HTML(filename=str(html_path)).write_pdf(str(out_path))
        if out_path.exists():
            return out_path
    except Exception:

        logger.debug("Exception in report_generator.py", exc_info=True)
    return None


def _convert_md_to_pdf(md_text: str, out_path: Path, title: str = "",
                        work_dir: Optional[Path] = None) -> Optional[Path]:
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
        except Exception:
            continue

    # Fallback: try weasyprint directly from HTML
    try:
        from weasyprint import HTML
        html = _md_to_html_full(md_text, title)
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
  .cover-page img.logo {{
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
  th, td {{
    border: 1px solid #ccc;
    padding: 6px 10px;
    text-align: left;
    vertical-align: top;
    word-break: break-word;
    overflow-wrap: break-word;
  }}
  th {{
    background: #1a1a2e;
    color: #fff;
    font-weight: 600;
  }}
  tr:nth-child(even) {{
    background: #f8f8f8;
  }}
  /* Finding tables - vertical key/value style */
  h3 + table th:first-child {{
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
<div style="page-break-after: always;"></div>
{rest}
<div class="report-footer">
  Generated by {COMPANY} — {datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")} UTC
</div>
</body>
</html>"""


def _md_to_html_full(md_text: str, title: str = "") -> str:
    """Wrap Markdown text in a full HTML document with proper styling."""
    return _md_to_html_body(md_text, title)


def _find_logo() -> Optional[Path]:
    """Search for the company logo in known template locations."""
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
    for d in (OBSIDIAN_DIR / "Templates").iterdir():
        data_dir = d / "Data"
        if data_dir.is_dir():
            for f in data_dir.iterdir():
                if f.name.lower().startswith("logo"):
                    return f
    return None


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
  th {{ background: #1a1a2e; color: #fff; }}
  tr:nth-child(even) {{ background: #f9f9f9; }}
  pre {{ background: #1e1e2e; color: #cdd6f4; padding: 1em; border-radius: 6px; overflow-x: auto; }}
  .critical {{ color: #e94560; font-weight: bold; }}
  .info {{ color: #0f3460; }}
  .footer {{ margin-top: 3em; font-size: 0.85em; color: #666; }}
</style>
</head><body>
"""


def _html_footer() -> str:
    return f"""<div class="footer">Generated by {COMPANY} &mdash; {datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")} UTC</div>
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