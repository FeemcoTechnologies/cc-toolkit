"""Interoperability exports for case findings.

Emits standards-based results so findings can be consumed by external
tooling:

- **SARIF 2.1.0** (JSON) — SAST/SCA result interchange (used by GitHub
  Code Scanning, VS Code, etc.).
- **XCCDF 1.2 results** (XML) — the core of the SCAP ARF format; a
  Benchmark of rules with one TestResult per case. Checklist instances
  attached to the case are included as control rules and scored. The
  output can be validated with `oscap xccdf validate`.

Severity mapping to SARIF: critical/high -> error, medium -> warning,
low/info -> note.
XCCDF result mapping: findings with status resolved/fixed -> pass,
otherwise fail; checklist statuses map to pass/fail/notapplicable/
notchecked/notselected.
"""

import datetime
import json
import re
from pathlib import Path
from typing import Dict, List, Optional
import xml.etree.ElementTree as ET

from .config import CASES_DIR

_XCCDF_NS = "http://checklists.nist.gov/xccdf/1.2"
_DC_NS = "http://purl.org/dc/elements/1.1/"
_XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"

_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_FINDING_XCCDF_RESULT = {
    "resolved": "pass",
    "fixed": "pass",
    "closed_other": "pass",
    "unvalidated": "fail",
    "confirmed": "fail",
    "reproduced": "fail",
    "validated": "fail",
}

_CHECKLIST_XCCDF_RESULT = {
    "passed": "pass",
    "failed": "fail",
    "not_applicable": "notapplicable",
    "in_progress": "notchecked",
    "not_started": "notselected",
}

# XCCDF Rule@severity enum is {unknown, info, low, medium, high}
_XCCDF_SEVERITY = {
    "critical": "high",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _load_findings(case_dir: Path) -> List[dict]:
    path = Path(case_dir) / "findings.json"
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("findings", [])
    except (json.JSONDecodeError, OSError):
        return []


def _load_checklist_items(case_dir: Path) -> List[dict]:
    """Flatten checklist instances into enriched items (one dict per item).

    When multiple checklist instances exist, items are deduplicated by id with
    the last (most recent) instance winning, so the export never emits
    duplicate XCCDF rule ids.
    """
    from .checklist_manager import ChecklistInstance

    by_id: Dict[str, dict] = {}
    try:
        for cat in ChecklistInstance(Path(case_dir)).items_by_category():
            for it in cat.get("items", []):
                by_id[it.get("id", "")] = {
                    "id": it.get("id", ""),
                    "description": it.get("description", ""),
                    "status": it.get("status", "not_started"),
                    "finding_id": it.get("finding_id"),
                    "category": cat.get("name", ""),
                    "instance_title": cat.get("instance_title", ""),
                    "control": it.get("control", ""),
                    "cwe": it.get("cwe", ""),
                }
    except Exception:
        pass
    return list(by_id.values())


# ---------------------------------------------------------------------------
# SARIF 2.1.0
# ---------------------------------------------------------------------------

def export_findings_sarif(case_dir: Path, output: Optional[str] = None,
                          case_id: str = "") -> dict:
    """Export findings as a SARIF 2.1.0 log file."""
    case_dir = Path(case_dir)
    findings = _load_findings(case_dir)
    sarif_level = _SARIF_LEVEL

    rules: List[dict] = []
    results: List[dict] = []
    seen_rule_ids = set()

    for f in findings:
        rule_id = f.get("cve") or f.get("cwe") or f.get("id") or "finding"
        if rule_id not in seen_rule_ids:
            seen_rule_ids.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": f.get("id", rule_id),
                "shortDescription": {"text": (f.get("title") or rule_id)[:500]},
                "help": {"text": (f.get("description") or "")[:5000]},
                "properties": {
                    "severity": f.get("severity", "medium"),
                    "cwe": f.get("cwe", ""),
                    "cve": f.get("cve", ""),
                    "cpe": f.get("cpe", ""),
                    "source": f.get("source", ""),
                },
            })
        uri = f.get("affected_hosts") or case_id or case_dir.name
        location = {"artifactLocation": {"uri": str(uri)}}
        results.append({
            "ruleId": rule_id,
            "ruleIndex": len(seen_rule_ids) - 1,
            "level": sarif_level.get(f.get("severity", "medium"), "warning"),
            "message": {"text": (f.get("title") or "Finding")[:2000]},
            "locations": [location],
            "partialFingerprints": {"findingId": f.get("id", ""),
                                    "cve": f.get("cve", ""),
                                    "cpe": f.get("cpe", "")},
            "properties": {
                "finding_id": f.get("id", ""),
                "severity": f.get("severity", "medium"),
                "status": f.get("status", ""),
                "cwe": f.get("cwe", ""),
                "cve": f.get("cve", ""),
                "cpe": f.get("cpe", ""),
                "cvss_score": f.get("cvss_score"),
                "cvss_vector": f.get("cvss_vector", ""),
                "source": f.get("source", ""),
            },
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Kali Command Center",
                "informationUri": "https://github.com/",
                "rules": rules,
            }},
            "results": results,
            "automationDetails": {"id": f"kali-command-center/{case_id or case_dir.name}"},
            "invocations": [{"executionSuccessful": True,
                             "endTimeUtc": _now()}],
        }],
    }

    return _write_json(case_dir, "exports", sarif, "findings.sarif",
                       output, case_id=case_id,
                       extra={"format": "sarif-2.1.0",
                              "rules": len(rules),
                              "results": len(results)})


# ---------------------------------------------------------------------------
# XCCDF 1.2 (SCAP) results
# ---------------------------------------------------------------------------

def _q(tag: str) -> str:
    return f"{{{_XCCDF_NS}}}{tag}"


def _dc(tag: str) -> str:
    return f"{{{_DC_NS}}}{tag}"


def _xccdf_id(kind: str, ident: str) -> str:
    """Build a schema-compliant XCCDF identifier.

    Pattern required by the XCCDF 1.2 schema:
        xccdf_<org>_group_<name>      (group)
        xccdf_<org>_rule_<name>       (rule)
        xccdf_<org>_testresult_<name> (test result)
    where <org> is a single non-underscore token (e.g. org.kcc).
    """
    org = "org.kcc"
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", ident or "case")
    return f"xccdf_{org}_{kind}_{safe}"


def export_findings_xccdf(case_dir: Path, output: Optional[str] = None,
                          case_id: str = "", include_checklist: bool = True) -> dict:
    """Export findings (and optional checklist status) as an XCCDF 1.2 results document.

    This is the results core of the SCAP ARF format. Validate with:
    ``oscap xccdf validate <file>``
    """
    case_dir = Path(case_dir)
    findings = _load_findings(case_dir)
    checklist_items = _load_checklist_items(case_dir) if include_checklist else []
    ident = case_id or case_dir.name
    bench_id = f"xccdf_org.kcc_benchmark_{re.sub(r'[^A-Za-z0-9._-]', '_', ident)}"

    ET.register_namespace("xccdf", _XCCDF_NS)
    ET.register_namespace("dc", _DC_NS)
    ET.register_namespace("xsi", _XSI_NS)

    benchmark = ET.Element(_q("Benchmark"), {"id": bench_id})

    status = ET.SubElement(benchmark, _q("status"))
    status.set("date", datetime.date.today().isoformat())
    status.text = "draft"

    ET.SubElement(benchmark, _q("title")).text = f"Kali Command Center results — {ident}"
    ET.SubElement(benchmark, _q("description")).text = (
        "Generated from case findings and checklist state. "
        "Each Rule maps to a finding or checklist control.")
    ET.SubElement(benchmark, _q("version")).text = "1.2"
    metadata = ET.SubElement(benchmark, _q("metadata"))
    creator = ET.SubElement(metadata, _dc("creator"))
    creator.text = "Kali Command Center (ai-combined-tools)"

    def _emit_rule(parent: ET.Element, rule_id: str, title_text: str,
                   desc_text: str, severity: str, refs: Dict[str, str]):
        rule = ET.SubElement(parent, _q("Rule"), {
            "id": rule_id,
            "severity": _XCCDF_SEVERITY.get(severity, "unknown"),
            "weight": "1.0",
        })
        ET.SubElement(rule, _q("title")).text = title_text
        d = ET.SubElement(rule, _q("description"))
        d.text = desc_text or title_text
        if refs.get("cve"):
            ET.SubElement(rule, _q("reference"), {"href": f"https://nvd.nist.gov/vuln/detail/{refs['cve']}"}).text = refs["cve"]
        if refs.get("cwe"):
            ET.SubElement(rule, _q("reference"),
                          {"href": f"https://cwe.mitre.org/data/definitions/{refs['cwe'].replace('CWE-', '')}.html"}).text = refs["cwe"]
        if refs.get("cpe"):
            ET.SubElement(rule, _q("ident")).text = refs["cpe"]
        ET.SubElement(rule, _q("check"), {"system": "urn:xccdf:check:manual"})
        return rule

    group_findings = ET.SubElement(benchmark, _q("Group"),
                                   {"id": _xccdf_id("group", f"findings_{ident}")})
    ET.SubElement(group_findings, _q("title")).text = "Findings"

    by_sev: Dict[str, List[dict]] = {}
    for f in findings:
        by_sev.setdefault(f.get("severity", "medium"), []).append(f)

    findings_ids = []
    for sev in ("critical", "high", "medium", "low", "info"):
        for f in by_sev.get(sev, []):
            rid = _xccdf_id("rule", f"finding_{f.get('id', '')}")
            findings_ids.append(rid)
            _emit_rule(group_findings, rid, f.get("title") or f.get("id", ""),
                       f.get("description", ""), sev,
                       {"cve": f.get("cve", ""), "cwe": f.get("cwe", ""),
                        "cpe": f.get("cpe", "")})

    group_controls = ET.SubElement(benchmark, _q("Group"),
                                   {"id": _xccdf_id("group", f"controls_{ident}")})
    ET.SubElement(group_controls, _q("title")).text = "Checklist Controls"
    control_ids = []
    control_lookup = {}
    for item in checklist_items:
        cid = _xccdf_id("rule", f"check_{item.get('id', '')}")
        control_ids.append(cid)
        control_lookup[cid] = item.get("status", "not_started")
        _emit_rule(group_controls, cid,
                   f"{item.get('control')} — {item.get('description') or item.get('id')}",
                   f"Checklist: {item.get('instance_title', '')} / {item.get('category', '')}",
                   "medium", {"cpe": "", "cwe": item.get("cwe", "")})

    # TestResult (XCCDF 1.2 TestResultType has NO benchmark child — the
    # association is implicit because the result is nested in the Benchmark).
    test_result = ET.SubElement(benchmark, _q("TestResult"), {
        "id": _xccdf_id("testresult", ident),
        "version": "1.2",
        "start-time": _now(),
        "end-time": _now(),
        "test-system": "kali-command-center",
    })
    ET.SubElement(test_result, _q("title")).text = f"Assessment — {ident}"
    ET.SubElement(test_result, _q("target")).text = ident

    def _rule_result(idref: str, result: str):
        rr = ET.SubElement(test_result, _q("rule-result"), {"idref": idref})
        ET.SubElement(rr, _q("result")).text = result
        ET.SubElement(rr, _q("check"), {"system": "urn:xccdf:check:manual"})

    total = len(findings_ids) + len(control_ids)
    passed = 0
    for rid in findings_ids:
        f = next((x for x in findings if _xccdf_id("rule", f"finding_{x.get('id')}") == rid), {})
        res = _FINDING_XCCDF_RESULT.get(f.get("status", "unvalidated"), "fail")
        if res == "pass":
            passed += 1
        _rule_result(rid, res)
    for cid in control_ids:
        res = _CHECKLIST_XCCDF_RESULT.get(control_lookup.get(cid, "not_started"), "notselected")
        if res == "pass":
            passed += 1
        _rule_result(cid, res)
    if total:
        score_el = ET.SubElement(test_result, _q("score"), {"system": "urn:xccdf:scoring:default"})
        score_el.text = f"{round(passed / total * 100, 2)}"

    tree = ET.ElementTree(benchmark)
    out_path = _resolve_output(case_dir, "exports", "findings-xccdf.xml", output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tree.write(str(out_path), encoding="utf-8", xml_declaration=True)
    return {
        "path": str(out_path),
        "format": "xccdf-1.2",
        "case_id": ident,
        "findings": len(findings),
        "checklist_items": len(checklist_items),
        "total_rules": total,
        "passed": passed,
        "score": round(passed / total * 100, 2) if total else 0,
        "validate_hint": "oscap xccdf validate <file>",
    }


# ---------------------------------------------------------------------------
# Shared helpers + facade
# ---------------------------------------------------------------------------

def _resolve_output(case_dir: Path, subdir: str, default_name: str,
                    output: Optional[str]) -> Path:
    if output:
        p = Path(output)
        if not p.is_absolute():
            p = Path(case_dir) / subdir / p
        return p
    return Path(case_dir) / subdir / default_name


def _write_json(case_dir: Path, subdir: str, data: dict, default_name: str,
                output: Optional[str], case_id: str = "",
                extra: Optional[dict] = None) -> dict:
    out_path = _resolve_output(case_dir, subdir, default_name, output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    result = {
        "path": str(out_path),
        "format": extra.get("format", "json") if extra else "json",
        "case_id": case_id or case_dir.name,
    }
    if extra:
        result.update(extra)
    return result


def export_case(case_id: str, fmt: str = "sarif", output: str = "",
                include_checklist: bool = True) -> dict:
    """Export a case's findings in an interoperable format.

    fmt: sarif | xccdf
    Returns a dict with the output path, format, and counts.
    """
    case_dir = CASES_DIR / case_id
    if not case_dir.is_dir():
        return {"error": f"Case '{case_id}' not found"}
    fmt = fmt.lower()
    if fmt == "sarif":
        return export_findings_sarif(case_dir, output or None, case_id=case_id)
    if fmt in ("xccdf", "xccdf-1.2", "scap", "arf"):
        return export_findings_xccdf(case_dir, output or None, case_id=case_id,
                                     include_checklist=include_checklist)
    return {"error": f"Unsupported format '{fmt}'. Use 'sarif' or 'xccdf'."}
