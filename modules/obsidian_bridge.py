import logging
"""Obsidian vault bridge — push structured findings to your vault."""

import datetime
import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional

from .config import OBSIDIAN_DIR, OBSIDIAN_OUTPUT_SUBDIR
logger = logging.getLogger(__name__)


class ObsidianBridge:
    """Write structured notes to the Obsidian vault without disturbing existing files."""

    def __init__(self, vault_path: Optional[Path] = None,
                 subdir: str = OBSIDIAN_OUTPUT_SUBDIR):
        self.vault_path = Path(vault_path or OBSIDIAN_DIR)
        self.subdir = subdir
        self.output_dir = self.vault_path / subdir

    def is_accessible(self) -> bool:
        return self.vault_path.exists() and self.vault_path.is_dir()

    def _sanitize_title(self, title: str) -> str:
        safe = re.sub(r'[<>:"/\\|?*]', "_", title)
        safe = re.sub(r'\s+', " ", safe).strip()[:200]
        return safe

    def _ensure_output_dir(self) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        return self.output_dir

    def write_note(self, title: str, content: str,
                   tags: Optional[List[str]] = None,
                   frontmatter: Optional[dict] = None) -> Optional[Path]:
        if not self.is_accessible():
            return None
        self._ensure_output_dir()
        safe_title = self._sanitize_title(title)
        fpath = self.output_dir / f"{safe_title}.md"
        if fpath.exists():
            base = fpath.stem
            fpath = self.output_dir / f"{base}_{datetime.datetime.now():%Y%m%d_%H%M%S}.md"

        fm = dict(frontmatter or {})
        fm.setdefault("created", datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"))
        fm.setdefault("tags", tags or [])
        fm_str = "---\n" + "\n".join(
            f"{k}: {v}" if not isinstance(v, list)
            else f"{k}:\n" + "\n".join(f"  - {i}" for i in v)
            for k, v in fm.items()
        ) + "\n---\n\n"

        full_content = fm_str + content
        fpath.write_text(full_content)
        return fpath

    def push_findings(self, case_id: str, target: str,
                      findings: Dict[str, List[str]],
                      scan_type: str = "recon") -> Optional[Path]:
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            f"# {scan_type.title()} Findings — {target}",
            f"**Case:** `{case_id}`  \n",
            f"**Generated:** {now} UTC  \n",
            "---\n",
        ]
        for section, items in findings.items():
            if not items:
                continue
            lines.append(f"## {section.title()}\n")
            for item in items:
                lines.append(f"- `{item}`")
            lines.append("")

        title = f"{scan_type}_{target}_{datetime.datetime.now():%Y%m%d}"
        return self.write_note(
            title=title,
            content="\n".join(lines),
            tags=[scan_type, case_id, "auto-generated"],
            frontmatter={
                "case_id": case_id,
                "target": target,
                "scan_type": scan_type,
                "source": "kali-command-center",
            },
        )

    def push_nmap_results(self, case_id: str, target: str,
                          nmap_xml: Path) -> Optional[Path]:
        """Attempt to parse nmap XML and push structured results."""
        import xml.etree.ElementTree as ET
        try:
            tree = ET.parse(str(nmap_xml))
            root = tree.getroot()
        except Exception:
            return None

        findings: Dict[str, List[str]] = {
            "open_ports": [],
            "services": [],
            "os_detection": [],
        }
        for host in root.findall("host"):
            for port in host.findall("ports/port"):
                port_id = port.get("portid", "?")
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    svc = port.find("service")
                    svc_name = svc.get("name", "unknown") if svc is not None else "unknown"
                    prod = svc.get("product", "") if svc is not None else ""
                    ver = svc.get("version", "") if svc is not None else ""
                    findings["open_ports"].append(f"{port_id}/{svc_name}")
                    banner = f"{prod} {ver}".strip()
                    if banner:
                        findings["services"].append(f"{port_id}: {banner}")
            for os_elem in host.findall("os/osmatch"):
                name = os_elem.get("name", "")
                if name:
                    findings["os_detection"].append(name)

        return self.push_findings(
            case_id=case_id, target=target,
            findings=findings, scan_type="nmap"
        )

    def push_nuclei_results(self, case_id: str, target: str,
                            nuclei_json: Path) -> Optional[Path]:
        try:
            data = []
            with nuclei_json.open() as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                        data.append(item)
                    except Exception:

                        logger.debug("Exception in obsidian_bridge.py", exc_info=True)
            if not data:
                return None
        except Exception:
            return None

        findings: Dict[str, List[str]] = {
            "vulnerabilities": [],
            "info": [],
            "critical": [],
        }
        for item in data:
            severity = (item.get("info") or item).get("severity", "unknown")
            name = (item.get("info") or item).get("name", "unknown")
            template = item.get("template-id", "")
            match = item.get("matched-at", "")
            entry = f"{name} [{template}]"
            if match:
                entry += f" @ {match}"
            if severity == "critical":
                findings["critical"].append(entry)
            else:
                findings["vulnerabilities"].append(f"[{severity}] {entry}")

        if not any(findings.values()):
            findings["info"].append("No results from nuclei scan")

        return self.push_findings(
            case_id=case_id, target=target,
            findings=findings, scan_type="nuclei"
        )

    def list_generated_notes(self) -> List[Path]:
        if not self.output_dir.exists():
            return []
        return sorted(self.output_dir.glob("*.md"))

    def summary(self) -> dict:
        if not self.is_accessible():
            return {"accessible": False, "vault": str(self.vault_path)}
        # Avoid full vault rglob (could be slow for large vaults); only walk generated dir
        all_notes_hint = len(list(self.vault_path.glob("*.md")))  # top-level only
        generated = self.list_generated_notes()
        return {
            "accessible": True,
            "vault": str(self.vault_path),
            "total_notes_hint": all_notes_hint,
            "generated_notes": len(generated),
            "generated_dir": str(self.output_dir),
        }