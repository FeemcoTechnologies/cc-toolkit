import logging
"""Findings database — structured findings per case."""

import datetime
import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Dict, List, Optional
logger = logging.getLogger(__name__)


class FindingsDB:
    """Structured findings storage linked to a case."""

    SEVERITIES = ["info", "low", "medium", "high", "critical"]

    def __init__(self, case_dir: Path):
        self.case_dir = Path(case_dir)
        self._path = self.case_dir / "findings.json"
        self._lock = threading.Lock()

    def _read(self) -> dict:
        if self._path.exists():
            return json.loads(self._path.read_text())
        return {"findings": []}

    def _write(self, data: dict):
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, default=str))
        tmp.replace(self._path)

    def add(self, title: str, severity: str = "medium",
            description: str = "", remediation: str = "",
            evidence_refs: list = None, source: str = "",
            cve: str = "", cwe: str = "", impact: str = "",
            poc: str = "", references: list = None) -> dict:
        if severity not in self.SEVERITIES:
            severity = "medium"
        finding = {
            "id": None,
            "title": title,
            "severity": severity,
            "description": description,
            "remediation": remediation,
            "evidence_refs": evidence_refs or [],
            "source": source,
            "cve": cve,
            "cwe": cwe,
            "impact": impact,
            "poc": poc,
            "references": references or [],
            "status": "unvalidated",
            "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "updated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        with self._lock:
            data = self._read()
            finding["id"] = f"F{len(data['findings'])+1:04d}"
            data["findings"].append(finding)
            self._write(data)
        return finding

    def list(self, severity: str = "", status: str = "") -> List[dict]:
        with self._lock:
            findings = self._read()["findings"]
        if severity:
            findings = [f for f in findings if f["severity"] == severity]
        if status:
            findings = [f for f in findings if f["status"] == status]
        return findings

    def get(self, finding_id: str) -> Optional[dict]:
        with self._lock:
            for f in self._read()["findings"]:
                if f["id"] == finding_id:
                    return dict(f)
        return None

    def update(self, finding_id: str, **kwargs) -> Optional[dict]:
        allowed = {"title", "severity", "description", "remediation",
                   "evidence_refs", "status", "source",
                   "cve", "cwe", "impact", "poc", "references"}
        with self._lock:
            data = self._read()
            for f in data["findings"]:
                if f["id"] == finding_id:
                    for k, v in kwargs.items():
                        if k in allowed:
                            if k == "severity" and v not in self.SEVERITIES:
                                continue
                            f[k] = v
                    f["updated"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    self._write(data)
                    return dict(f)
        return None

    def delete(self, finding_id: str) -> bool:
        with self._lock:
            data = self._read()
            before = len(data["findings"])
            data["findings"] = [f for f in data["findings"] if f["id"] != finding_id]
            if len(data["findings"]) < before:
                self._write(data)
                return True
        return False

    def close(self, finding_id: str) -> Optional[dict]:
        return self.update(finding_id, status="closed_other")

    def summary(self) -> dict:
        with self._lock:
            data = self._read()["findings"]
        counts = {}
        for f in data:
            sev = f["severity"]
            counts[sev] = counts.get(sev, 0) + 1
        return {
            "total": len(data),
            "by_severity": counts,
            "unvalidated": sum(1 for f in data if f["status"] in ("open", "unvalidated")),
        }

    def import_from_nuclei(self, nuclei_json: Path) -> int:
        """Parse nuclei JSON-lines and add as findings. Returns count added."""
        count = 0
        try:
            with nuclei_json.open() as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                        info = item.get("info", {})
                        sev_map = {"unknown": "info", "low": "low",
                                   "medium": "medium", "high": "high",
                                   "critical": "critical"}
                        sev = sev_map.get(info.get("severity", ""), "info")
                        self.add(
                            title=info.get("name", item.get("template-id", "?")),
                            severity=sev,
                            description=f"Matched at: {item.get('matched-at', '?')}",
                            source=f"nuclei:{item.get('template-id', '?')}",
                            evidence_refs=[str(nuclei_json)],
                        )
                        count += 1
                    except Exception:

                        logger.debug("Exception in findings_db.py", exc_info=True)
        except Exception:

            logger.debug("Exception in findings_db.py", exc_info=True)
        return count