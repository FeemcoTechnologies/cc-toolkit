import datetime
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import threading
from pathlib import Path
from typing import Dict, List, Optional

from .config import CASES_DIR


def _dir_size(path: Path) -> int:
    total = 0
    for f in path.rglob("*"):
        if f.is_file():
            total += f.stat().st_size
    return total


def _human_size(size: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


class CaseManager:
    """Create and manage forensic/pentest/IR cases with evidence tracking."""

    CASE_TYPES = [
        "pentest",            # generic/unclassified
        "pentest_web",        # web application
        "pentest_external",    # external network
        "pentest_internal_ad", # internal AD
        "pentest_cloud",       # cloud (AWS, Azure, GCP)
        "pentest_physical",    # physical facility
        "ir",                 # incident response (operational)
        "forensics",          # deep-dive forensics (chain of custody)
        "osint",              # OSINT research
    ]

    CASE_STRUCTURE = {
        "scans": "Raw scan outputs (nmap, nuclei, ffuf, etc.)",
        "loot": "Extracted data, credentials, files",
        "evidence": "Hashed evidence files for chain of custody",
        "reports": "Generated reports (HTML, Markdown, PDF)",
        "screenshots": "Screenshots of findings",
        "notes": "Case notes and observations",
        "wordlists": "Custom wordlists for this case",
    }

    # Allowed parent directories for source files in add_evidence
    _ALLOWED_SOURCE_DIRS = None

    @classmethod
    def _allowed_src_dirs(cls) -> List[Path]:
        if cls._ALLOWED_SOURCE_DIRS is None:
            dirs = [Path.cwd()]
            for env_var in ("TMPDIR", "TEMP", "TMP"):
                val = os.environ.get(env_var)
                if val:
                    dirs.append(Path(val))
            cls._ALLOWED_SOURCE_DIRS = dirs
        return cls._ALLOWED_SOURCE_DIRS

    @classmethod
    def _is_allowed_source(cls, path: Path) -> bool:
        """Check that a source file path is within an allowed directory."""
        resolved = path.resolve()
        for base in cls._allowed_src_dirs():
            try:
                if os.path.commonpath([str(resolved), str(base.resolve())]) == str(base.resolve()):
                    return True
            except (ValueError, OSError):
                continue
        return False

    def __init__(self, cases_dir: Optional[Path] = None):
        self.cases_dir = Path(cases_dir or CASES_DIR)
        self.cases_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._file_locks: Dict[str, threading.Lock] = {}

    def _get_file_lock(self, path: Path) -> threading.Lock:
        key = str(path.resolve())
        if key not in self._file_locks:
            self._file_locks[key] = threading.Lock()
        return self._file_locks[key]

    def _update_json(self, path: Path, updater):
        """Atomically read, modify, and write a JSON file."""
        lock = self._get_file_lock(path)
        with lock:
            data = json.loads(path.read_text()) if path.exists() else {}
            result = updater(data)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2, default=str))
            tmp.replace(path)
            return result if result is not None else data

    def _case_path(self, case_id: str) -> Path:
        return self.cases_dir / case_id

    def _manifest_path(self, case_id: str) -> Path:
        return self._case_path(case_id) / "case.json"

    def _write_manifest(self, case_id: str, manifest: dict):
        """Atomically write manifest to case.json via tmp+replace."""
        mf = self._manifest_path(case_id)
        manifest["modified"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        tmp = mf.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(manifest, indent=2, default=str))
        tmp.replace(mf)

    def _update_manifest(self, case_id: str, updater) -> Optional[dict]:
        """Atomically read, modify, and write case.json. updater(manifest) is called under lock."""
        with self._lock:
            mf = self._manifest_path(case_id)
            if not mf.exists():
                return None
            manifest = json.loads(mf.read_text())
            result = updater(manifest)
            self._write_manifest(case_id, manifest)
            return result if result is not None else manifest

    def list_cases(self) -> List[dict]:
        cases = []
        for d in sorted(self.cases_dir.iterdir()):
            if d.is_dir():
                mf = d / "case.json"
                if mf.exists():
                    try:
                        c = json.loads(mf.read_text())
                    except (json.JSONDecodeError, ValueError):
                        c = {"case_id": d.name, "status": "corrupt"}
                    cases.append(c)
                else:
                    cases.append({
                        "case_id": d.name,
                        "created": datetime.datetime.fromtimestamp(
                            d.stat().st_ctime
                        ).isoformat(),
                        "status": "unknown",
                    })
        return cases

    def create(self, case_id: str, client: str = "",
               case_type: str = "pentest",
               description: str = "", targets: list = None,
               goals: list = None) -> dict:
        case_dir = self._case_path(case_id)
        if case_dir.exists():
            raise FileExistsError(f"Case '{case_id}' already exists at {case_dir}")

        if case_type not in self.CASE_TYPES:
            raise ValueError(f"Invalid case_type '{case_type}'. Valid: {', '.join(self.CASE_TYPES)}")

        now = datetime.datetime.now(datetime.timezone.utc)
        manifest = {
            "case_id": case_id,
            "client": client,
            "type": case_type,
            "description": description,
            "goals": goals or [],
            "status": "open",
            "created": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "modified": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "evidence": [],
            "notes": [],
            "scope": {"in_scope": targets or [], "out_of_scope": []},
        }
        # Shared timeline — available for all case types
        manifest["ir_timeline"] = []
        # Type-specific defaults
        if case_type == "ir":
            manifest["ir_ttps"] = []
            manifest["ir_containment"] = []
        elif case_type == "forensics":
            manifest["forensics_chain_of_custody"] = []
        case_dir.mkdir(parents=True, exist_ok=True)
        for subdir in self.CASE_STRUCTURE:
            (case_dir / subdir).mkdir(parents=True, exist_ok=True)
        self._manifest_path(case_id).write_text(json.dumps(manifest, indent=2))
        # Log creation event
        self.ir_timeline_add(case_id, now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                             f"Case created ({case_type})", severity="info",
                             source="system")
        return manifest

    def info(self, case_id: str) -> Optional[dict]:
        mf = self._manifest_path(case_id)
        if not mf.exists():
            return None
        manifest = json.loads(mf.read_text())
        case_dir = self._case_path(case_id)
        for subdir in self.CASE_STRUCTURE:
            sp = case_dir / subdir
            if sp.exists():
                files = list(sp.iterdir())
                manifest[f"_{subdir}_count"] = len(files)
                manifest[f"_{subdir}_size"] = sum(
                    f.stat().st_size for f in files if f.is_file()
                )
        # Add findings summary
        findings_p = case_dir / "findings.json"
        if findings_p.exists():
            fd = json.loads(findings_p.read_text())
            manifest["_findings_total"] = len(fd.get("findings", []))
            by_sev = {}
            for f in fd.get("findings", []):
                s = f.get("severity", "unknown")
                by_sev[s] = by_sev.get(s, 0) + 1
            manifest["_findings_by_severity"] = by_sev
        # Add scope summary
        scope_p = case_dir / "scope.json"
        if scope_p.exists():
            sc = json.loads(scope_p.read_text())
            manifest["_scope_count"] = len(sc.get("in_scope", []))
        # Add tasks summary
        tasks_p = case_dir / "tasks.json"
        if tasks_p.exists():
            tk = json.loads(tasks_p.read_text())
            manifest["_tasks_total"] = len(tk.get("tasks", []))
            manifest["_tasks_done"] = sum(1 for t in tk.get("tasks", []) if t.get("done"))
            manifest["tasks"] = tk.get("tasks", [])
        return manifest

    def get_evidence(self, case_id: str) -> list:
        mf = self._manifest_path(case_id)
        if not mf.exists():
            return []
        manifest = json.loads(mf.read_text())
        return manifest.get("evidence", [])

    def get_notes(self, case_id: str) -> list:
        mf = self._manifest_path(case_id)
        if not mf.exists():
            return []
        manifest = json.loads(mf.read_text())
        return manifest.get("notes", [])

    def add_evidence(self, case_id: str, filepath: str,
                     category: str = "evidence",
                     description: str = "") -> Optional[dict]:
        mf = self._manifest_path(case_id)
        if not mf.exists():
            return None
        manifest = json.loads(mf.read_text())
        src = Path(filepath).resolve()
        if not src.exists():
            return None
        case_dir = self._case_path(case_id).resolve()
        # Reject source files outside allowed directories (prevents arbitrary file read)
        if not str(src).startswith(str(case_dir)) and not self._is_allowed_source(src):
            return None
        ev_dir = (case_dir / category).resolve()
        ev_dir.mkdir(parents=True, exist_ok=True)
        dest = (ev_dir / src.name).resolve()
        # If source is already inside the case directory, register in-place
        # rather than copying (avoids SameFileError from shutil.copy2).
        if str(src).startswith(str(case_dir)):
            stored_path = src
        else:
            shutil.copy2(str(src), str(dest))
            stored_path = dest
        data = stored_path.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()
        record = {
            "original_path": str(src),
            "stored_path": str(stored_path),
            "filename": src.name,
            "size": src.stat().st_size,
            "sha256": sha256,
            "md5": md5,
            "category": category,
            "description": description,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        manifest["evidence"].append(record)
        self._write_manifest(case_id, manifest)
        return record

    def delete_evidence(self, case_id: str, filename: str) -> bool:
        """Remove an evidence record from the manifest by filename. Returns True if found and removed."""
        mf = self._manifest_path(case_id)
        if not mf.exists():
            return False
        manifest = json.loads(mf.read_text())
        ev_list = manifest.get("evidence", [])
        new_list = [e for e in ev_list if e.get("filename") != filename]
        if len(new_list) == len(ev_list):
            return False
        manifest["evidence"] = new_list
        self._write_manifest(case_id, manifest)
        return True

    def verify_evidence(self, case_id: str) -> List[dict]:
        """Rehash all evidence files and compare against manifest. Return discrepancies."""
        mf = self._manifest_path(case_id)
        if not mf.exists():
            return [{"error": "Case not found"}]
        manifest = json.loads(mf.read_text())
        results = []
        for ev in manifest.get("evidence", []):
            stored = Path(ev["stored_path"])
            if not stored.exists():
                results.append({
                    "filename": ev["filename"],
                    "status": "missing",
                    "expected_sha256": ev["sha256"],
                })
                continue
            actual_sha = hashlib.sha256(stored.read_bytes()).hexdigest()
            actual_md5 = hashlib.md5(stored.read_bytes()).hexdigest()
            match = actual_sha == ev["sha256"] and actual_md5 == ev["md5"]
            results.append({
                "filename": ev["filename"],
                "status": "valid" if match else "CORRUPTED",
                "sha256_match": actual_sha == ev["sha256"],
                "md5_match": actual_md5 == ev["md5"],
            })
        return results

    # ---- Scope Tracker ----
    def _scope_path(self, case_id: str) -> Path:
        return self._case_path(case_id) / "scope.json"

    def _load_scope(self, case_id: str) -> dict:
        p = self._scope_path(case_id)
        if p.exists():
            return json.loads(p.read_text())
        mf = self._manifest_path(case_id)
        if mf.exists():
            return json.loads(mf.read_text()).get("scope",
                                                   {"in_scope": [], "out_of_scope": []})
        return {"in_scope": [], "out_of_scope": []}

    def _save_scope(self, case_id: str, scope: dict):
        self._scope_path(case_id).write_text(json.dumps(scope, indent=2))

    def scope_add(self, case_id: str, target: str, in_scope: bool = True) -> dict:
        sp = self._scope_path(case_id)
        key = "in_scope" if in_scope else "out_of_scope"
        return self._update_json(sp, lambda scope: (
            scope.setdefault(key, []).append(target)
            if target not in scope.setdefault(key, []) else None,
            scope.setdefault("in_scope", scope.get("in_scope", [])),
            scope.setdefault("out_of_scope", scope.get("out_of_scope", [])),
            scope
        )[-1])

    def scope_remove(self, case_id: str, target: str) -> dict:
        sp = self._scope_path(case_id)
        return self._update_json(sp, lambda scope: (
            scope.get("in_scope", []).remove(target)
            if target in scope.get("in_scope", []) else None,
            scope.get("out_of_scope", []).remove(target)
            if target in scope.get("out_of_scope", []) else None,
            scope
        )[-1])

    def scope_list(self, case_id: str) -> dict:
        return self._load_scope(case_id)

    def scope_check(self, case_id: str, target: str) -> dict:
        """Check if a target is in scope. Returns {'in_scope': bool, 'reason': str}."""
        scope = self._load_scope(case_id)
        if target in scope.get("in_scope", []):
            return {"in_scope": True, "reason": "explicitly in scope"}
        if target in scope.get("out_of_scope", []):
            return {"in_scope": False, "reason": "explicitly out of scope"}
        if scope.get("in_scope"):
            return {"in_scope": False, "reason": "not in defined scope"}
        return {"in_scope": True, "reason": "no scope restrictions"}

    # ---- Task Checklist ----
    def _tasks_path(self, case_id: str) -> Path:
        return self._case_path(case_id) / "tasks.json"

    def _load_tasks(self, case_id: str) -> dict:
        p = self._tasks_path(case_id)
        if p.exists():
            return json.loads(p.read_text())
        return {"tasks": []}

    def _save_tasks(self, case_id: str, data: dict):
        self._tasks_path(case_id).write_text(json.dumps(data, indent=2))

    def task_add(self, case_id: str, description: str,
                 priority: str = "medium") -> dict:
        tp = self._tasks_path(case_id)
        task = {"id": None, "description": description, "priority": priority,
                "done": False, "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        return self._update_json(tp, lambda data: (
            data.setdefault("tasks", []),
            task.__setitem__("id", f"T{len(data['tasks'])+1:03d}"),
            data["tasks"].append(task),
            task
        )[-1])

    def task_done(self, case_id: str, task_id: str) -> Optional[dict]:
        tp = self._tasks_path(case_id)
        return self._update_json(tp, lambda data: next(
            (t for t in data.get("tasks", []) if t["id"] == task_id
             and t.__setitem__("done", True) is None
             and t.__setitem__("completed", datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")) is None),
            None
        ))

    def task_list(self, case_id: str, show_done: bool = False) -> List[dict]:
        tasks = self._load_tasks(case_id)["tasks"]
        if not show_done:
            tasks = [t for t in tasks if not t["done"]]
        return tasks

    def task_delete(self, case_id: str, task_id: str) -> bool:
        tp = self._tasks_path(case_id)
        if not tp.exists():
            return False
        tasks = json.loads(tp.read_text())
        before = len(tasks["tasks"])
        tasks["tasks"] = [t for t in tasks["tasks"] if t["id"] != task_id]
        if len(tasks["tasks"]) < before:
            tp.write_text(json.dumps(tasks, indent=2))
            return True
        return False

    def add_note(self, case_id: str, body: str, tags: List[str] = None) -> Optional[dict]:
        mf = self._manifest_path(case_id)
        if not mf.exists():
            return None
        manifest = json.loads(mf.read_text())
        note = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "body": body,
            "tags": tags or [],
        }
        manifest["notes"].append(note)
        self._write_manifest(case_id, manifest)
        return note

    def close(self, case_id: str) -> Optional[dict]:
        return self.set_meta(case_id, status="closed")

    # ---- Archive / Unarchive ----

    def _archive_path(self, case_id: str) -> Path:
        return self.cases_dir / f"{case_id}.tar.gz"

    def archive_case(self, case_id: str) -> dict:
        """Compress a closed case to a tar.gz archive and remove the live directory.
        The case.json manifest is embedded inside the archive for searching.
        Returns summary dict.
        """
        case_dir = self._case_path(case_id)
        if not case_dir.exists():
            raise FileNotFoundError(f"Case '{case_id}' directory not found at {case_dir}")

        # Ensure closed and log to timeline
        mf = self._manifest_path(case_id)
        now = datetime.datetime.now(datetime.timezone.utc)
        if mf.exists():
            manifest = json.loads(mf.read_text())
            manifest["status"] = "closed"
            self._write_manifest(case_id, manifest)
            self.ir_timeline_add(case_id, now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                 "Case archived", severity="info", source="system")

        archive_path = self._archive_path(case_id)
        orig_size = _dir_size(case_dir)
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(case_dir, arcname=case_id)

        shutil.rmtree(case_dir)
        archived_size = archive_path.stat().st_size
        return {
            "case_id": case_id,
            "original_size": orig_size,
            "archived_size": archived_size,
            "savings_pct": round((1 - archived_size / max(orig_size, 1)) * 100, 1),
        }

    def unarchive_case(self, case_id: str) -> dict:
        """Extract a tar.gz archive back to a live case directory."""
        archive_path = self._archive_path(case_id)
        if not archive_path.exists():
            raise FileNotFoundError(f"Archive '{case_id}.tar.gz' not found")

        case_dir = self._case_path(case_id)
        if case_dir.exists():
            raise FileExistsError(f"Case '{case_id}' already exists — remove it first or unarchive to a different ID")

        with tarfile.open(archive_path, "r:gz") as tar:
            for member in tar.getmembers():
                # Prevent tar-slip path traversal
                member_path = Path(member.name)
                if member_path.is_absolute() or ".." in member_path.parts:
                    raise tarfile.ExtractError(f"Unsafe path in archive: {member.name}")
            tar.extractall(path=self.cases_dir)

        # Ensure case.json is valid and log to timeline
        mf = self._manifest_path(case_id)
        now = datetime.datetime.now(datetime.timezone.utc)
        if mf.exists():
            manifest = json.loads(mf.read_text())
            manifest["status"] = "archived"
            self._write_manifest(case_id, manifest)
            self.ir_timeline_add(case_id, now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                 "Case unarchived", severity="info", source="system")

        return {"case_id": case_id, "status": "unarchived"}

    def delete_archive(self, case_id: str) -> dict:
        """Permanently delete a case archive."""
        archive_path = self._archive_path(case_id)
        if not archive_path.exists():
            raise FileNotFoundError(f"Archive '{case_id}.tar.gz' not found")
        size = archive_path.stat().st_size
        archive_path.unlink()
        return {"case_id": case_id, "deleted_size": size}

    def list_archives(self) -> List[dict]:
        """List all archived cases (tar.gz files in cases dir)."""
        archives = []
        for f in sorted(self.cases_dir.glob("*.tar.gz")):
            case_id = f.stem  # removes .tar, leaves .gz base name
            if case_id.endswith(".tar"):
                case_id = case_id[:-4]
            size = f.stat().st_size
            archives.append({
                "case_id": case_id,
                "archived_size": size,
                "archived_size_hr": _human_size(size),
                "modified": datetime.datetime.fromtimestamp(
                    f.stat().st_mtime
                ).isoformat(),
            })
        return archives

    # ---- Goals ----
    def goal_add(self, case_id: str, goal: str) -> Optional[dict]:
        """Add an analysis goal to a case. Goals are required for all case types."""
        mf = self._manifest_path(case_id)
        if not mf.exists():
            return None
        manifest = json.loads(mf.read_text())
        if "goals" not in manifest:
            manifest["goals"] = []
        manifest["goals"].append(goal)
        self._write_manifest(case_id, manifest)
        return {"case_id": case_id, "goals": manifest["goals"]}

    def goal_remove(self, case_id: str, index: int = -1) -> Optional[dict]:
        mf = self._manifest_path(case_id)
        if not mf.exists():
            return None
        manifest = json.loads(mf.read_text())
        goals = manifest.get("goals", [])
        if not goals:
            return None
        if 0 <= index < len(goals):
            removed = goals.pop(index)
        else:
            removed = goals.pop()
        self._write_manifest(case_id, manifest)
        return {"removed": removed, "goals": goals}

    def goal_list(self, case_id: str) -> List[str]:
        mf = self._manifest_path(case_id)
        if not mf.exists():
            return []
        return json.loads(mf.read_text()).get("goals", [])

    # ---- Incident Response: Timeline ----
    def ir_timeline_add(self, case_id: str, timestamp: str,
                        event: str, severity: str = "info",
                        source: str = "") -> Optional[dict]:
        """Add a timestamped event to the IR timeline."""
        mf = self._manifest_path(case_id)
        if not mf.exists():
            return None
        manifest = json.loads(mf.read_text())
        if "ir_timeline" not in manifest:
            manifest["ir_timeline"] = []
        entry = {
            "timestamp": timestamp,
            "event": event,
            "severity": severity,
            "source": source,
            "logged": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        manifest["ir_timeline"].append(entry)
        self._write_manifest(case_id, manifest)
        return entry

    def ir_timeline_list(self, case_id: str) -> List[dict]:
        mf = self._manifest_path(case_id)
        if not mf.exists():
            return []
        return json.loads(mf.read_text()).get("ir_timeline", [])

    # ---- Incident Response: TTPs (MITRE ATT&CK) ----
    def ir_ttp_add(self, case_id: str, tactic: str, technique: str,
                   technique_id: str = "", notes: str = "") -> Optional[dict]:
        """Log a TTP observed during incident response."""
        mf = self._manifest_path(case_id)
        if not mf.exists():
            return None
        manifest = json.loads(mf.read_text())
        if "ir_ttps" not in manifest:
            manifest["ir_ttps"] = []
        entry = {
            "tactic": tactic,
            "technique": technique,
            "technique_id": technique_id,
            "notes": notes,
            "logged": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        manifest["ir_ttps"].append(entry)
        self._write_manifest(case_id, manifest)
        return entry

    def ir_ttp_list(self, case_id: str) -> List[dict]:
        mf = self._manifest_path(case_id)
        if not mf.exists():
            return []
        return json.loads(mf.read_text()).get("ir_ttps", [])

    # ---- Incident Response: Containment Steps ----
    def ir_containment_add(self, case_id: str, action: str,
                           status: str = "pending",
                           owner: str = "") -> Optional[dict]:
        """Document a containment/remediation step."""
        mf = self._manifest_path(case_id)
        if not mf.exists():
            return None
        manifest = json.loads(mf.read_text())
        if "ir_containment" not in manifest:
            manifest["ir_containment"] = []
        entry = {
            "id": f"C{len(manifest['ir_containment'])+1:03d}",
            "action": action,
            "status": status,
            "owner": owner,
            "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        manifest["ir_containment"].append(entry)
        self._write_manifest(case_id, manifest)
        return entry

    def ir_containment_update(self, case_id: str, containment_id: str,
                              status: str) -> Optional[dict]:
        mf = self._manifest_path(case_id)
        if not mf.exists():
            return None
        manifest = json.loads(mf.read_text())
        for entry in manifest.get("ir_containment", []):
            if entry.get("id") == containment_id:
                entry["status"] = status
                entry["updated"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                self._write_manifest(case_id, manifest)
                return entry
        return None

    def ir_containment_list(self, case_id: str) -> List[dict]:
        mf = self._manifest_path(case_id)
        if not mf.exists():
            return []
        return json.loads(mf.read_text()).get("ir_containment", [])

    def ir_summary(self, case_id: str) -> dict:
        """Return a summary of IR data for a case."""
        mf = self._manifest_path(case_id)
        if not mf.exists():
            return {"error": "Case not found"}
        manifest = json.loads(mf.read_text())
        timeline = manifest.get("ir_timeline", [])
        ttps = manifest.get("ir_ttps", [])
        containment = manifest.get("ir_containment", [])
        return {
            "case_id": case_id,
            "timeline_events": len(timeline),
            "ttps": len(ttps),
            "containment_steps": len(containment),
            "containment_done": sum(1 for c in containment if c.get("status") == "done"),
            "severity_counts": {
                s: sum(1 for e in timeline if e.get("severity") == s)
                for s in set(e.get("severity", "info") for e in timeline)
            },
        }

    # ---- Metadata update (dates, exec summary, contacts, methodology, etc.) ----
    def set_meta(self, case_id: str, **kwargs) -> Optional[dict]:
        """Update arbitrary metadata fields in case.json manifest.

        Allowed keys: client, description, case_type, status, assessment_dates,
        executive_summary, key_observations, recommendations, contacts,
        methodology_tools, strengths, weaknesses.
        """
        allowed = {"client", "description", "case_type", "status",
                   "assessment_dates", "executive_summary", "key_observations",
                   "recommendations", "contacts", "methodology_tools",
                   "strengths", "weaknesses"}
        old_status = [None]

        def updater(manifest):
            old_status[0] = manifest.get("status", "")
            for k, v in kwargs.items():
                if k in allowed:
                    manifest[k] = v
            return manifest

        result = self._update_manifest(case_id, updater)
        if result is None:
            return None
        # Log status changes to timeline
        if "status" in kwargs and kwargs["status"] != old_status[0]:
            ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            self.ir_timeline_add(case_id, ts,
                                 f"Status changed: {old_status[0] or 'unknown'} → {kwargs['status']}",
                                 severity="info", source="system")
        return result

    # ---- Strengths ----
    def add_strength(self, case_id: str, text: str) -> Optional[dict]:
        mf = self._manifest_path(case_id)
        if not mf.exists():
            return None
        manifest = json.loads(mf.read_text())
        if "strengths" not in manifest:
            manifest["strengths"] = []
        manifest["strengths"].append(text)
        self._write_manifest(case_id, manifest)
        return {"case_id": case_id, "strengths": manifest["strengths"]}

    def remove_strength(self, case_id: str, index: int = -1) -> Optional[dict]:
        mf = self._manifest_path(case_id)
        if not mf.exists():
            return None
        manifest = json.loads(mf.read_text())
        strengths = manifest.get("strengths", [])
        if not strengths:
            return None
        if 0 <= index < len(strengths):
            removed = strengths.pop(index)
        else:
            removed = strengths.pop()
        self._write_manifest(case_id, manifest)
        return {"removed": removed, "strengths": strengths}

    def list_strengths(self, case_id: str) -> List[str]:
        mf = self._manifest_path(case_id)
        if not mf.exists():
            return []
        return json.loads(mf.read_text()).get("strengths", [])

    # ---- Weaknesses ----
    def add_weakness(self, case_id: str, text: str) -> Optional[dict]:
        mf = self._manifest_path(case_id)
        if not mf.exists():
            return None
        manifest = json.loads(mf.read_text())
        if "weaknesses" not in manifest:
            manifest["weaknesses"] = []
        manifest["weaknesses"].append(text)
        self._write_manifest(case_id, manifest)
        return {"case_id": case_id, "weaknesses": manifest["weaknesses"]}

    def remove_weakness(self, case_id: str, index: int = -1) -> Optional[dict]:
        mf = self._manifest_path(case_id)
        if not mf.exists():
            return None
        manifest = json.loads(mf.read_text())
        weaknesses = manifest.get("weaknesses", [])
        if not weaknesses:
            return None
        if 0 <= index < len(weaknesses):
            removed = weaknesses.pop(index)
        else:
            removed = weaknesses.pop()
        self._write_manifest(case_id, manifest)
        return {"removed": removed, "weaknesses": weaknesses}

    def list_weaknesses(self, case_id: str) -> List[str]:
        mf = self._manifest_path(case_id)
        if not mf.exists():
            return []
        return json.loads(mf.read_text()).get("weaknesses", [])

    def evidence_chain(self, case_id: str) -> List[dict]:
        mf = self._manifest_path(case_id)
        if not mf.exists():
            return []
        manifest = json.loads(mf.read_text())
        return manifest.get("evidence", [])

    def delete(self, case_id: str) -> bool:
        case_dir = self._case_path(case_id)
        if not case_dir.exists():
            return False
        shutil.rmtree(str(case_dir))
        return True
