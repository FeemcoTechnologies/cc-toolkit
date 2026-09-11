import copy
import json
import threading
import uuid
from pathlib import Path
from typing import Dict, List, Optional

_CHECKLIST_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates" / "checklists"

_TEMPLATE_CACHE: Dict[str, dict] = {}
_TEMPLATE_CACHE_LOCK = threading.Lock()

ITEM_STATUSES = ["not_started", "in_progress", "passed", "failed", "not_applicable"]


def _load_template(template_id: str) -> Optional[dict]:
    with _TEMPLATE_CACHE_LOCK:
        if template_id in _TEMPLATE_CACHE:
            return copy.deepcopy(_TEMPLATE_CACHE[template_id])
        for ext in (".yaml", ".yml"):
            yml_path = _CHECKLIST_TEMPLATES_DIR / f"{template_id}{ext}"
            if yml_path.exists():
                import yaml
                with yml_path.open(encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                _TEMPLATE_CACHE[template_id] = data
                return copy.deepcopy(data)
        return None


def _safe_template_id(template_id: str) -> str:
    """Sanitize template_id for use as a filename (replace path separators)."""
    return template_id.replace("/", "-").replace("\\", "-")


def _save_template(template_id: str, data: dict) -> bool:
    """Save or overwrite a checklist template YAML."""
    safe_id = _safe_template_id(template_id)
    path = _CHECKLIST_TEMPLATES_DIR / f"{safe_id}.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    import yaml
    with path.open("w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
    with _TEMPLATE_CACHE_LOCK:
        _TEMPLATE_CACHE.pop(template_id, None)
    return True


def _delete_template(template_id: str) -> bool:
    safe_id = _safe_template_id(template_id)
    for ext in (".yaml", ".yml"):
        p = _CHECKLIST_TEMPLATES_DIR / f"{safe_id}{ext}"
        if p.exists():
            p.unlink()
            with _TEMPLATE_CACHE_LOCK:
                _TEMPLATE_CACHE.pop(template_id, None)
            return True
    return False


def list_templates() -> List[dict]:
    """List all available checklist templates."""
    results = []
    for p in sorted(_CHECKLIST_TEMPLATES_DIR.glob("*.yaml")) + sorted(_CHECKLIST_TEMPLATES_DIR.glob("*.yml")):
        with _TEMPLATE_CACHE_LOCK:
            if p.stem in _TEMPLATE_CACHE:
                data = _TEMPLATE_CACHE[p.stem]
            else:
                import yaml
                try:
                    with p.open(encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                except Exception:
                    continue
                _TEMPLATE_CACHE[p.stem] = data
        results.append({
            "id": p.stem,
            "title": data.get("title", p.stem),
            "description": data.get("description", ""),
            "version": data.get("version", ""),
            "item_count": sum(len(c.get("items", [])) for c in data.get("categories", [])),
        })
    return results


def get_template_source(template_id: str) -> Optional[str]:
    """Return raw YAML source of a template."""
    safe_id = _safe_template_id(template_id)
    for ext in (".yaml", ".yml"):
        p = _CHECKLIST_TEMPLATES_DIR / f"{safe_id}{ext}"
        if p.exists():
            return p.read_text(encoding="utf-8")
    return None


class ChecklistInstance:
    """Checklist instances attached to a specific case. Supports multiple per case."""

    def __init__(self, case_dir: Path):
        self.case_dir = Path(case_dir)
        self._path = self.case_dir / "checklists.json"
        self._lock = threading.Lock()

    def _read(self) -> List[dict]:
        # Backward compat: migrate old single checklist.json to new format
        old_path = self.case_dir / "checklist.json"
        if old_path.exists() and not self._path.exists():
            try:
                old = json.loads(old_path.read_text())
                if isinstance(old, dict) and "items" in old:
                    old["instance_id"] = old.get("instance_id", str(uuid.uuid4()))
                    self._write([old])
                    old_path.unlink()
            except Exception:
                pass

        if self._path.exists():
            try:
                data = json.loads(self._path.read_text())
                if isinstance(data, list):
                    return data
            except (json.JSONDecodeError, ValueError, OSError):
                pass
        return []

    def _write(self, data: List[dict]):
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, default=str))
        tmp.replace(self._path)

    def _build_instance(self, template: dict) -> dict:
        items = {}
        for cat in template.get("categories", []):
            for item in cat.get("items", []):
                items[item["id"]] = {
                    "status": "not_started",
                    "notes": "",
                    "finding_id": None,
                    "runbook_result": None,
                    "updated": None,
                }
        now = __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat()
        return {
            "instance_id": str(uuid.uuid4()),
            "checklist_id": template.get("checklist_id", ""),
            "title": template.get("title", ""),
            "template_version": template.get("version", ""),
            "categories": template.get("categories", []),
            "items": items,
            "created": now,
            "modified": None,
        }

    def initialize(self, template_id: str, replace: bool = False) -> dict:
        """Create a new checklist instance from a template.
        If replace=True and instances exist, replaces the last one.
        Otherwise appends."""
        template = _load_template(template_id)
        if not template:
            return {"error": f"Template '{template_id}' not found"}
        instance = self._build_instance(template)
        instances = self._read()
        if replace and instances:
            instances[-1] = instance
        else:
            instances.append(instance)
        self._write(instances)
        return instance

    def from_findings(self, findings: List[dict], title: str = "",
                      replace: bool = False) -> dict:
        """Build a checklist instance directly from findings (grouped by severity).

        Each finding becomes an item whose id matches the finding id and is
        pre-linked via `finding_id`, so the compliance export / review flow can
        map controls back to evidence.
        """
        now = __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat()
        categories = []
        for sev in ("critical", "high", "medium", "low", "info"):
            items = [f for f in findings if f.get("severity") == sev]
            if not items:
                continue
            categories.append({
                "name": f"{sev.capitalize()} ({len(items)})",
                "items": [{"id": f.get("id", ""),
                           "description": f.get("title", ""),
                           "finding_id": f.get("id", "")}
                          for f in items],
            })
        instance = {
            "instance_id": str(uuid.uuid4()),
            "checklist_id": "from-findings",
            "title": title or "Findings Review",
            "template_version": "1.0",
            "categories": categories,
            "items": {
                f.get("id", ""): {
                    "status": "not_started",
                    "notes": "",
                    "finding_id": f.get("id", ""),
                    "runbook_result": None,
                    "updated": None,
                } for f in findings if f.get("id")
            },
            "created": now,
            "modified": None,
        }
        instances = self._read()
        if replace and instances:
            instances[-1] = instance
        else:
            instances.append(instance)
        self._write(instances)
        return instance

    def get(self) -> List[dict]:
        """Return all checklist instances."""
        instances = self._read()
        for inst in instances:
            inst.setdefault("instance_id", str(uuid.uuid4()))
            inst.setdefault("items", {})
        return instances

    def get_instance(self, instance_id: str) -> Optional[dict]:
        """Return a single checklist instance by ID."""
        for inst in self._read():
            if inst.get("instance_id") == instance_id:
                return inst
        return None

    def delete_instance(self, instance_id: str) -> bool:
        """Delete a checklist instance by ID."""
        instances = self._read()
        before = len(instances)
        instances = [i for i in instances if i.get("instance_id") != instance_id]
        if len(instances) < before:
            self._write(instances)
            return True
        return False

    def get_progress(self, instance_id: str = "") -> dict:
        """Return progress summary counts for a specific instance or all."""
        instances = self._read()
        if instance_id:
            instances = [i for i in instances if i.get("instance_id") == instance_id]

        total = 0
        counts = {s: 0 for s in ITEM_STATUSES}
        for inst in instances:
            items = inst.get("items", {})
            total += len(items)
            for v in items.values():
                s = v.get("status", "not_started")
                counts[s] = counts.get(s, 0) + 1

        return {
            "total": total,
            "by_status": counts,
            "completed": counts.get("passed", 0) + counts.get("not_applicable", 0),
            "percent": round(
                (counts.get("passed", 0) + counts.get("not_applicable", 0))
                / total * 100 if total else 0
            ),
        }

    def update_item(
        self,
        item_id: str,
        status: str = None,
        notes: str = None,
        finding_id: str = None,
        runbook_result: str = None,
        instance_id: str = "",
    ) -> Optional[dict]:
        """Update a single checklist item. If instance_id is empty, applies to all."""
        if status and status not in ITEM_STATUSES:
            return None
        now = __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat()
        with self._lock:
            instances = self._read()
            updated = None
            for inst in instances:
                if instance_id and inst.get("instance_id") != instance_id:
                    continue
                items = inst.get("items", {})
                if item_id not in items:
                    continue
                if status is not None:
                    items[item_id]["status"] = status
                if notes is not None:
                    items[item_id]["notes"] = notes
                if finding_id is not None:
                    items[item_id]["finding_id"] = finding_id
                if runbook_result is not None:
                    items[item_id]["runbook_result"] = runbook_result
                items[item_id]["updated"] = now
                inst["modified"] = now
                updated = dict(items[item_id])
            if updated is not None:
                self._write(instances)
            return updated

    def set_finding(self, item_id: str, finding_id: str,
                    instance_id: str = "") -> Optional[dict]:
        return self.update_item(item_id, finding_id=finding_id, instance_id=instance_id)

    def items_by_status(self, status: str = "", instance_id: str = "") -> List[tuple]:
        """Return (item_id, metadata, category_name) for matching items."""
        results = []
        for inst in self._read():
            if instance_id and inst.get("instance_id") != instance_id:
                continue
            for cat in inst.get("categories", []):
                for tmpl in cat.get("items", []):
                    meta = inst.get("items", {}).get(tmpl["id"])
                    if meta and (not status or meta.get("status") == status):
                        results.append((tmpl, meta, cat["name"]))
        return results

    def items_by_category(self, instance_id: str = "") -> List[dict]:
        """Return categories enriched with instance status."""
        results = []
        for inst in self._read():
            if instance_id and inst.get("instance_id") != instance_id:
                continue
            items = inst.get("items", {})
            for cat in inst.get("categories", []):
                cat_items = []
                for tmpl in cat.get("items", []):
                    meta = items.get(tmpl["id"], {})
                    cat_items.append({**tmpl, **meta})
                results.append({
                    "instance_id": inst.get("instance_id", ""),
                    "instance_title": inst.get("title", ""),
                    "name": cat["name"],
                    "items": cat_items,
                    "total": len(cat_items),
                    "passed": sum(1 for i in cat_items if i.get("status") == "passed"),
                    "failed": sum(1 for i in cat_items if i.get("status") == "failed"),
                    "in_progress": sum(1 for i in cat_items if i.get("status") == "in_progress"),
                    "not_started": sum(1 for i in cat_items if i.get("status") == "not_started"),
                })
        return results