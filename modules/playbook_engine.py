import logging
"""
Runbook Engine v2 — full automation with conditionals, loops, parallel execution,
human prompts, notifications, nested runbooks, artifact tracking, and reports.

Supports both legacy playbook YAML (simple tool chain) and v2 runbook YAML.
"""

import datetime
import functools
import json
import os
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from shutil import which
from typing import Any, Dict, List, Optional, Tuple, Union

from .config import PLAYBOOKS_DIR, CASES_DIR, CC_DIR
from .notifier import Notifier
from .report_generator import generate_markdown_report
logger = logging.getLogger(__name__)

try:
    import yaml
except ImportError:
    yaml = None


# Precompiled regex for variable resolution (avoids re.compile per call)
_STEP_VAR_RE = re.compile(r"\{steps\.(\w+)\.(\w+)\}")
_STEP_STDOUT_RE = re.compile(r"\{steps\.(\w+)\.stdout_lines\}")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class RunbookError(Exception):
    pass


# ---------------------------------------------------------------------------
# Context — holds all state during runbook execution
# ---------------------------------------------------------------------------
class RunContext:
    def __init__(self, runbook_path: str, targets: List[str], case_id: str,
                 vars_override: dict):
        self.runbook_path = runbook_path
        self.targets = targets
        self.case_id = case_id or f"run_{datetime.datetime.now():%Y%m%d_%H%M%S}"
        self.case_dir = CASES_DIR / self.case_id
        self.vars: Dict[str, Any] = dict(vars_override or {})
        self.vars.setdefault("case_id", self.case_id)
        self.vars.setdefault("case_dir", str(self.case_dir))
        self.vars.setdefault("timestamp",
                             datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S"))
        self.vars.setdefault("scripts_dir", str(CC_DIR / "tools"))
        if targets:
            raw = targets[0]
            self.vars["target"] = raw
            self.vars["targets"] = targets
            self.vars["target_safe"] = raw.replace("/", "_")
        self.step_outputs: Dict[str, dict] = {}
        self.artifacts: List[Path] = []
        self.log: List[dict] = []
        self._lock = threading.Lock()
        self._step_index: Dict[str, int] = {}

    def set_var(self, key: str, value: Any):
        self.vars[key] = value

    def resolve(self, text: str) -> str:
        if not text or not isinstance(text, str):
            return text or ""
        # Replace {var}
        for k, v in self.vars.items():
            text = text.replace(f"{{{k}}}", str(v) if v is not None else "")
        # Replace {steps.id.field}
        for m in _STEP_VAR_RE.finditer(text):
            sid, field = m.group(1), m.group(2)
            out = self.step_outputs.get(sid, {})
            val = out.get(field, "")
            if isinstance(val, list):
                val = "\n".join(str(x) for x in val)
            text = text.replace(m.group(0), str(val))
        # Replace {steps.id.stdout_lines}
        for m in _STEP_STDOUT_RE.finditer(text):
            sid = m.group(1)
            out = self.step_outputs.get(sid, {})
            raw = out.get("stdout", "") or ""
            text = text.replace(m.group(0), raw)
        return text

    def resolve_args(self, args: Union[str, List, Dict]) -> Union[str, List, Dict]:
        if isinstance(args, str):
            return self.resolve(args)
        if isinstance(args, dict):
            return {k: self.resolve(v) for k, v in args.items()}
        return [self.resolve(a) for a in args]

    def add_artifact(self, path: str):
        p = Path(path)
        if p.exists():
            self.artifacts.append(p)

    def add_log(self, entry: dict):
        entry["ts"] = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        self.log.append(entry)


# ---------------------------------------------------------------------------
# Condition evaluator
# ---------------------------------------------------------------------------
def _eval_condition(condition: Any, ctx: RunContext) -> bool:
    if condition is None:
        return True
    if isinstance(condition, bool):
        return condition
    if isinstance(condition, str):
        return _eval_string_cond(condition, ctx)
    if isinstance(condition, dict):
        return _eval_dict_cond(condition, ctx)
    return True


def _eval_string_cond(cond: str, ctx: RunContext) -> bool:
    # on_port:N  — check if any previous step output mentions "/N/tcp open"
    m = re.match(r"on_port:(\d+)", cond)
    if m:
        port = m.group(1)
        for sid, out in ctx.step_outputs.items():
            text = out.get("stdout", "") or ""
            if f"/{port}" in text and "open" in text:
                return True
        return False
    # on_match:pattern
    m = re.match(r"on_match:(.+)", cond)
    if m:
        pattern = m.group(1).lower()
        for sid, out in ctx.step_outputs.items():
            text = (out.get("stdout", "") or "") + (out.get("stderr", "") or "")
            if pattern in text.lower():
                return True
        return False
    # on_rc:0
    m = re.match(r"on_rc:(-?\d+)", cond)
    if m:
        expected = int(m.group(1))
        return any(
            out.get("rc") == expected for out in ctx.step_outputs.values()
        )
    # always
    if cond.strip() == "always":
        return True
    return True


def _eval_dict_cond(cond: dict, ctx: RunContext) -> bool:
    operator = None
    for op in ("and", "or", "not", "ref", "contains", "eq", "gt", "lt",
                "exists", "file_exists"):
        if op in cond:
            operator = op
            break
    if operator == "and":
        return all(_eval_dict_cond(c, ctx) if isinstance(c, dict)
                   else _eval_string_cond(str(c), ctx) for c in cond["and"])
    elif operator == "or":
        return any(_eval_dict_cond(c, ctx) if isinstance(c, dict)
                   else _eval_string_cond(str(c), ctx) for c in cond["or"])
    elif operator == "not":
        return not _eval_dict_cond(cond["not"], ctx)
    elif operator == "ref":
        out = ctx.step_outputs.get(cond["ref"], {})
        expected = cond.get("expected")
        field = cond.get("field", "rc")
        val = out.get(field)
        if expected is not None:
            return str(val) == str(expected)
        return val is not None
    elif operator == "contains":
        out = ctx.step_outputs.get(cond.get("ref", ""), {})
        text = json.dumps(out)
        return cond["contains"] in text
    elif operator == "file_exists":
        return Path(ctx.resolve(cond["file_exists"])).exists()
    elif operator == "exists":
        return cond["exists"] in ctx.vars
    elif operator in ("eq", "gt", "lt"):
        left = ctx.resolve(str(cond.get(operator, "")))
        right = ctx.resolve(str(cond.get("value", "")))
        try:
            a, b = float(left), float(right)
            return {"eq": a == b, "gt": a > b, "lt": a < b}[operator]
        except (ValueError, TypeError):
            return {"eq": left == right,
                    "gt": left > right,
                    "lt": left < right}.get(operator, False)
    return True


# ---------------------------------------------------------------------------
# Step executors
# ---------------------------------------------------------------------------
def _reader_thread(stream, parts):
    """Read all lines from a stream into parts list."""
    for line in iter(stream.readline, ""):
        parts.append(line)
    stream.close()

def _exec_tool(step: dict, ctx: RunContext) -> dict:
    tool = step.get("tool", "")
    args = ctx.resolve_args(step.get("args", []))
    timeout = step.get("timeout", 600)
    tp = which(tool)
    if not tp:
        return {"rc": -1, "error": f"Tool not found: {tool}"}

    result = {"rc": -1, "stdout": "", "stderr": "", "cmd": f"{tool} {' '.join(args)}"}
    stdout_parts, stderr_parts = [], []
    proc = None
    try:
        proc = subprocess.Popen(
            [tp] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        import threading
        out_thread = threading.Thread(target=_reader_thread, args=(proc.stdout, stdout_parts), daemon=True)
        err_thread = threading.Thread(target=_reader_thread, args=(proc.stderr, stderr_parts), daemon=True)
        out_thread.start()
        err_thread.start()

        deadline = time.time() + timeout
        step_id = step.get("id", step.get("name", ""))
        while time.time() < deadline:
            out_thread.join(timeout=5)
            err_thread.join(timeout=5)
            if proc.poll() is not None:
                break
            # Periodic progress save: flush partial output to disk
            if step_id and ctx:
                partial = "".join(stdout_parts) if stdout_parts else ""
                partial_err = "".join(stderr_parts) if stderr_parts else ""
                with ctx._lock:
                    existing = ctx.step_outputs.get(step_id, {})
                    existing["stdout"] = partial[-2000:]
                    existing["stderr"] = partial_err[-2000:]
                    existing["running"] = True
                    existing["rc"] = -1
                    ctx.step_outputs[step_id] = existing
                # Write checkpoint file
                if ctx.case_dir:
                    try:
                        ck = {
                            "runbook": "",
                            "case_id": ctx.case_id,
                            "step_outputs": {k: {"rc": v.get("rc"), "error": v.get("error", ""),
                                                  "stdout": (v.get("stdout") or "")[-2000:],
                                                  "stderr": (v.get("stderr") or "")[-2000:],
                                                  "running": v.get("running", False),
                                                  "skipped": v.get("skipped", False)}
                                             for k, v in ctx.step_outputs.items()},
                        }
                        (ctx.case_dir / "runbook-log.json").write_text(
                            json.dumps(ck, indent=2, default=str))
                    except Exception:

                        logger.debug("Exception in playbook_engine.py", exc_info=True)

        out_thread.join(timeout=2)
        err_thread.join(timeout=2)
        if proc:
            proc.wait(timeout=timeout)
        result["rc"] = proc.returncode if proc else -1
        result["stdout"] = "".join(stdout_parts)
        result["stderr"] = "".join(stderr_parts)
        result["stdout_lines"] = [l.rstrip("\n\r") for l in stdout_parts
                                   if l.strip()]
    except subprocess.TimeoutExpired:
        if proc:
            proc.kill()
            proc.wait()
        result["error"] = f"Timed out after {timeout}s"
        result["stdout"] = "".join(stdout_parts) if stdout_parts else ""
        result["stderr"] = "".join(stderr_parts) if stderr_parts else ""
    except Exception as e:
        if proc:
            try:
                proc.kill()
                proc.wait(timeout=5)
            except Exception:

                logger.debug("Exception in playbook_engine.py", exc_info=True)
        result["error"] = str(e)

    # Save stdout to a specific path if requested
    save_path = step.get("save")
    if save_path:
        out_path = ctx.resolve(save_path)
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text(result.get("stdout", "") or "")
        result["saved_to"] = out_path
        ctx.add_artifact(out_path)

    # Track artifacts the tool was expected to create
    for art in step.get("artifacts", []):
        art_path = ctx.resolve(art)
        if Path(art_path).exists():
            ctx.add_artifact(art_path)
        elif art != save_path:
            result.setdefault("missing_artifacts", []).append(art)

    return result


def _exec_conditional(step: dict, ctx: RunContext, run_step_fn) -> List[dict]:
    results = []
    cond = step.get("condition") if "condition" in step else step.get("when", True)
    if _eval_condition(cond, ctx):
        then_steps = step.get("then", [])
        if isinstance(then_steps, dict):
            then_steps = [then_steps]
        for s in then_steps:
            r = run_step_fn(s, ctx)
            results.append(r)
    else:
        else_steps = step.get("else", [])
        if isinstance(else_steps, dict):
            else_steps = [else_steps]
        for s in else_steps:
            r = run_step_fn(s, ctx)
            results.append(r)
    return results


def _exec_foreach(step: dict, ctx: RunContext, run_step_fn) -> List[dict]:
    items_raw = step.get("items", [])
    items = ctx.resolve(str(items_raw)) if isinstance(items_raw, str) else items_raw
    if isinstance(items, str):
        items = [l.strip() for l in items.split("\n") if l.strip()]
    var_name = step.get("var", "item")
    child_steps = step.get("steps", [])
    results = []

    for item in items:
        ctx.set_var(var_name, item)
        for s in child_steps:
            r = run_step_fn(s, ctx)
            results.append(r)

    return results


def _exec_parallel(step: dict, ctx: RunContext, run_step_fn) -> List[dict]:
    children = step.get("steps", [])
    if isinstance(children, dict):
        children = [children]
    results = []
    max_workers = step.get("max_workers", 10)

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        fut_map = {}
        for s in children:
            sid = s.get("id", s.get("name", "parallel_step"))
            f = ex.submit(run_step_fn, s, ctx)
            fut_map[f] = sid
        for f in as_completed(fut_map):
            try:
                r = f.result()
                if isinstance(r, list):
                    results.extend(r)
                else:
                    results.append(r)
            except Exception as e:
                results.append({"error": str(e)})
    return results


def _exec_prompt(step: dict, ctx: RunContext, run_step_fn=None) -> dict:
    cond = step.get("condition") or step.get("when", True)
    if not _eval_condition(cond, ctx):
        return {"skipped": True}
    msg = ctx.resolve(step.get("message", "Continue?"))
    print(f"\n[PROMPT] {msg}")
    print("  [Y] Yes  [n] No  [s] Skip all prompts  [q] Quit runbook")
    try:
        resp = input("  \u2192 ").strip().lower() or "y"
    except (EOFError, KeyboardInterrupt):
        resp = "q"
    result = {"response": resp, "prompt": msg}
    if resp == "q":
        raise RunbookError("Runbook cancelled by operator")
    elif resp == "s":
        ctx.set_var("_skip_prompts", True)
    then_steps = step.get("then", [])
    if isinstance(then_steps, dict):
        then_steps = [then_steps]
    if resp == "y" and then_steps and run_step_fn:
        for s in then_steps:
            run_step_fn(s, ctx)
    return result


def _exec_notify(step: dict, ctx: RunContext) -> dict:
    cond = step.get("condition") or step.get("when", True)
    if not _eval_condition(cond, ctx):
        return {"notified": False}
    level = step.get("level", "info")
    msg = ctx.resolve(step.get("message", ""))
    symbols = {"info": "[i]", "warn": "[!]", "critical": "[!!!]", "success": "[+]"}
    sym = symbols.get(level, "[i]")
    print(f"\n  {sym} {level.upper()}: {msg}")
    ctx.add_log({"type": "notify", "level": level, "message": msg})
    # Send to configured webhooks
    webhook_targets = step.get("webhooks") or step.get("targets")
    if webhook_targets:
        cfg = {}
        try:
            from .constants import load_config
            cfg = load_config()
        except Exception:

            logger.debug("Exception in playbook_engine.py", exc_info=True)
        n = Notifier(cfg)
        results = n.send(msg, level, webhook_targets)
        for r in results:
            for k, v in r.items():
                if not v.get("sent"):
                    print(f"    [!] Webhook {k} failed: {v.get('error')}")
        return {"notified": True, "level": level, "message": msg, "webhooks": results}
    return {"notified": True, "level": level, "message": msg}


def _exec_set(step: dict, ctx: RunContext) -> dict:
    var = step.get("var", "")
    val = ctx.resolve(str(step.get("value", "")))
    if var:
        ctx.set_var(var, val)
        return {"set": var, "to": val}
    return {"error": "No var specified"}


def _exec_wait(step: dict, ctx: RunContext) -> dict:
    duration = int(step.get("duration", step.get("seconds", 5)))
    reason = ctx.resolve(step.get("reason", ""))
    if reason:
        print(f"  Waiting {duration}s — {reason}")
    else:
        print(f"  Waiting {duration}s...")
    time.sleep(duration)
    return {"waited": duration}


def _exec_runbook(step: dict, ctx: RunContext, run_step_fn) -> dict:
    path = ctx.resolve(step.get("path", ""))
    if not path:
        return {"error": "No runbook path specified"}
    pb = Path(path)
    if not pb.exists():
        pb = PLAYBOOKS_DIR / path
    if not pb.exists():
        pb = PLAYBOOKS_DIR / f"{path}.yaml"
    if not pb.exists():
        return {"error": f"Runbook not found: {path}"}

    sub_vars = ctx.resolve_args(step.get("vars", {}))
    sub_ctx = RunContext(
        str(pb), ctx.targets, f"{ctx.case_id}_sub",
        {**ctx.vars, **sub_vars}
    )
    engine = RunbookEngine(PLAYBOOKS_DIR)
    try:
        data = engine.load(str(pb))
        result = engine.run(data, sub_ctx)
        return {"nested_runbook": str(pb), "results_count": len(result)}
    except Exception as e:
        return {"error": str(e), "nested_runbook": str(pb)}


def _exec_report(step: dict, ctx: RunContext) -> dict:
    fmt = step.get("format", "markdown")
    title = ctx.resolve(step.get("title", "Runbook Report"))
    output = ctx.resolve(step.get("output", f"{ctx.case_dir}/report.md"))
    sections = {}

    for s in step.get("sections", []):
        heading = ctx.resolve(s.get("heading", "Section"))
        body = ctx.resolve(s.get("body", ""))
        sections[heading] = body

    # Auto-collect all step outputs as a section
    sections.setdefault("Step Outputs", "")
    for sid, out in ctx.step_outputs.items():
        rc = out.get("rc", "?")
        cmd = out.get("cmd", "?")
        sections["Step Outputs"] += f"- `{sid}` rc={rc} `{cmd}`\n"

    if fmt == "html":
        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>{title}</title><style>
body {{ font-family: Arial; margin: 2em; background: #f5f5f5; }}
h1 {{ color: #1a1a2e; border-bottom: 3px solid #e94560; }}
pre {{ background: #1e1e2e; color: #cdd6f4; padding: 1em; border-radius: 6px; }}
</style></head><body><h1>{title}</h1>"""
        for h, b in sections.items():
            html += f"<h2>{h}</h2><pre>{b}</pre>"
        html += f"<p>Generated {datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')} UTC</p></body></html>"
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text(html)
    else:
        md = generate_markdown_report(sections, title)
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text(md)

    ctx.add_artifact(output)
    return {"report": output, "format": fmt}


def _exec_log(step: dict, ctx: RunContext) -> dict:
    msg = ctx.resolve(step.get("message", "") or str(step.get("args", [""])[0]))
    ctx.add_log({"type": "log", "message": msg})
    return {"log": msg}


def _exec_burp(step: dict, ctx: RunContext) -> dict:
    """Execute a Burp Suite action via REST API. Step params:
        action: str       — "scan_start" | "scan_status" | "issues_list" | "proxy_history"
                            | "repeater_send" | "scope_set" | "health"
        target: str       — URL for scan_start / repeater_send
        scan_id: str      — scan ID for status / issues
        scope: [str]      — URL prefixes for scope_set
        limit: int        — max results for proxy_history/issues (default 50)
        severity: str     — filter issues by severity
        host: str         — filter proxy history by host
    """
    from .burp_client import BurpClient
    from .constants import BURP_API_URL, BURP_API_KEY, BURP_PROXY_URL

    action = step.get("action", "health")
    bc = BurpClient(api_url=BURP_API_URL, api_key=BURP_API_KEY,
                    proxy_url=BURP_PROXY_URL)

    if action == "health":
        result = bc.health()
        return {"rc": 0 if result.get("status") == "ok" else -1, **result}

    elif action == "scan_start":
        urls = step.get("targets", [ctx.resolve(step.get("target", ""))])
        if not urls or not urls[0]:
            return {"error": "No target specified for scan_start", "rc": -1}
        urls = [urls] if isinstance(urls, str) else urls
        r = bc.scan_start(urls)
        return {"rc": 0 if "error" not in r else -1, **r}

    elif action == "scan_status":
        sid = step.get("scan_id", "")
        if not sid:
            return {"error": "No scan_id specified", "rc": -1}
        r = bc.scan_status(sid)
        return {"rc": 0 if "error" not in r else -1, **r}

    elif action == "issues_list":
        sid = step.get("scan_id", ctx.vars.get("burp_scan_id", ""))
        sev = step.get("severity", "")
        if not sid:
            return {"error": "No scan_id specified for issues_list", "rc": -1}
        r = bc.issues_list(sid, severity=sev)
        return {"rc": 0, "issues": r, "count": len(r) if isinstance(r, list) else 0}

    elif action == "config_set":
        cfg = step.get("config", {})
        r = bc.config_set(cfg)
        return {"rc": 0 if "error" not in r else -1, **r}

    else:
        return {"error": f"Unknown burp action: {action}", "rc": -1}


def _exec_dns(step: dict, ctx: RunContext) -> dict:
    """Resolve or start monitoring a domain. Step params:
        domain: str    — target domain
        action: str    — "resolve" | "monitor"
        types: [str]   — record types (default: [A, AAAA, MX, NS])
        interval: int  — monitor interval in seconds
        duration: int  — total duration (0 = unlimited)
    """
    from .dns_wrapper import resolve, start_monitor, start_background_monitor

    domain = ctx.resolve(step.get("domain", step.get("target", "")))
    if not domain:
        return {"error": "No domain specified for dns step", "rc": -1}
    types = step.get("types", ["A", "AAAA", "MX", "NS"])
    action = step.get("action", "resolve").lower()

    if action == "monitor":
        interval = int(step.get("interval", 300))
        duration = int(step.get("duration", 0))
        start_background_monitor()
        r = start_monitor(domain, types, interval, duration)
        if "error" in r:
            return {"error": r["error"], "rc": -1}
        return {
            "rc": 0,
            "stdout": f"Monitoring {domain} every {interval}s for types {types}",
            "domain": domain,
            "action": "monitor",
            "interval": interval,
        }

    # Default: resolve
    records = resolve(domain, types)
    output_lines = []
    for rtype, entries in records.get("records", {}).items():
        if entries:
            output_lines.append(f"{rtype}: {', '.join(e['value'] for e in entries)}")
    result = {
        "rc": 0,
        "stdout": "\n".join(output_lines),
        "domain": domain,
        "action": "resolve",
        "records": records,
    }
    return result


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------
class RunbookEngine:
    """Full runbook engine supporting v2 YAML with conditionals, loops, etc."""

    # Known top-level keys (anything else triggers a warning, not an error)
    KNOWN_TOP_KEYS = {"name", "description", "version", "vars", "preflight",
                      "steps", "postflight", "steps_order", "target_required"}

    # Allowed step types
    STEP_TYPES = {"tool", "parallel", "sequential", "prompt", "conditional",
                  "foreach", "log", "notify", "set", "wait", "runbook", "report",
                  "dns", "burp"}

    def __init__(self, runbook_dir: Optional[Path] = None):
        self.runbook_dir = Path(runbook_dir or PLAYBOOKS_DIR)
        self.runbook_dir.mkdir(parents=True, exist_ok=True)

    def list_runbooks(self) -> List[Path]:
        return sorted(self.runbook_dir.glob("*.yaml")) + sorted(
            self.runbook_dir.glob("*.yml")
        )

    def validate_all(self) -> List[dict]:
        """Validate every runbook in the directory. Returns list of {file, errors}."""
        if yaml is None:
            return [{"file": "*", "errors": ["PyYAML not installed: pip install pyyaml"]}]
        results = []
        for f in self.list_runbooks():
            try:
                data = yaml.safe_load(f.read_text()) or {}
                errs = self.validate(data, filename=f.name)
            except Exception as e:
                errs = [f"Load error: {e}"]
            results.append({"file": f.name, "errors": errs})
        return results

    @staticmethod
    def validate(data: dict, filename: str = "") -> List[str]:
        """Validate runbook YAML structure. Returns list of error strings."""
        errors = []

        if not isinstance(data, dict):
            errors.append(f"Top-level structure must be a dict, got {type(data).__name__}")
            return errors

        unknown = [k for k in data if k not in RunbookEngine.KNOWN_TOP_KEYS]
        if unknown:
            errors.append(f"Unknown top-level keys: {', '.join(unknown)}")

        RunbookEngine._validate_steps(data.get("preflight", []), errors, "preflight", filename)
        RunbookEngine._validate_steps(data.get("steps", []), errors, "steps", filename)
        RunbookEngine._validate_steps(data.get("postflight", []), errors, "postflight", filename)

        if not data.get("steps"):
            errors.append("'steps' list is empty or missing")

        return errors

    @staticmethod
    def _validate_steps(steps: list, errors: List[str], context: str, filename: str):
        if not isinstance(steps, list):
            errors.append(f"{context}: expected a list, got {type(steps).__name__}")
            return

        for i, step in enumerate(steps):
            prefix = f"[{filename}] {context}[{i}]"
            RunbookEngine._validate_step(step, errors, prefix)

    @staticmethod
    def _validate_step(step, errors: List[str], prefix: str):
        if not isinstance(step, dict):
            errors.append(f"{prefix}: expected a dict, got {type(step).__name__} ('{step}')")
            return

        step_id = step.get("id", step.get("name", f"<index>"))

        # Must have at least one meaningful field
        has_content = bool(step.get("id") or step.get("name") or
                          step.get("tool") or step.get("type") or
                          step.get("message"))
        if not has_content:
            errors.append(f"{prefix}: step has no id, name, tool, type, or message")

        # Check type validity
        step_type = step.get("type", "tool")
        if step_type not in RunbookEngine.STEP_TYPES:
            errors.append(f"{prefix}/{step_id}: unknown type '{step_type}'")

        # 'parallel' / 'sequential' must have nested 'steps' list
        if step_type in ("parallel", "sequential"):
            nested = step.get("steps")
            if nested is None:
                errors.append(f"{prefix}/{step_id}: type '{step_type}' missing 'steps' list")
            elif not isinstance(nested, list):
                errors.append(f"{prefix}/{step_id}: 'steps' must be a list, got {type(nested).__name__}")
            else:
                for j, child in enumerate(nested):
                    RunbookEngine._validate_step(child, errors, f"{prefix}/{step_id}.steps[{j}]")

        # 'prompt' must have 'message', and 'then'/'else' must be lists
        if step_type == "prompt":
            if not step.get("message"):
                errors.append(f"{prefix}/{step_id}: prompt step missing 'message'")
            for key in ("then", "else"):
                val = step.get(key)
                if val is not None:
                    if isinstance(val, dict):
                        # Common mistake: {then: {steps: [...]}} instead of {then: [...]}
                        if "steps" in val:
                            errors.append(
                                f"{prefix}/{step_id}: '{key}' contains a 'steps' wrapper dict; "
                                f"use a list directly, not '{{steps: [...]}}'"
                            )
                        else:
                            errors.append(
                                f"{prefix}/{step_id}: '{key}' must be a list of steps, "
                                f"got a dict with keys: {', '.join(val.keys())}"
                            )
                    elif not isinstance(val, list):
                        errors.append(
                            f"{prefix}/{step_id}: '{key}' must be a list, "
                            f"got {type(val).__name__}"
                        )
                    else:
                        for j, child in enumerate(val):
                            RunbookEngine._validate_step(child, errors,
                                                         f"{prefix}/{step_id}.{key}[{j}]")

        # 'conditional' must have 'condition' key
        if step_type == "conditional":
            if step.get("condition") is None:
                errors.append(f"{prefix}/{step_id}: conditional step missing 'condition'")

        # 'foreach' must have 'items' key
        if step_type == "foreach":
            if step.get("items") is None:
                errors.append(f"{prefix}/{step_id}: foreach step missing 'items'")

        # 'tool' must have 'tool' key
        if step_type == "tool" and not step.get("tool"):
            errors.append(f"{prefix}/{step_id}: tool step missing 'tool' field")

        # 'when' should be a string, bool, or dict (dict = compound condition)
        when = step.get("when")
        if when is not None and not isinstance(when, (str, bool, dict)):
            errors.append(f"{prefix}/{step_id}: 'when' should be string/bool/dict, "
                          f"got {type(when).__name__}")

        # 'timeout' should be numeric
        timeout = step.get("timeout")
        if timeout is not None and not isinstance(timeout, (int, float)):
            errors.append(f"{prefix}/{step_id}: 'timeout' should be a number, "
                          f"got {type(timeout).__name__}")

    def load(self, name_or_path: str, validate: bool = True) -> dict:
        if yaml is None:
            raise RunbookError("PyYAML required: pip install pyyaml")
        p = Path(name_or_path)
        if not p.exists():
            p = self.runbook_dir / name_or_path
            if not p.exists():
                p = self.runbook_dir / f"{name_or_path}.yaml"
                if not p.exists():
                    p = self.runbook_dir / f"{name_or_path}.yml"
        if not p.exists():
            raise RunbookError(f"Runbook not found: {name_or_path}")
        data = yaml.safe_load(p.read_text())
        if validate and isinstance(data, dict):
            errs = self.validate(data, filename=p.name)
            if errs:
                raise RunbookError(
                    f"Runbook validation failed ({len(errs)} error(s)):\n  " +
                    "\n  ".join(errs)
                )
        return data

    def _save_log(self, ctx: RunContext, data: dict, results: list):
        """Write current runbook state to runbook-log.json."""
        run_log = {
            "runbook": data.get("name", "unnamed"),
            "case_id": ctx.case_id,
            "start": ctx.log[0]["ts"] if ctx.log else "",
            "end": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "steps": len(results) if results else 0,
            "artifacts": [str(a) for a in ctx.artifacts],
            "step_outputs": {k: {"rc": v.get("rc"), "error": v.get("error"),
                                "stdout": (v.get("stdout") or "")[-2000:],
                                "stderr": (v.get("stderr") or "")[-2000:],
                                "skipped": v.get("skipped", False),
                                "type": v.get("type", "")}
                             for k, v in ctx.step_outputs.items()},
        }
        ctx.case_dir.mkdir(parents=True, exist_ok=True)
        (ctx.case_dir / "runbook-log.json").write_text(
            json.dumps(run_log, indent=2, default=str)
        )

    def run(self, data: dict, ctx: Optional[RunContext] = None,
            verbose: bool = False) -> List[dict]:
        if ctx is None:
            ctx = RunContext("", [], "", {})

        # Apply runbook-level vars
        for k, v in (data.get("vars", {}) or {}).items():
            ctx.vars.setdefault(k, v)

        # Create case directory
        ctx.case_dir.mkdir(parents=True, exist_ok=True)

        # Preflight
        for step in data.get("preflight", []):
            self._run_step(step, ctx, verbose)

        # Main steps (save after each step for live dashboard updates)
        results = []
        for step in data.get("steps", []):
            r = self._run_step(step, ctx, verbose)
            if isinstance(r, list):
                results.extend(r)
            else:
                results.append(r)
            self._save_log(ctx, data, results)

        # Postflight
        for step in data.get("postflight", []):
            self._run_step(step, ctx, verbose)

        # Final save
        self._save_log(ctx, data, results)

        # Write minimal case.json so the case is accessible from the dashboard
        case_json = ctx.case_dir / "case.json"
        if not case_json.exists():
            import calendar
            now = datetime.datetime.now(datetime.timezone.utc)
            case_json.write_text(json.dumps({
                "case_id": ctx.case_id,
                "client": "",
                "type": "pentest",
                "description": f"Runbook: {data.get('name', ctx.runbook_path)}",
                "goals": [],
                "status": "open",
                "created": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "modified": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "evidence": [],
                "notes": [],
                "scope": {"in_scope": ctx.targets, "out_of_scope": []},
                "_runbook": data.get("name", ctx.runbook_path),
                "_runbook_file": ctx.runbook_path,
            }, indent=2))

        return results

    def run_file(self, path: str, targets: List[str] = None,
                 case_id: str = "", vars_override: dict = None,
                 verbose: bool = False) -> List[dict]:
        data = self.load(path)
        ctx = RunContext(path, targets or [], case_id or "", vars_override or {})
        return self.run(data, ctx, verbose)

    @staticmethod
    def save_results(results: List[dict], path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(results, indent=2, default=str))

    def _run_steps(self, steps: list, ctx: RunContext,
                   verbose: bool) -> List[dict]:
        results = []
        prompt_skip = False
        for step in steps:
            # Check global skip-prompts
            if ctx.vars.get("_skip_prompts") and step.get("type") == "prompt":
                if verbose:
                    print(f"  Skipping prompt (global skip)")
                continue
            r = self._run_step(step, ctx, verbose)
            if isinstance(r, list):
                results.extend(r)
            else:
                results.append(r)
        return results

    def _run_step(self, step: dict, ctx: RunContext,
                  verbose: bool = False) -> Union[dict, List[dict]]:
        step_type = step.get("type", "tool")
        step_id = step.get("id", step.get("name", f"step_{len(ctx.log)}"))
        step_name = step.get("name", step_id)

        if verbose:
            print(f"  [{step_id}] {step_name}  ({step_type})")

        # Condition check for step-level when
        when = step.get("when", True)
        if not _eval_condition(when, ctx):
            if verbose:
                print(f"    skipped (condition not met)")
            return {"step_id": step_id, "skipped": True, "type": step_type}

        ctx.add_log({"step_id": step_id, "name": step_name, "type": step_type})

        # Wrapper that passes verbose to recursive calls
        _rs = functools.partial(self._run_step, verbose=verbose)

        try:
            if step_type == "tool":
                result = _exec_tool(step, ctx)
            elif step_type == "conditional":
                result = _exec_conditional(step, ctx, _rs)
            elif step_type == "foreach":
                result = _exec_foreach(step, ctx, _rs)
            elif step_type == "parallel":
                result = _exec_parallel(step, ctx, _rs)
            elif step_type == "prompt":
                result = _exec_prompt(step, ctx, _rs)
            elif step_type == "notify":
                result = _exec_notify(step, ctx)
            elif step_type == "set":
                result = _exec_set(step, ctx)
            elif step_type == "wait":
                result = _exec_wait(step, ctx)
            elif step_type == "runbook":
                result = _exec_runbook(step, ctx, self._run_step)
            elif step_type == "report":
                result = _exec_report(step, ctx)
            elif step_type == "log":
                result = _exec_log(step, ctx)
            elif step_type == "burp":
                result = _exec_burp(step, ctx)
            elif step_type == "dns":
                result = _exec_dns(step, ctx)
            else:
                result = {"error": f"Unknown step type: {step_type}"}

        except RunbookError as e:
            result = {"error": str(e)}
            print(f"  [!] {e}")
        except Exception as e:
            result = {"error": f"{type(e).__name__}: {e}"}
            if verbose:
                import traceback
                traceback.print_exc()

        if isinstance(result, dict):
            result["step_id"] = step_id
            with ctx._lock:
                ctx.step_outputs[step_id] = result

        # Print result status
        if isinstance(result, dict) and verbose:
            rc = result.get("rc")
            error = result.get("error")
            if error:
                print(f"    \u2717 {error[:120]}")
            elif rc is not None:
                print(f"    {'\u2713' if rc == 0 else '\u2717'} rc={rc}")
            else:
                print(f"    \u2713")

        return result


# ===========================================================================
# Backward-compatible alias
# ===========================================================================
PlaybookEngine = RunbookEngine