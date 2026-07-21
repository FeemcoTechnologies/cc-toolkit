"""CC Command Center — Web Dashboard

Flask web app providing terminal access, case management dashboards,
note editor, evidence upload, and one-click report generation.
Integrates JupyterLab and Caido via iframes.
"""

import base64
import datetime
import io
import json
import logging
import mimetypes
import os
import re
import secrets
import shlex
import time
import shutil
import sys
import subprocess
import traceback
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file, session, redirect

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.case_manager import CaseManager
from modules.config import CASES_DIR, load_config, BURP_API_URL, BURP_API_KEY, BURP_PROXY_URL
from modules.findings_db import FindingsDB
from modules.tag_refs import resolve as resolve_tag, search as search_tags
from modules.job_queue import get_job_manager, run_in_thread
try:
    from modules.ws_terminal import WSTerminalServer
    HAS_WS_TERMINAL = True
except ImportError:
    HAS_WS_TERMINAL = False
    WSTerminalServer = None  # type: ignore

app = Flask(__name__)
# Persistent secret key so sessions survive restarts
_SECRET_FILE = Path(__file__).with_name(".dashboard_secret")
if not _SECRET_FILE.exists():
    _SECRET_FILE.write_text(secrets.token_hex(32))
app.config["SECRET_KEY"] = os.environ.get("CC_DASHBOARD_SECRET", _SECRET_FILE.read_text().strip())

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
CC_DIR = Path(__file__).resolve().parent.parent
CASES_DIR.mkdir(parents=True, exist_ok=True)
CFG = load_config()

_ws_port = int(os.environ.get("CC_WS_PORT", 5001))
DASHBOARD_CONFIG = {
    "jupyter_url": CFG.get("jupyter_url", "http://127.0.0.1:8888"),
    "caido_url": CFG.get("caido_url", "http://127.0.0.1:8080"),
    "ai_tunnel_target": CFG.get("ai_tunnel_target", "127.0.0.1"),
    "listen_host": CFG.get("dashboard_host", "0.0.0.0"),
    "listen_port": CFG.get("dashboard_port", 5000),
    "debug": CFG.get("dashboard_debug", False),
    "ws_port": _ws_port,
    # Burp Suite Pro
    "burp_api_url": CFG.get("burp_api_url", BURP_API_URL),
    "burp_api_key": CFG.get("burp_api_key", BURP_API_KEY),
    "burp_proxy_url": CFG.get("burp_proxy_url", BURP_PROXY_URL),
}

API_KEY = CFG.get("dashboard_api_key", "")

# ---------------------------------------------------------------------------
# Case type icons & colors (used in templates)
# ---------------------------------------------------------------------------
CASE_TYPE_ICONS = {
    "pentest": "target",
    "pentest_web": "globe",
    "pentest_external": "server",
    "pentest_internal_ad": "users",
    "pentest_cloud": "cloud",
    "pentest_physical": "building",
    "ir": "shield",
    "forensics": "search",
    "osint": "eye",
}

CASE_TYPE_COLORS = {
    "pentest": "#6366f1",
    "pentest_web": "#22c55e",
    "pentest_external": "#f97316",
    "pentest_internal_ad": "#a855f7",
    "pentest_cloud": "#06b6d4",
    "pentest_physical": "#eab308",
    "ir": "#dc2626",
    "forensics": "#10b981",
    "osint": "#6366f1",
}

# ---------------------------------------------------------------------------
# Debug logging ring buffer + file log
# ---------------------------------------------------------------------------
DEBUG_LOG = []  # ring buffer of (timestamp, level, message) tuples
DEBUG_LOG_MAX = 500

_log_dir = CC_DIR / "data" / "logs"
_log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(str(_log_dir / "dashboard.log"), encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
_logger = logging.getLogger("cc_dashboard")


def log_debug(level: str, msg: str):
    """Log to file + ring buffer for /api/debug/log."""
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    DEBUG_LOG.append((ts, level, msg))
    if len(DEBUG_LOG) > DEBUG_LOG_MAX:
        DEBUG_LOG[:] = DEBUG_LOG[-DEBUG_LOG_MAX:]
    getattr(_logger, level.lower(), _logger.info)("%s", msg)


# ---------------------------------------------------------------------------
# Optional API key auth
# ---------------------------------------------------------------------------
def _check_auth():
    """Check API key header OR session CSRF token (header or JSON body)."""
    if not API_KEY:
        return True
    key = request.headers.get("X-API-Key", "")
    if key == API_KEY:
        return True
    csrf_hdr = request.headers.get("X-CSRF-Token", "")
    sess_token = session.get("_csrf_token", "")
    log_debug("AUTH", f"key={key!r} csrf_hdr={csrf_hdr[:16]!r} sess={sess_token[:16]!r}")
    if csrf_hdr and csrf_hdr == sess_token:
        return True
    body = request.get_json(silent=True) or {}
    body_token = body.get("csrf_token", "")
    log_debug("AUTH", f"body_token={body_token[:16]!r} sess={sess_token[:16]!r}")
    if body_token and body_token == sess_token:
        return True
    return False

def require_api_key(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not _check_auth():
            return jsonify({"error": "Unauthorized"}), 401
        return f(*a, **kw)
    return wrapper

def require_api_key_html(f):
    """For HTML pages: redirect to home if no key (only when API_KEY is set)."""
    @wraps(f)
    def wrapper(*a, **kw):
        if not _check_auth():
            return render_template("error.html",
                                   message="Unauthorized — provide X-API-Key header"), 401
        return f(*a, **kw)
    return wrapper


# ---------------------------------------------------------------------------
# CSRF Protection
# ---------------------------------------------------------------------------
def generate_csrf_token():
    """Generate (or return existing) CSRF token for the current session."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

def csrf_required(f):
    """Decorator: require a valid CSRF token on POST/PUT/DELETE requests."""
    @wraps(f)
    def wrapper(*a, **kw):
        if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            # Exempt requests with valid API key header (already authenticated)
            api_key = request.headers.get('X-API-Key', '')
            if API_KEY and api_key == API_KEY:
                return f(*a, **kw)

            token = None
            # Check form data first (HTML forms — both urlencoded and multipart)
            if request.form:
                token = request.form.get('csrf_token')
            # Check JSON body
            elif request.is_json:
                token = request.json.get('csrf_token') if request.json else None
            # Check X-CSRF-Token header (AJAX)
            if not token:
                token = request.headers.get('X-CSRF-Token')
            # Check query param (fallback)
            if not token:
                token = request.args.get('csrf_token')

            if not token or token != session.get('_csrf_token', ''):
                log_debug("WARNING",
                    f"CSRF fail on {request.method} {request.path}: "
                    f"token={token!r}, session_token={session.get('_csrf_token', '')!r}, "
                    f"content_type={request.content_type}")
                if request.is_json or request.headers.get('Accept') == 'application/json':
                    return jsonify({'error': 'CSRF token missing or invalid'}), 403
                return render_template('error.html', message='CSRF token missing or invalid'), 403
        return f(*a, **kw)
    return wrapper

@app.context_processor
def inject_csrf_token():
    """Make csrf_token() available in all Jinja2 templates."""
    return dict(csrf_token=generate_csrf_token)
# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _run_cc_command(cmd_str: str) -> dict:
    """Run a `cc` CLI command and return structured result.
    If the first word is not a known cc subcommand, fall back to running
    it as an external system command."""
    _CC_SUBCOMMANDS = {
        "start", "stop", "monitor", "dashboard", "config", "doctor", "run",
        "route-scan", "wsgidav", "swaks", "watch", "prompts", "papermill",
        "wordlists", "recon", "web", "ad", "exploit", "wifi", "forensics",
        "case", "ir", "playbook", "report", "findings", "tools", "infra",
        "kerberos", "bloodhound", "nmap", "browser", "dns", "ref", "binary",
        "history", "flashcards",
    }
    try:
        parts = shlex.split(cmd_str)
        if parts and parts[0] not in _CC_SUBCOMMANDS and parts[0] not in ("cc", "python3", "python"):
            if not shutil.which(parts[0]):
                return {"rc": -1, "stdout": "", "stderr": f"Command not found: {parts[0]}"}
            r = subprocess.run(parts, capture_output=True, text=True, timeout=180)
            return {"rc": r.returncode, "stdout": r.stdout, "stderr": r.stderr}
        r = subprocess.run(
            [sys.executable, str(CC_DIR / "kali-command-center.py")] + parts,
            capture_output=True, text=True, timeout=120,
            cwd=str(CC_DIR),
        )
        return {"rc": r.returncode, "stdout": r.stdout, "stderr": r.stderr}
    except subprocess.TimeoutExpired:
        return {"rc": -1, "stdout": "", "stderr": "Command timed out"}
    except Exception as e:
        return {"rc": -1, "stdout": "", "stderr": str(e)}


# ---------------------------------------------------------------------------
# Global error handler — catch all unhandled exceptions and return JSON
# ---------------------------------------------------------------------------
@app.errorhandler(Exception)
def handle_uncaught_exception(e):
    """Catch any unhandled exception, log it, return JSON for API routes."""
    tb = traceback.format_exc()
    log_debug("ERROR", f"Unhandled {type(e).__name__}: {e}\n{tb}")
    if request.is_json or request.path.startswith("/api/"):
        return jsonify({"error": f"Internal error: {type(e).__name__}: {str(e)[:200]}"}), 500
    return render_template("error.html", message=f"Internal error: {type(e).__name__}"), 500


@app.errorhandler(404)
def handle_404(e):
    if request.is_json or request.path.startswith("/api/"):
        return jsonify({"error": "Not found"}), 404
    return render_template("error.html", message="Page not found"), 404


@app.errorhandler(405)
def handle_405(e):
    if request.is_json or request.path.startswith("/api/"):
        return jsonify({"error": "Method not allowed"}), 405
    return render_template("error.html", message="Method not allowed"), 405


@app.after_request
def after_request_logger(response):
    log_level = "WARNING" if 400 <= response.status_code < 500 else "ERROR" if response.status_code >= 500 else None
    if log_level:
        log_debug(log_level, f"{response.status_code} {request.method} {request.path}")
    return response


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
# Dashboard layout config path
DASHBOARD_LAYOUT_PATH = CC_DIR / "dashboard_layout.json"

_DEFAULT_DASHBOARD_WIDGETS = [
    {"id": "stats-bar", "enabled": True, "title": "Overview", "width": "full"},
    {"id": "severity-chart", "enabled": True, "title": "Findings by Severity", "width": "half"},
    {"id": "status-chart", "enabled": True, "title": "Findings by Status", "width": "half"},
    {"id": "recent-findings", "enabled": True, "title": "Recent Findings", "width": "full"},
    {"id": "case-overview", "enabled": True, "title": "Case Overview", "width": "full"},
    {"id": "top-cves", "enabled": True, "title": "Top CVEs", "width": "half"},
    {"id": "finding-trend", "enabled": False, "title": "Findings Over Time", "width": "half"},
    {"id": "recent-activity", "enabled": True, "title": "Recent Activity", "width": "half"},
    {"id": "recent-loot", "enabled": True, "title": "Recent Loot", "width": "half"},
]


def _load_dashboard_layout() -> list:
    if DASHBOARD_LAYOUT_PATH.exists():
        try:
            data = json.loads(DASHBOARD_LAYOUT_PATH.read_text())
            return data.get("widgets", list(_DEFAULT_DASHBOARD_WIDGETS))
        except Exception:
            pass
    return list(_DEFAULT_DASHBOARD_WIDGETS)


def _save_dashboard_layout(widgets: list):
    DASHBOARD_LAYOUT_PATH.write_text(json.dumps({"widgets": widgets}, indent=2))


@app.route("/")
@require_api_key_html
def index():
    cm = CaseManager()
    cases = cm.list_cases()
    for c in cases:
        ctype = c.get("type", "pentest")
        c["icon"] = CASE_TYPE_ICONS.get(ctype, "folder")
        c["color"] = CASE_TYPE_COLORS.get(ctype, "#6b7280")
    widget_layout = _load_dashboard_layout()
    return render_template("index.html", cases=cases,
                           config=DASHBOARD_CONFIG,
                           widget_layout=widget_layout)


@app.route("/case/<case_id>")
@require_api_key_html
def case_dashboard(case_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        info = None
    if not info:
        return render_template("error.html",
                               message=f"Case '{case_id}' not found"), 404
    ctype = info.get("type", "pentest")
    # ensure _findings_by_severity always exists
    if "_findings_by_severity" not in info:
        info["_findings_by_severity"] = {}
    return render_template("case_dashboard.html",
                           case=info,
                           icon=CASE_TYPE_ICONS.get(ctype, "folder"),
                           color=CASE_TYPE_COLORS.get(ctype, "#6b7280"),
                           config=DASHBOARD_CONFIG)


@app.route("/case/<case_id>/edit")
@require_api_key_html
def case_edit(case_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        info = None
    if not info:
        return render_template("error.html",
                               message=f"Case '{case_id}' not found"), 404
    return render_template("case_edit.html",
                           case=info,
                           config=DASHBOARD_CONFIG)


@app.route("/api/case/<case_id>/meta", methods=["POST"])
@require_api_key
@csrf_required
def api_case_meta_update(case_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    data = request.json or {}
    allowed = {"executive_summary", "key_observations", "recommendations", "status"}
    payload = {k: v for k, v in data.items() if k in allowed}
    if payload:
        cm.set_meta(case_id, **payload)
    return jsonify({"status": "ok"})


@app.route("/api/case/<case_id>/archive", methods=["POST"])
@require_api_key
@csrf_required
def api_case_archive(case_id: str):
    cm = CaseManager()
    try:
        result = cm.archive_case(case_id)
        return jsonify(result)
    except (FileNotFoundError, Exception) as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/case/<case_id>/unarchive", methods=["POST"])
@require_api_key
@csrf_required
def api_case_unarchive(case_id: str):
    cm = CaseManager()
    try:
        result = cm.unarchive_case(case_id)
        return jsonify(result)
    except (FileNotFoundError, FileExistsError, Exception) as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/case/<case_id>/archive", methods=["DELETE"])
@require_api_key
@csrf_required
def api_case_delete_archive(case_id: str):
    cm = CaseManager()
    try:
        result = cm.delete_archive(case_id)
        return jsonify(result)
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404


@app.route("/api/case/<case_id>", methods=["DELETE"])
@require_api_key
@csrf_required
def api_case_delete(case_id: str):
    cm = CaseManager()
    if not cm.delete(case_id):
        return jsonify({"error": "Case not found"}), 404
    return jsonify({"status": "deleted", "case_id": case_id})


@app.route("/api/archives")
@require_api_key
def api_archives():
    cm = CaseManager()
    return jsonify(cm.list_archives())


@app.route("/api/case/<case_id>/strengths/add", methods=["POST"])
@require_api_key
@csrf_required
def api_case_strength_add(case_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    text = (request.json or {}).get("text", "")
    if not text.strip():
        return jsonify({"error": "Text required"}), 400
    cm.add_strength(case_id, text.strip())
    return jsonify({"status": "ok"})


@app.route("/api/case/<case_id>/strengths/remove", methods=["POST"])
@require_api_key
@csrf_required
def api_case_strength_remove(case_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    index = (request.json or {}).get("index", -1)
    cm.remove_strength(case_id, index=index)
    return jsonify({"status": "ok"})


@app.route("/api/case/<case_id>/weaknesses/add", methods=["POST"])
@require_api_key
@csrf_required
def api_case_weakness_add(case_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    text = (request.json or {}).get("text", "")
    if not text.strip():
        return jsonify({"error": "Text required"}), 400
    cm.add_weakness(case_id, text.strip())
    return jsonify({"status": "ok"})


@app.route("/api/case/<case_id>/weaknesses/remove", methods=["POST"])
@require_api_key
@csrf_required
def api_case_weakness_remove(case_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    index = (request.json or {}).get("index", -1)
    cm.remove_weakness(case_id, index=index)
    return jsonify({"status": "ok"})


# ---------------------------------------------------------------------------
# Scope management API
# ---------------------------------------------------------------------------

@app.route("/api/case/<case_id>/scope/add", methods=["POST"])
@require_api_key
@csrf_required
def api_case_scope_add(case_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    target = (request.json or {}).get("target", "").strip()
    if not target:
        return jsonify({"error": "Target required"}), 400
    in_scope = (request.json or {}).get("in_scope", True)
    cm.scope_add(case_id, target, in_scope=in_scope)
    return jsonify({"status": "ok"})


@app.route("/api/case/<case_id>/scope/remove", methods=["POST"])
@require_api_key
@csrf_required
def api_case_scope_remove(case_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    target = (request.json or {}).get("target", "").strip()
    if not target:
        return jsonify({"error": "Target required"}), 400
    cm.scope_remove(case_id, target)
    return jsonify({"status": "ok"})


@app.route("/api/case/<case_id>/scope/list")
@require_api_key
def api_case_scope_list(case_id: str):
    cm = CaseManager()
    return jsonify(cm.scope_list(case_id))


@app.route("/api/case/<case_id>/scope/check")
@require_api_key
def api_case_scope_check(case_id: str):
    cm = CaseManager()
    target = request.args.get("target", "").strip()
    if not target:
        return jsonify({"error": "Target required"}), 400
    return jsonify(cm.scope_check(case_id, target))


# ---------------------------------------------------------------------------
# Scan API — run nmap from web UI
# ---------------------------------------------------------------------------

@app.route("/api/case/<case_id>/scan/nmap", methods=["POST"])
@require_api_key
@csrf_required
def api_case_scan_nmap(case_id: str):
    """Run an nmap scan subcommand for this case. Results go to case scans/ + evidence."""
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    data = request.json or {}
    subcommand = data.get("subcommand", "")
    target = data.get("target", "")
    ports = data.get("ports", "")
    timeout = int(data.get("timeout", 7200))
    VALID = ["init-tcp", "init-udp", "full-tcp", "full-ack",
             "service-version", "versions-tcp", "versions-udp",
             "vuln", "pipeline", "parse", "custom"]
    if subcommand not in VALID:
        return jsonify({"error": f"Unknown subcommand '{subcommand}'. Valid: {', '.join(VALID)}"}), 400
    if not target:
        return jsonify({"error": "target required"}), 400
    import subprocess, sys, json as _json
    from pathlib import Path as _Path
    script = str(_Path(__file__).resolve().parent.parent / "kali-command-center.py")
    cmd = [
        sys.executable or "python3", script, "nmap",
        subcommand,
        "--target", target,
        "--case-id", case_id,
    ]
    if ports:
        cmd.extend(["--ports", ports])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = r.stdout[-3000:] if len(r.stdout) > 3000 else r.stdout
        err = r.stderr[-500:] if r.stderr else ""
        refreshed = cm.info(case_id)
        return jsonify({
            "status": "ok" if r.returncode == 0 else "error",
            "exit_code": r.returncode,
            "output": output,
            "stderr": err,
            "case_id": case_id,
            "evidence_count": len(refreshed.get("evidence", [])),
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": f"Scan timed out after {timeout}s"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Task API — manage case tasks
# ---------------------------------------------------------------------------

@app.route("/api/case/<case_id>/tasks/add", methods=["POST"])
@require_api_key
@csrf_required
def api_case_tasks_add(case_id: str):
    cm = CaseManager()
    data = request.json or {}
    desc = data.get("description", "").strip()
    priority = data.get("priority", "medium")
    if not desc:
        return jsonify({"error": "description required"}), 400
    task = cm.task_add(case_id, description=desc, priority=priority)
    if task:
        return jsonify({"status": "ok", "task": task})
    return jsonify({"error": "Case not found"}), 404


@app.route("/api/case/<case_id>/tasks/toggle/<task_id>", methods=["POST"])
@require_api_key
@csrf_required
def api_case_tasks_toggle(case_id: str, task_id: str):
    cm = CaseManager()
    tasks = cm.task_list(case_id, show_done=True)
    task = next((t for t in tasks if t.get("id") == task_id), None)
    if not task:
        return jsonify({"error": "Task not found"}), 404
    if task.get("done"):
        # Cannot un-done currently, re-add if needed
        return jsonify({"status": "already_done"})
    result = cm.task_done(case_id, task_id)
    if result:
        return jsonify({"status": "ok"})
    return jsonify({"error": "Failed"}), 500


@app.route("/api/case/<case_id>/tasks/delete/<task_id>", methods=["POST"])
@require_api_key
@csrf_required
def api_case_tasks_delete(case_id: str, task_id: str):
    cm = CaseManager()
    if cm.task_delete(case_id, task_id):
        return jsonify({"status": "ok"})
    return jsonify({"error": "Task not found"}), 404


# ---------------------------------------------------------------------------
# Case data
# ---------------------------------------------------------------------------

@app.route("/api/case/<case_id>/data")
@app.route("/case/<case_id>/data")
@require_api_key
def case_data(case_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        info = None
    if not info:
        return jsonify({"error": "Case not found"}), 404
    return jsonify(info)


@app.route("/api/cases")
@require_api_key
def api_cases():
    cm = CaseManager()
    return jsonify(cm.list_cases())


# ---------------------------------------------------------------------------
# Asset Inventory
# ---------------------------------------------------------------------------

_AT = None

def _get_at():
    global _AT
    if _AT is None:
        from modules.asset_tracker import AssetTracker
        _AT = AssetTracker()
    return _AT


@app.route("/assets")
@require_api_key_html
def assets_page():
    return render_template("assets.html", config=DASHBOARD_CONFIG)


# Customers
@app.route("/api/customers")
@require_api_key
def api_customers_list():
    return jsonify(_get_at().list_customers())


@app.route("/api/customers", methods=["POST"])
@require_api_key
@csrf_required
def api_customers_create():
    data = request.json or {}
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "name required"}), 400
    try:
        c = _get_at().create_customer(name, data.get("notes", ""))
        return jsonify(c), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 409


@app.route("/api/customers/<customer_id>", methods=["DELETE"])
@require_api_key
@csrf_required
def api_customers_delete(customer_id: str):
    try:
        _get_at().delete_customer(customer_id)
        return jsonify({"status": "deleted"})
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404


# Assets
@app.route("/api/assets")
@require_api_key
def api_assets_list():
    at = _get_at()
    return jsonify(at.list_assets(
        customer_id=request.args.get("customer_id", ""),
        kind=request.args.get("kind", ""),
        tag=request.args.get("tag", ""),
        search=request.args.get("search", ""),
    ))


@app.route("/api/assets", methods=["POST"])
@require_api_key
@csrf_required
def api_assets_create():
    data = request.json or {}
    required = {"kind", "address"}
    missing = required - set(data.keys())
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400
    try:
        a = _get_at().create_asset(
            customer_id=data.get("customer_id", ""),
            kind=data["kind"], address=data["address"],
            label=data.get("label", ""), fqdn=data.get("fqdn", ""),
            os=data.get("os", ""), tags=data.get("tags", []),
            source="manual", notes=data.get("notes", ""),
        )
        return jsonify(a), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/assets/<asset_id>", methods=["DELETE"])
@require_api_key
@csrf_required
def api_assets_delete(asset_id: str):
    try:
        _get_at().delete_asset(asset_id)
        return jsonify({"status": "deleted"})
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404


@app.route("/api/assets/stats")
@require_api_key
def api_assets_stats():
    return jsonify(_get_at().get_stats())


# Import Nmap XML
@app.route("/api/assets/import/nmap", methods=["POST"])
@require_api_key
@csrf_required
def api_assets_import_nmap():
    data = request.json or {}
    xml = data.get("xml", "")
    if not xml.strip():
        return jsonify({"error": "xml content required"}), 400
    try:
        result = _get_at().import_nmap_xml(
            xml, customer_id=data.get("customer_id", ""),
            case_id=data.get("case_id", ""),
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# Extract assets from case findings
@app.route("/api/case/<case_id>/assets/extract", methods=["POST"])
@require_api_key
@csrf_required
def api_case_assets_extract(case_id: str):
    cm = CaseManager()
    from modules.findings_db import FindingsDB
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    if not info:
        return jsonify({"error": "Case not found"}), 404
    db = FindingsDB(cm._case_path(case_id))
    findings = db.list()
    data = request.json or {}
    result = _get_at().extract_from_findings(
        findings, customer_id=data.get("customer_id", ""), case_id=case_id,
    )
    return jsonify(result)


# Credentials
@app.route("/api/credentials")
@require_api_key
def api_credentials_list():
    return jsonify(_get_at().list_credentials(
        asset_id=request.args.get("asset_id", ""),
    ))


@app.route("/api/credentials", methods=["POST"])
@require_api_key
@csrf_required
def api_credentials_create():
    data = request.json or {}
    missing = [k for k in ("asset_id", "kind", "username", "secret") if not data.get(k)]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400
    try:
        c = _get_at().add_credential(
            asset_id=data["asset_id"], kind=data["kind"],
            username=data["username"], secret=data["secret"],
            service=data.get("service", ""), url=data.get("url", ""),
            notes=data.get("notes", ""),
        )
        return jsonify(c), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/credentials/<cred_id>")
@require_api_key
def api_credentials_get(cred_id: str):
    decrypt = request.args.get("decrypt") == "1"
    c = _get_at().get_credential(cred_id, decrypt=decrypt)
    if not c:
        return jsonify({"error": "Credential not found"}), 404
    return jsonify(c)


@app.route("/api/credentials/<cred_id>", methods=["DELETE"])
@require_api_key
@csrf_required
def api_credentials_delete(cred_id: str):
    try:
        _get_at().delete_credential(cred_id)
        return jsonify({"status": "deleted"})
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404


# ---------------------------------------------------------------------------
# Network Topology
# ---------------------------------------------------------------------------

@app.route("/api/case/<case_id>/topology")
@require_api_key
def api_case_topology(case_id: str):
    """Parse nmap outputs in case scans/ dir and return structured topology data."""
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404

    hosts = []
    scans_dir = cm._case_path(case_id) / "scans"
    nmap_files = sorted(scans_dir.glob("*.nmap")) if scans_dir.exists() else []

    # Also check default nmap_scans/ directory
    default_scans = CC_DIR / "nmap_scans"
    if default_scans.exists():
        nmap_files += sorted(default_scans.glob("*.nmap"))

    seen_targets = set()

    for f in nmap_files:
        text = f.read_text(errors="ignore")
        # Extract target IP from filename or content
        target = f.stem.replace("-scan", "").replace(".nmap", "")
        # Try to find actual IP in file
        ip_match = re.search(r"Nmap scan report for ([\d.]+)", text)
        if ip_match:
            target = ip_match.group(1)
        if target in seen_targets:
            continue
        seen_targets.add(target)

        ports = []
        os_info = []
        vulns = []
        for m in re.finditer(r"^(\d+)/(tcp|udp)\s+open\s+(\S*)\s*(.*)$", text, re.MULTILINE):
            ports.append({
                "port": int(m.group(1)),
                "protocol": m.group(2),
                "service": m.group(3),
                "extra": m.group(4).strip(),
            })
        for m in re.finditer(r"OS details:\s*(.*)", text):
            os_info.append(m.group(1).strip())
        for m in re.finditer(r"\|([\w-]+):[\s\S]*?(?=^[^\s])", text, re.MULTILINE):
            sn = m.group(1).strip()
            if sn not in ("osclass", "fingerprint") and ("vuln" in sn.lower() or "VULNERABLE" in m.group(0)):
                vulns.append({"script": sn, "output": m.group(0)[:500]})

        hosts.append({
            "id": target,
            "label": target,
            "os": os_info[0] if os_info else "unknown",
            "ports": ports,
            "vulns": vulns,
            "port_count": len(ports),
        })

    # If no hosts found via nmap files, return empty
    if not hosts:
        return jsonify({
            "hosts": [],
            "services": [],
            "total_hosts": 0,
            "total_ports": 0,
            "message": "No scan data found. Run an nmap scan first."
        })

    # Collect unique service names
    all_services = sorted(set(p["service"] for h in hosts for p in h["ports"] if p["service"]))
    total_ports = sum(h["port_count"] for h in hosts)

    return jsonify({
        "hosts": hosts,
        "services": all_services,
        "total_hosts": len(hosts),
        "total_ports": total_ports,
    })


@app.route("/case/<case_id>/topology")
@require_api_key_html
def case_topology(case_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        info = None
    if not info:
        return render_template("error.html", message="Case not found"), 404
    return render_template("topology.html", case=info, config=DASHBOARD_CONFIG)


# ---------------------------------------------------------------------------
# Findings dashboard
# ---------------------------------------------------------------------------
@app.route("/api/findings/stats")
@require_api_key
def api_findings_stats():
    """Aggregated findings statistics across all cases."""
    cm = CaseManager()
    cases = cm.list_cases()
    all_findings = []
    severity_counts = {s: 0 for s in ["critical", "high", "medium", "low", "info"]}
    status_counts = {}
    cve_counts = {}
    cwe_counts = {}
    findings_by_case = {}

    for c in cases:
        cid = c.get("case_id", "")
        db = FindingsDB(cm._case_path(cid))
        findings = db.list()
        for f in findings:
            all_findings.append(f)
            sev = f.get("severity", "info")
            if sev in severity_counts:
                severity_counts[sev] += 1
            st = f.get("status", "unvalidated")
            status_counts[st] = status_counts.get(st, 0) + 1
            cve = f.get("cve", "").strip()
            if cve:
                cve_counts[cve] = cve_counts.get(cve, 0) + 1
            cwe = f.get("cwe", "").strip()
            if cwe:
                cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
        findings_by_case[cid] = len(findings)

    return jsonify({
        "total": len(all_findings),
        "severity_counts": dict(sorted(severity_counts.items(), key=lambda x: severity_counts[x[0]], reverse=True)),
        "status_counts": status_counts,
        "cve_counts": dict(sorted(cve_counts.items(), key=lambda x: -x[1])[:20]),
        "cwe_counts": dict(sorted(cwe_counts.items(), key=lambda x: -x[1])[:20]),
        "findings_by_case": dict(sorted(findings_by_case.items(), key=lambda x: -x[1])),
    })


@app.route("/api/findings/list")
@require_api_key
def api_findings_list():
    """All findings across all cases with case context. Supports ?case_id= filter."""
    cm = CaseManager()
    filter_case_id = request.args.get("case_id", "").strip()
    cases = cm.list_cases()
    results = []
    for c in cases:
        cid = c.get("case_id", "")
        if filter_case_id and cid != filter_case_id:
            continue
        ctitle = c.get("client", cid)
        try:
            db = FindingsDB(cm._case_path(cid))
            findings = db.list()
            for f in findings:
                f["_case_id"] = cid
                f["_case_title"] = ctitle
                results.append(f)
        except Exception as e:
            log_debug("ERROR", f"Failed to load findings for case {cid}: {e}")
    # Support optional ?severity=high&search=xxx query params
    sev_filter = request.args.get("severity", "")
    search = request.args.get("search", "").lower().strip()
    if sev_filter:
        results = [f for f in results if f.get("severity") == sev_filter]
    if search:
        results = [f for f in results if search in f.get("title","").lower()
                   or search in f.get("cve","").lower()
                   or search in f.get("description","").lower()
                   or search in f.get("id","").lower()]
    return jsonify(results)


@app.route("/api/case/<case_id>/findings/stats")
@require_api_key
def api_case_findings_stats(case_id: str):
    """Aggregated findings statistics for a single case."""
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    db = FindingsDB(cm._case_path(case_id))
    findings = db.list()
    severity_counts = {s: 0 for s in ["critical", "high", "medium", "low", "info"]}
    status_counts = {}
    cve_counts = {}
    for f in findings:
        sev = f.get("severity", "info")
        if sev in severity_counts:
            severity_counts[sev] += 1
        st = f.get("status", "unvalidated")
        status_counts[st] = status_counts.get(st, 0) + 1
        cve = f.get("cve", "").strip()
        if cve:
            cve_counts[cve] = cve_counts.get(cve, 0) + 1
    return jsonify({
        "total": len(findings),
        "severity_counts": severity_counts,
        "status_counts": status_counts,
        "cve_counts": dict(sorted(cve_counts.items(), key=lambda x: -x[1])[:10]),
    })


@app.route("/findings")
@require_api_key_html
def findings_page():
    return render_template("findings.html", config=DASHBOARD_CONFIG)


@app.route("/case/<case_id>/findings")
@require_api_key_html
def case_findings_page(case_id: str):
    """Show only findings for a specific case."""
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        info = {"case_id": case_id, "client": case_id, "type": "pentest"}
    return render_template("findings.html", case=info, config=DASHBOARD_CONFIG)


@app.route("/api/cases/create", methods=["POST"])
@require_api_key
@csrf_required
def api_case_create():
    data = request.json or {}
    case_id = data.get("case_id", "").strip()
    if not case_id:
        return jsonify({"error": "case_id required"}), 400
    client = data.get("client", "").strip()
    case_type = data.get("type", "pentest")
    description = data.get("description", "")
    goals = data.get("goals", [])
    cm = CaseManager()
    try:
        result = cm.create(case_id, client=client, case_type=case_type,
                           description=description, goals=goals)
        return jsonify(result), 201
    except (FileExistsError, ValueError) as e:
        return jsonify({"error": str(e)}), 409


@app.route("/api/case/<case_id>/goals")
@require_api_key
def api_case_goals(case_id: str):
    cm = CaseManager()
    return jsonify(cm.goal_list(case_id))


@app.route("/api/case/<case_id>/goals/add", methods=["POST"])
@require_api_key
@csrf_required
def api_case_goal_add(case_id: str):
    goal = (request.json or {}).get("goal", "")
    if not goal:
        return jsonify({"error": "Goal required"}), 400
    cm = CaseManager()
    r = cm.goal_add(case_id, goal)
    return jsonify(r or {"error": "Case not found"})


@app.route("/api/case/<case_id>/timeline")
@require_api_key
def api_ir_timeline(case_id: str):
    cm = CaseManager()
    return jsonify(cm.ir_timeline_list(case_id))


@app.route("/api/case/<case_id>/timeline/add", methods=["POST"])
@require_api_key
@csrf_required
def api_ir_timeline_add(case_id: str):
    data = request.json or {}
    cm = CaseManager()
    r = cm.ir_timeline_add(case_id, timestamp=data.get("timestamp", ""),
                            event=data.get("event", ""),
                            severity=data.get("severity", "info"),
                            source=data.get("source", ""))
    return jsonify(r or {"error": "Case not found"})


@app.route("/api/case/<case_id>/ttps")
@require_api_key
def api_ir_ttps(case_id: str):
    cm = CaseManager()
    return jsonify(cm.ir_ttp_list(case_id))


@app.route("/api/case/<case_id>/containment")
@require_api_key
def api_ir_containment(case_id: str):
    cm = CaseManager()
    return jsonify(cm.ir_containment_list(case_id))


@app.route("/api/cc", methods=["POST"])
@csrf_required
@require_api_key
def api_cc_command():
    cmd = (request.json or {}).get("command", "")
    if not cmd:
        return jsonify({"error": "Command required"}), 400
    result = _run_cc_command(cmd)
    return jsonify(result)


@app.route("/case/<case_id>/notes")
@require_api_key_html
def case_notes(case_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        info = None
    if not info:
        return render_template("error.html", message="Case not found"), 404
    return render_template("notes.html", case=info, config=DASHBOARD_CONFIG)


@app.route("/api/case/<case_id>/notes", methods=["GET", "POST"])
@require_api_key
@csrf_required
def api_notes(case_id: str):
    cm = CaseManager()
    if request.method == "POST":
        j = request.json or {}
        body = j.get("body", "")
        tags = j.get("tags", [])
        r = cm.add_note(case_id, body, tags)
        return jsonify(r or {"error": "Case not found"})
    return jsonify(cm.get_notes(case_id))


@app.route("/case/<case_id>/evidence")
@require_api_key_html
def case_evidence(case_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        info = None
    if not info:
        return render_template("error.html", message="Case not found"), 404
    return render_template("evidence.html", case=info, config=DASHBOARD_CONFIG)


@app.route("/api/case/<case_id>/evidence")
@require_api_key
def api_case_evidence(case_id: str):
    """Return evidence list for a case (reads only the manifest, not full case data)."""
    cm = CaseManager()
    return jsonify(cm.get_evidence(case_id))


@app.route("/api/case/<case_id>/evidence/upload", methods=["POST"])
@require_api_key
@csrf_required
def api_evidence_upload(case_id: str):
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    f = request.files["file"]
    category = request.form.get("category", "evidence")
    description = request.form.get("description", "")
    import tempfile
    temp_dir = Path(tempfile.gettempdir()) / "cc_uploads"
    temp_dir.mkdir(parents=True, exist_ok=True)
    safe_name = Path(f.filename).name
    if not safe_name:
        return jsonify({"error": "Invalid filename"}), 400
    blocked = {".exe", ".dll", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".msi", ".jar"}
    if Path(safe_name).suffix.lower() in blocked:
        return jsonify({"error": f"File type '{Path(safe_name).suffix}' not allowed"}), 400
    max_size = 100 * 1024 * 1024
    if request.content_length and request.content_length > max_size:
        return jsonify({"error": f"File too large ({request.content_length:,} bytes)"}), 400
    temp_path = temp_dir / safe_name
    if request.content_length is None:
        f.save(str(temp_path))
        if temp_path.stat().st_size > max_size:
            temp_path.unlink(missing_ok=True)
            return jsonify({"error": "File too large"}), 400
    else:
        f.save(str(temp_path))
    cm = CaseManager()
    rec = cm.add_evidence(case_id, str(temp_path), category, description)
    temp_path.unlink(missing_ok=True)
    return jsonify(rec or {"error": "Failed to add evidence"})


@app.route("/api/case/<case_id>/evidence/verify", methods=["POST"])
@require_api_key
@csrf_required
def api_evidence_verify(case_id: str):
    """Re-hash all evidence and report integrity status."""
    cm = CaseManager()
    try:
        results = cm.verify_evidence(case_id)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify(results)


@app.route("/api/case/<case_id>/evidence/delete", methods=["POST"])
@require_api_key
@csrf_required
def api_evidence_delete(case_id: str):
    """Delete an evidence record by filename."""
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    filename = (request.json or {}).get("filename", "").strip()
    if not filename:
        return jsonify({"error": "filename required"}), 400
    deleted = cm.delete_evidence(case_id, filename)
    if deleted:
        return jsonify({"status": "deleted", "filename": filename})
    return jsonify({"error": "Evidence not found"}), 404


# ---------------------------------------------------------------------------
# Case File Manager
# ---------------------------------------------------------------------------
CASE_DIR_ICONS = {
    "scans": "activity", "loot": "package", "evidence": "shield",
    "screenshots": "image", "reports": "file-text", "notes": "file",
    "wordlists": "type",
}

def _walk_case_dir(case_dir: Path, prefix: str = "") -> list:
    """Recursively list files in a case directory with type info."""
    entries = []
    for child in sorted(case_dir.iterdir()):
        if child.name.startswith("."):
            continue
        rel = f"{prefix}/{child.name}" if prefix else child.name
        if child.is_dir():
            entries.append({
                "name": child.name, "path": rel, "type": "dir",
                "icon": CASE_DIR_ICONS.get(child.name, "folder"),
                "size": 0,
                "children": _walk_case_dir(child, rel),
            })
        elif child.is_file():
            size = child.stat().st_size
            mime, _ = mimetypes.guess_type(str(child))
            entries.append({
                "name": child.name, "path": rel, "type": "file",
                "size": size, "mime": mime or "application/octet-stream",
                "ext": child.suffix.lower(),
            })
    return entries


@app.route("/case/<case_id>/files")
@require_api_key_html
def case_files(case_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        info = None
    if not info:
        return render_template("error.html", message="Case not found"), 404
    return render_template("files.html", case=info, config=DASHBOARD_CONFIG)


@app.route("/api/case/<case_id>/files/tree")
@require_api_key
def api_case_file_tree(case_id: str):
    """Return the full directory tree for a case."""
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    case_dir = cm._case_path(case_id)
    if not case_dir.exists():
        return jsonify({"tree": [], "message": "Case directory is empty"})
    tree = _walk_case_dir(case_dir)
    return jsonify({"tree": tree})


@app.route("/api/case/<case_id>/files/list")
@require_api_key
def api_case_file_list(case_id: str):
    """List files in a specific subdirectory of the case."""
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    sub = request.args.get("path", "")
    case_dir = cm._case_path(case_id)
    target = (case_dir / sub).resolve()
    if not str(target).startswith(str(case_dir.resolve()) + os.sep) and target != case_dir:
        return jsonify({"error": "Access denied"}), 403
    if not target.exists():
        return jsonify({"error": "Path not found"}), 404
    if target.is_file():
        return jsonify({"error": "Not a directory"}), 400
    entries = []
    for child in sorted(target.iterdir()):
        if child.name.startswith("."):
            continue
        rel = str(child.relative_to(case_dir)).replace("\\", "/")
        if child.is_dir():
            entries.append({
                "name": child.name, "path": rel, "type": "dir",
                "size": 0,
                "icon": CASE_DIR_ICONS.get(child.name, "folder"),
            })
        else:
            mime, _ = mimetypes.guess_type(str(child))
            entries.append({
                "name": child.name, "path": rel, "type": "file",
                "size": child.stat().st_size,
                "mime": mime or "application/octet-stream",
                "ext": child.suffix.lower(),
            })
    return jsonify({"path": sub, "entries": entries})


@app.route("/api/case/<case_id>/files/preview")
@require_api_key
def api_case_file_preview(case_id: str):
    """Preview a file's contents (text, image, or hex dump)."""
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    file_path = request.args.get("path", "")
    case_dir = cm._case_path(case_id)
    target = (case_dir / file_path).resolve()
    if not str(target).startswith(str(case_dir.resolve()) + os.sep):
        return jsonify({"error": "Access denied"}), 403
    if not target.exists() or not target.is_file():
        return jsonify({"error": "File not found"}), 404

    mime, _ = mimetypes.guess_type(str(target))
    size = target.stat().st_size
    ext = target.suffix.lower()
    text_exts = {".txt", ".md", ".log", ".xml", ".json", ".yml", ".yaml",
                 ".conf", ".cfg", ".ini", ".py", ".sh", ".bat", ".ps1",
                 ".html", ".csv", ".nmap", ".toml"}
    img_exts = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico"}

    if ext in img_exts:
        # Return base64 for inline display
        raw = target.read_bytes()
        b64 = base64.b64encode(raw).decode()
        return jsonify({
            "type": "image", "mime": mime or "image/png",
            "size": size, "name": target.name,
            "data": f"data:{mime or 'image/png'};base64,{b64}",
        })
    elif ext in text_exts or (mime and mime.startswith("text/")):
        text = target.read_text(encoding="utf-8", errors="replace")
        return jsonify({
            "type": "text", "mime": mime or "text/plain",
            "size": size, "name": target.name,
            "data": text[:100000],
            "truncated": len(text) > 100000,
        })
    else:
        # Hex dump first 4KB
        raw = target.read_bytes()
        hex_lines = []
        for i in range(0, min(len(raw), 4096), 16):
            chunk = raw[i:i+16]
            hex_str = " ".join(f"{b:02x}" for b in chunk[:8]) + "  " + " ".join(f"{b:02x}" for b in chunk[8:])
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            hex_lines.append(f"{i:08x}  {hex_str:<48}  {ascii_str}")
        return jsonify({
            "type": "hex", "mime": mime or "application/octet-stream",
            "size": size, "name": target.name,
            "data": "\n".join(hex_lines),
            "truncated": len(raw) > 4096,
        })


@app.route("/api/case/<case_id>/files/upload", methods=["POST"])
@require_api_key
@csrf_required
def api_case_file_upload(case_id: str):
    """Upload a file to a specific subdirectory within the case."""
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    sub = request.form.get("path", "")
    case_dir = cm._case_path(case_id)
    target_dir = (case_dir / sub).resolve()
    if not str(target_dir).startswith(str(case_dir.resolve()) + os.sep) and target_dir != case_dir:
        return jsonify({"error": "Access denied"}), 403
    target_dir.mkdir(parents=True, exist_ok=True)

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    f = request.files["file"]
    safe_name = Path(f.filename).name
    if not safe_name:
        return jsonify({"error": "Invalid filename"}), 400
    dest = target_dir / safe_name
    f.save(str(dest))
    return jsonify({"status": "ok", "path": str(dest.relative_to(case_dir)).replace("\\", "/"),
                    "size": dest.stat().st_size})


@app.route("/api/case/<case_id>/files/delete", methods=["POST"])
@require_api_key
@csrf_required
def api_case_file_delete(case_id: str):
    """Delete a file from the case directory (NOT evidence — use evidence API for that)."""
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    file_path = (request.json or {}).get("path", "")
    case_dir = cm._case_path(case_id)
    target = (case_dir / file_path).resolve()
    if not str(target).startswith(str(case_dir.resolve()) + os.sep):
        return jsonify({"error": "Access denied"}), 403
    if not target.exists():
        return jsonify({"error": "File not found"}), 404
    if target.is_dir():
        return jsonify({"error": "Cannot delete directories via this endpoint"}), 400
    target.unlink()
    return jsonify({"status": "deleted", "path": file_path})


# ---------------------------------------------------------------------------
# Kanban Board
# ---------------------------------------------------------------------------

@app.route("/case/<case_id>/board")
@require_api_key_html
def case_board(case_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        info = None
    if not info:
        return render_template("error.html", message="Case not found"), 404
    return render_template("board.html", case=info, config=DASHBOARD_CONFIG)


@app.route("/api/case/<case_id>/board/data")
@require_api_key
def api_case_board_data(case_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    db = FindingsDB(cm._case_path(case_id))
    findings = db.list()
    # Map old statuses to new statuses for backward compatibility
    STATUS_MAP = {
        "open": "unvalidated",
        "in_progress": "validated",
        "resolved": "remediated",
        "closed": "closed_other",
    }
    columns = {
        "unvalidated": {"title": "Unvalidated", "items": [], "color": "#6b7280"},
        "validated": {"title": "Validated", "items": [], "color": "#6366f1"},
        "remediated": {"title": "Remediated", "items": [], "color": "#22c55e"},
        "closed_other": {"title": "Closed (Other)", "items": [], "color": "#374151"},
    }
    for f in findings:
        status = f.get("status", "unvalidated")
        status = STATUS_MAP.get(status, status)
        if status not in columns:
            status = "unvalidated"
        columns[status]["items"].append(f)
    for col in columns.values():
        col["items"].sort(key=lambda x: x.get("severity", "info"))
    return jsonify({"columns": columns})


@app.route("/api/case/<case_id>/board/update", methods=["POST"])
@require_api_key
@csrf_required
def api_case_board_update(case_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    data = request.json or {}
    finding_id = data.get("finding_id", "")
    new_status = data.get("status", "")
    if not finding_id or not new_status:
        return jsonify({"error": "finding_id and status required"}), 400
    db = FindingsDB(cm._case_path(case_id))
    finding = db.get(finding_id)
    if not finding:
        return jsonify({"error": "Finding not found"}), 404
    db.update(finding_id, status=new_status)
    return jsonify({"status": "ok"})


# ---------------------------------------------------------------------------
# Project Board (case-level Kanban)
# ---------------------------------------------------------------------------

@app.route("/projects")
@require_api_key_html
def project_board():
    return render_template("project_board.html", config=DASHBOARD_CONFIG)


@app.route("/api/projects/board/data")
@require_api_key
def api_projects_board_data():
    cm = CaseManager()
    cases = cm.list_cases()
    FINDING_STATUS_MAP = {
        "open": "unvalidated", "in_progress": "validated",
        "resolved": "remediated", "closed": "closed_other",
    }
    CASE_COLORS = {
        "open": {"color": "#6b7280", "title": "Open"},
        "pending": {"color": "#eab308", "title": "Pending"},
        "on-hold": {"color": "#f97316", "title": "On Hold"},
        "closed": {"color": "#374151", "title": "Closed"},
    }
    columns = {}
    for key, val in CASE_COLORS.items():
        columns[key] = {**val, "items": []}

    for c in cases:
        cid = c.get("case_id", "")
        status = c.get("status", "open")
        if status not in columns:
            status = "open"
        try:
            db = FindingsDB(cm._case_path(cid))
            findings = db.list()
            mapped_findings = []
            for f in findings:
                fs = f.get("status", "unvalidated")
                fs = FINDING_STATUS_MAP.get(fs, fs)
                mapped_findings.append({**f, "status": fs})
            by_sev = {}
            for f in findings:
                s = f.get("severity", "info")
                by_sev[s] = by_sev.get(s, 0) + 1
            c["findings"] = mapped_findings
            c["finding_count"] = len(findings)
            c["findings_by_severity"] = by_sev
        except Exception:
            c["findings"] = []
            c["finding_count"] = 0
            c["findings_by_severity"] = {}
        columns[status]["items"].append(c)

    # Sort items within each column by created date descending
    for col in columns.values():
        col["items"].sort(key=lambda x: x.get("created", ""), reverse=True)
    return jsonify({"columns": columns})


@app.route("/api/projects/board/update", methods=["POST"])
@require_api_key
@csrf_required
def api_projects_board_update():
    data = request.json or {}
    case_id = data.get("case_id", "")
    new_status = data.get("status", "")
    if not case_id or not new_status:
        return jsonify({"error": "case_id and status required"}), 400
    cm = CaseManager()
    try:
        result = cm.set_meta(case_id, status=new_status)
    except Exception:
        return jsonify({"error": "Failed to update case status"}), 500
    if result is None:
        return jsonify({"error": "Case not found"}), 404
    return jsonify({"status": "ok"})


# ---------------------------------------------------------------------------
# Finding Create
# ---------------------------------------------------------------------------

@app.route("/api/case/<case_id>/finding/create", methods=["POST"])
@require_api_key
@csrf_required
def api_case_finding_create(case_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    data = request.json or {}
    title = data.get("title", "").strip()
    if not title:
        return jsonify({"error": "title required"}), 400
    db = FindingsDB(cm._case_path(case_id))
    tags = data.get("tags", [])
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    finding = db.add(
        title=title,
        severity=data.get("severity", "medium"),
        description=data.get("description", ""),
        remediation=data.get("remediation", ""),
        source=data.get("source", "manual"),
        cve=data.get("cve", ""),
        cwe=data.get("cwe", ""),
        impact=data.get("impact", ""),
        poc=data.get("poc", ""),
        cvss_score=data.get("cvss_score"),
        cvss_vector=data.get("cvss_vector", ""),
        tags=tags,
        affected_hosts=data.get("affected_hosts", ""),
    )
    # Override default status if provided
    new_status = data.get("status", "")
    if new_status and new_status != "unvalidated":
        db.update(finding["id"], status=new_status)
        finding["status"] = new_status
    return jsonify({"status": "ok", "finding": finding})


# ---------------------------------------------------------------------------
# Finding Detail
# ---------------------------------------------------------------------------

@app.route("/case/<case_id>/finding/<finding_id>")
@require_api_key_html
def case_finding_detail(case_id: str, finding_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        info = None
    if not info:
        return render_template("error.html", message="Case not found"), 404
    db = FindingsDB(cm._case_path(case_id))
    finding = db.get(finding_id)
    if not finding:
        return render_template("error.html",
                               message=f"Finding '{finding_id}' not found"), 404
    return render_template("finding_detail.html",
                           case=info, finding=finding,
                           config=DASHBOARD_CONFIG)


@app.route("/api/case/<case_id>/finding/<finding_id>")
@require_api_key
def api_case_finding_detail(case_id: str, finding_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    db = FindingsDB(cm._case_path(case_id))
    finding = db.get(finding_id)
    if not finding:
        return jsonify({"error": "Finding not found"}), 404
    return jsonify(finding)


@app.route("/api/case/<case_id>/finding/<finding_id>/update",
           methods=["POST"])
@csrf_required
@require_api_key
def api_case_finding_update(case_id: str, finding_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    data = request.json or {}
    db = FindingsDB(cm._case_path(case_id))
    finding = db.get(finding_id)
    if not finding:
        return jsonify({"error": "Finding not found"}), 404
    allowed = {"title", "severity", "status", "description", "remediation",
               "impact", "poc", "source", "cve", "cwe", "references",
               "cvss_score", "cvss_vector", "tags", "affected_hosts",
               "command_output", "evidence_refs"}
    kwargs = {k: v for k, v in data.items() if k in allowed}
    log_debug("INFO", f"Updating finding {case_id}/{finding_id}: {kwargs}")
    db.update(finding_id, **kwargs)
    return jsonify({"status": "ok"})


@app.route("/api/case/<case_id>/finding/<finding_id>/tags/add",
           methods=["POST"])
@require_api_key
@csrf_required
def api_case_finding_tag_add(case_id: str, finding_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    tag = (request.json or {}).get("tag", "").strip()
    if not tag:
        return jsonify({"error": "tag required"}), 400
    db = FindingsDB(cm._case_path(case_id))
    f = db.add_tag(finding_id, tag)
    if not f:
        return jsonify({"error": "Finding not found"}), 404
    return jsonify({"status": "ok", "finding": f})


@app.route("/api/case/<case_id>/finding/<finding_id>/tags/remove",
           methods=["POST"])
@require_api_key
@csrf_required
def api_case_finding_tag_remove(case_id: str, finding_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    tag = (request.json or {}).get("tag", "").strip()
    if not tag:
        return jsonify({"error": "tag required"}), 400
    db = FindingsDB(cm._case_path(case_id))
    f = db.remove_tag(finding_id, tag)
    if not f:
        return jsonify({"error": "Finding not found"}), 404
    return jsonify({"status": "ok", "finding": f})


@app.route("/api/case/<case_id>/tags")
@require_api_key
def api_case_tags(case_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    db = FindingsDB(cm._case_path(case_id))
    return jsonify(db.tags())


@app.route("/api/tags/search")
@require_api_key
def api_tags_search():
    q = request.args.get("q", "").strip()
    namespace = request.args.get("namespace", "").strip()
    if not q:
        return jsonify([])
    results = search_tags(q, namespace)
    return jsonify(results)


@app.route("/api/tags/resolve")
@require_api_key
def api_tags_resolve():
    tag = request.args.get("tag", "").strip()
    if not tag:
        return jsonify({"error": "tag required"}), 400
    return jsonify(resolve_tag(tag))


@app.route("/api/case/<case_id>/finding/<finding_id>/delete",
           methods=["POST"])
@require_api_key
@csrf_required
def api_case_finding_delete(case_id: str, finding_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    db = FindingsDB(cm._case_path(case_id))
    if db.delete(finding_id):
        return jsonify({"status": "deleted"})
    return jsonify({"error": "Finding not found"}), 404


@app.route("/api/findings/bulk-update", methods=["POST"])
@require_api_key
@csrf_required
def api_findings_bulk_update():
    """Bulk update findings across cases.
    Body: {"findings": [{"case_id": "...", "finding_id": "..."}], "changes": {"status": "remediated"}}
    """
    data = request.json or {}
    findings_list = data.get("findings", [])
    changes = data.get("changes", {})
    log_debug("INFO", f"Bulk update {len(findings_list)} findings: changes={changes}")
    cm = CaseManager()
    updated = 0
    errors = []
    for item in findings_list:
        cid = item.get("case_id", "")
        fid = item.get("finding_id", "")
        if not cid or not fid:
            errors.append({"finding_id": fid, "error": "Missing case_id or finding_id"})
            continue
        try:
            db = FindingsDB(cm._case_path(cid))
            result = db.update(fid, **changes)
            if result:
                updated += 1
            else:
                errors.append({"finding_id": fid, "case_id": cid, "error": "Not found"})
        except Exception as e:
            errors.append({"finding_id": fid, "case_id": cid, "error": str(e)})
    log_debug("INFO", f"Bulk update result: updated={updated}, errors={len(errors)}")
    return jsonify({"status": "ok", "updated": updated, "errors": errors})


@app.route("/api/findings/bulk-delete", methods=["POST"])
@require_api_key
@csrf_required
def api_findings_bulk_delete():
    """Bulk delete findings across cases.
    Body: {"findings": [{"case_id": "...", "finding_id": "..."}]}
    """
    data = request.json or {}
    findings_list = data.get("findings", [])
    log_debug("INFO", f"Bulk delete {len(findings_list)} findings")
    cm = CaseManager()
    deleted = 0
    errors = []
    for item in findings_list:
        cid = item.get("case_id", "")
        fid = item.get("finding_id", "")
        if not cid or not fid:
            errors.append({"finding_id": fid, "error": "Missing case_id or finding_id"})
            continue
        try:
            db = FindingsDB(cm._case_path(cid))
            if db.delete(fid):
                deleted += 1
            else:
                errors.append({"finding_id": fid, "case_id": cid, "error": "Not found"})
        except Exception as e:
            errors.append({"finding_id": fid, "case_id": cid, "error": str(e)})
    log_debug("INFO", f"Bulk delete result: deleted={deleted}, errors={len(errors)}")
    return jsonify({"status": "ok", "deleted": deleted, "errors": errors})


# ---------------------------------------------------------------------------
# Gantt / Timeline View
# ---------------------------------------------------------------------------

@app.route("/case/<case_id>/gantt")
@require_api_key_html
def case_gantt(case_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        info = None
    if not info:
        return render_template("error.html", message="Case not found"), 404
    return render_template("gantt.html", case=info, config=DASHBOARD_CONFIG)


@app.route("/api/case/<case_id>/gantt/data")
@require_api_key
def api_case_gantt_data(case_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    # Gather timeline + findings for Gantt
    timeline = info.get("ir_timeline", info.get("timeline", []))
    tasks = info.get("tasks", [])
    db = FindingsDB(cm._case_path(case_id))
    findings = db.list()

    items = []
    # Timeline events as Gantt items
    for ev in (timeline or []):
        ts = ev.get("timestamp", "")
        items.append({
            "id": "evt-" + str(len(items)),
            "type": "event",
            "title": ev.get("event", "Event")[:60],
            "start": ts[:10] if ts else "",
            "end": "",
            "severity": ev.get("severity", "info"),
            "source": ev.get("source", ""),
        })
    # Findings as Gantt items
    for f in (findings or []):
        created = f.get("created", "")[:10]
        items.append({
            "id": "fnd-" + (f.get("id", "")),
            "type": "finding",
            "title": f.get("title", "Finding")[:60],
            "start": created,
            "end": "",
            "severity": f.get("severity", "info"),
            "status": f.get("status", "unvalidated"),
            "cve": f.get("cve", ""),
        })
    # Tasks
    for t in (tasks or []):
        items.append({
            "id": "task-" + str(len(items)),
            "type": "task",
            "title": (t.get("description", t.get("title", "Task")))[:60],
            "start": t.get("created", "")[:10],
            "end": t.get("completed", "")[:10] if t.get("completed") else "",
            "status": t.get("status", "pending"),
        })
    return jsonify({"items": items})


# ---------------------------------------------------------------------------
# Runbook Editor
# ---------------------------------------------------------------------------

@app.route("/case/<case_id>/runbook")
@require_api_key_html
def case_runbook(case_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        info = None
    if not info:
        return render_template("error.html", message="Case not found"), 404
    return render_template("runbook_editor.html", case=info, config=DASHBOARD_CONFIG)

# Legacy redirect
@app.route("/case/<case_id>/playbook")
def case_playbook_redirect(case_id: str):
    return redirect(f"/case/{case_id}/runbook")


@app.route("/api/case/<case_id>/runbook", methods=["GET", "POST", "PUT"])
@require_api_key
@csrf_required
def api_case_runbook(case_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    runbook_path = cm._case_path(case_id) / "playbook.json"  # keep storage filename for compat
    if request.method == "GET":
        if runbook_path.exists():
            return jsonify(json.loads(runbook_path.read_text()))
        return jsonify({"steps": []})
    data = request.json or {}
    if request.method in ("POST", "PUT"):
        runbook_path.write_text(json.dumps(data, indent=2, default=str))
        return jsonify({"status": "saved", "steps": len(data.get("steps", []))})

    return jsonify({"error": "Method not allowed"}), 405


@app.route("/api/case/<case_id>/runbook/run", methods=["POST"])
@require_api_key
@csrf_required
def api_case_runbook_run(case_id: str):
    """Run this case's runbook steps against a target using RunbookEngine."""
    from modules.playbook_engine import RunbookEngine, RunContext
    from modules.case_manager import CaseManager
    import json as _json, shlex

    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404

    runbook_path = cm._case_path(case_id) / "playbook.json"
    if not runbook_path.exists():
        return jsonify({"error": "No runbook defined for this case"}), 400
    runbook_data = _json.loads(runbook_path.read_text())
    steps = runbook_data.get("steps", [])
    if not steps:
        return jsonify({"error": "Runbook has no steps"}), 400

    data = request.json or {}
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "Target required"}), 400

    targets = [target]
    job_id = _jm.create("runbook", f"Runbook for {case_id} against {target}",
                         total_steps=len(steps) + 2)
    prog = _make_job_progress("", job_id)

    def _run(*, _progress=None):
        try:
            from modules.playbook_engine import RunbookEngine
            from modules.constants import PLAYBOOKS_DIR
            if _progress:
                _progress(current_step=1, message="Building runbook...")

            runbook_steps = []
            for i, s in enumerate(steps):
                tool = (s.get("tool") or "").strip()
                target_str = (s.get("target") or "{target}").strip()
                try:
                    args = shlex.split(target_str)
                except Exception:
                    args = [target_str]
                step = {
                    "id": f"step_{i}",
                    "name": s.get("name", f"Step {i+1}"),
                    "tool": tool,
                    "args": args,
                    "timeout": s.get("timeout", 300),
                    "retries": s.get("retries", 0),
                }
                desc = (s.get("description") or "").strip()
                if desc:
                    step["description"] = desc
                runbook_steps.append(step)

            runbook_data_inner = {
                "name": f"Case Runbook - {case_id}",
                "description": f"Runbook execution for {case_id} against {target}",
                "steps": runbook_steps,
            }

            if _progress:
                _progress(current_step=2, message=f"Running {len(steps)} steps...")

            engine = RunbookEngine(PLAYBOOKS_DIR)
            ctx = RunContext("case-runbook", targets, case_id, {})
            results = engine.run(runbook_data_inner, ctx, verbose=False)

            if _progress:
                _progress(current_step=len(steps) + 1, message="Saving results...")

            runlog_path = cm._case_path(case_id) / "runbook-log.json"
            if runlog_path.exists():
                runlog = _json.loads(runlog_path.read_text())
                step_outs = runlog.get("step_outputs", {})
                note_lines = [f"## Runbook Execution Results"]
                for sid, out in step_outs.items():
                    rc = out.get("rc", "?")
                    err = out.get("error", "")
                    status = "OK" if rc == 0 else f"FAIL (rc={rc})"
                    line = f"- {sid}: {status}"
                    if err:
                        line += f" — {err[:200]}"
                    note_lines.append(line)
                cm.add_note(case_id, "\n".join(note_lines), tags=["runbook"])

            return {
                "case_id": case_id,
                "target": target,
                "step_count": len(results) if results else 0,
            }

        except Exception as e:
            raise e

    run_in_thread(_jm, job_id, _run, progress_callback=prog)
    return jsonify({"status": "ok", "job_id": job_id, "case_id": case_id})


@app.route("/api/case/<case_id>/runbook-log")
@require_api_key
def api_case_runbook_log(case_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        return jsonify({"error": "Case not found"}), 404
    log_path = cm._case_path(case_id) / "runbook-log.json"
    if not log_path.exists():
        return jsonify({"step_outputs": {}, "runbook": info.get("_runbook", "")}), 200
    try:
        data = json.loads(log_path.read_text())
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Runbook Viewer & Launcher
# ---------------------------------------------------------------------------

@app.route("/runbooks")
@require_api_key_html
def runbooks_list():
    try:
        from modules.playbook_engine import RunbookEngine
        from modules.constants import PLAYBOOKS_DIR
        import yaml
        engine = RunbookEngine(PLAYBOOKS_DIR)
        files = engine.list_runbooks()
        runbooks = []
        for f in files:
            try:
                data = yaml.safe_load(f.read_text()) or {}
                steps = data.get("steps", [])
                pre = data.get("preflight", [])
                post = data.get("postflight", [])
                all_steps = steps + pre + post
                step_count = _count_runbook_steps(data)
                type_counts = _count_step_types(data)
                phases = []
                if pre:
                    phases.append("preflight")
                if post:
                    phases.append("postflight")
                runbooks.append({
                    "filename": f.name,
                    "name": data.get("name", f.stem),
                    "version": data.get("version", ""),
                    "description": data.get("description", ""),
                    "step_count": step_count,
                    "type_counts": type_counts,
                    "phases": "+".join(phases) if phases else "",
                })
            except Exception:
                runbooks.append({
                    "filename": f.name,
                    "name": f.stem,
                    "version": "",
                    "description": "",
                    "step_count": 0,
                    "type_counts": {},
                    "phases": "",
                })
        runbooks.sort(key=lambda x: x["name"].lower())
    except Exception as e:
        runbooks = []
    return render_template("runbooks.html", runbooks=runbooks,
                           config=DASHBOARD_CONFIG)


def _count_runbook_steps(data: dict) -> int:
    count = 0
    for phase in ("preflight", "steps", "postflight"):
        for step in data.get(phase, []):
            count += 1
            count += _count_nested_steps(step)
    return count


def _count_nested_steps(step) -> int:
    if not isinstance(step, dict):
        return 0
    count = 0
    for key in ("steps", "then", "else"):
        for child in step.get(key, []):
            if isinstance(child, dict):
                count += 1
                count += _count_nested_steps(child)
    return count


def _count_step_types(data: dict) -> dict:
    counts = {}
    for phase in ("preflight", "steps", "postflight"):
        for step in data.get(phase, []):
            _count_types_in_step(step, counts)
    return dict(sorted(counts.items()))


def _count_types_in_step(step, counts: dict):
    if not isinstance(step, dict):
        return
    t = step.get("type", "tool")
    counts[t] = counts.get(t, 0) + 1
    for key in ("steps", "then", "else"):
        for child in step.get(key, []):
            _count_types_in_step(child, counts)


@app.route("/runbook/<filename>")
@require_api_key_html
def runbook_detail(filename: str):
    try:
        from modules.playbook_engine import RunbookEngine
        from modules.constants import PLAYBOOKS_DIR
        engine = RunbookEngine(PLAYBOOKS_DIR)
        data = engine.load(filename)
    except Exception as e:
        return render_template("error.html",
                               message=f"Runbook '{filename}' not found: {e}"), 404
    # Build nested step HTML using Jinja macro in the template
    return render_template("runbook_detail.html", data=data,
                           filename=filename,
                           config=DASHBOARD_CONFIG)


@app.route("/api/runbook/<filename>/run", methods=["POST"])
@require_api_key
@csrf_required
def api_runbook_run(filename: str):
    data = request.json or {}
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400
    case_id_input = data.get("case_id", "").strip() or None
    vars_override = data.get("vars", {}) or {}

    resolved_case_id = case_id_input or f"runbook-{filename.replace('.yaml','').replace('.yml','')}-{datetime.datetime.now(datetime.timezone.utc):%Y%m%d_%H%M%S}"

    # Create the case upfront so the dashboard can redirect to it immediately
    from modules.case_manager import CaseManager
    cm = CaseManager()
    try:
        cm.create(resolved_case_id, description=f"Runbook: {filename} against {target}",
                  targets=[target])
    except FileExistsError:
        pass  # case already exists, that's fine

    job_id = _jm.create("runbook", f"Run {filename} against {target}",
                         total_steps=5)
    prog = _make_job_progress("", job_id)

    def _run(*, _progress=None):
        try:
            from modules.playbook_engine import RunbookEngine
            from modules.constants import PLAYBOOKS_DIR
            from modules.case_manager import CaseManager
            import json as _json
            if _progress:
                _progress(current_step=1, message="Loading runbook...")
            engine = RunbookEngine(PLAYBOOKS_DIR)
            if _progress:
                _progress(current_step=2, message=f"Running {filename} against {target}...")
            results = engine.run_file(
                filename, targets=[target],
                case_id=resolved_case_id,
                vars_override=vars_override,
                verbose=False,
            )
            if _progress:
                _progress(current_step=4, message="Saving results...")

            # Save step outputs summary as a case note
            cm = CaseManager()
            try:
                runlog_path = Path(cm._case_path(resolved_case_id)) / "runbook-log.json"
                if runlog_path.exists():
                    runlog = _json.loads(runlog_path.read_text())
                    step_outs = runlog.get("step_outputs", {})
                    note_lines = [f"## {filename} Step Results"]
                    for sid, out in step_outs.items():
                        rc = out.get("rc", "?")
                        err = out.get("error", "")
                        status = "OK" if rc == 0 else f"FAIL (rc={rc})"
                        line = f"- {sid}: {status}"
                        if err:
                            line += f" — {err[:200]}"
                        note_lines.append(line)
                    cm.add_note(resolved_case_id, "\n".join(note_lines), tags=["runbook"])
            except Exception:
                pass

            # Return case details so the job stores it as result
            return {
                "case_id": resolved_case_id,
                "target": target,
                "step_count": len(results) if results else 0,
            }

        except Exception as e:
            raise e

    run_in_thread(_jm, job_id, _run, progress_callback=prog)
    return jsonify({"status": "ok", "job_id": job_id, "case_id": resolved_case_id})


# ---------------------------------------------------------------------------
# Runbook listing/steps APIs (for Runbook Editor import)
# ---------------------------------------------------------------------------

@app.route("/api/runbooks/list")
@require_api_key
def api_runbooks_list():
    try:
        from modules.playbook_engine import RunbookEngine
        from modules.constants import PLAYBOOKS_DIR
        import yaml
        engine = RunbookEngine(PLAYBOOKS_DIR)
        files = engine.list_runbooks()
        result = []
        for f in files:
            try:
                data = yaml.safe_load(f.read_text()) or {}
                result.append({
                    "filename": f.name,
                    "name": data.get("name", f.stem),
                    "description": (data.get("description") or "")[:120],
                    "step_count": _count_runbook_steps(data),
                })
            except Exception:
                result.append({
                    "filename": f.name,
                    "name": f.stem,
                    "description": "",
                    "step_count": 0,
                })
        result.sort(key=lambda x: x["name"].lower())
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/runbook/<filename>/steps")
@require_api_key
def api_runbook_steps(filename: str):
    try:
        from modules.playbook_engine import RunbookEngine
        from modules.constants import PLAYBOOKS_DIR
        import yaml
        engine = RunbookEngine(PLAYBOOKS_DIR)
        data = engine.load(filename)
        steps = []
        for s in data.get("steps", []):
            if not isinstance(s, dict):
                continue
            tool = s.get("tool") or s.get("type", "")
            if tool in ("log", "set", "wait", "parallel", "foreach", "conditional", "notify", "prompt"):
                continue
            args = s.get("args", [])
            target_str = " ".join(str(a) for a in args) if args else ""
            steps.append({
                "name": s.get("name", s.get("id", "")),
                "tool": tool,
                "target": target_str,
                "timeout": s.get("timeout", 300),
                "retries": s.get("retries", 0),
                "description": s.get("description", ""),
            })
        return jsonify({"filename": filename, "name": data.get("name", filename), "steps": steps})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Rule Management
# ---------------------------------------------------------------------------

_RM = None  # lazy singleton

def _get_rm():
    global _RM
    if _RM is None:
        from modules.rules_manager import RuleManager
        _RM = RuleManager()
    return _RM


@app.route("/rules")
@require_api_key_html
def rules_list():
    rm = _get_rm()
    fmt = request.args.get("format", "")
    sev = request.args.get("severity", "")
    q = request.args.get("q", "")
    cat = request.args.get("category", "")
    rules = rm.list_rules(rule_format=fmt, severity=sev, search=q, category=cat)
    stats = rm.get_format_stats()
    return render_template("rules.html", rules=rules, stats=stats,
                           active_format=fmt, active_severity=sev,
                           active_q=q, active_category=cat,
                           config=DASHBOARD_CONFIG)


@app.route("/rules/<format_name>/<rule_id>")
@require_api_key_html
def rule_detail(format_name: str, rule_id: str):
    rm = _get_rm()
    rule = rm.get_rule(format_name, rule_id)
    if not rule:
        return render_template("error.html",
                               message=f"Rule not found: {format_name}/{rule_id}"), 404
    return render_template("rule_detail.html", rule=rule,
                           config=DASHBOARD_CONFIG)


@app.route("/rules/new")
@require_api_key_html
def rule_new():
    fmt = request.args.get("format", "semgrep")
    rm = _get_rm()
    template = rm.get_format_template(fmt)
    return render_template("rule_edit.html", rule=None,
                           format_name=fmt, content=template,
                           is_new=True, config=DASHBOARD_CONFIG)


@app.route("/rules/<format_name>/<rule_id>/edit")
@require_api_key_html
def rule_edit(format_name: str, rule_id: str):
    rm = _get_rm()
    rule = rm.get_rule(format_name, rule_id)
    if not rule:
        return render_template("error.html",
                               message=f"Rule not found: {format_name}/{rule_id}"), 404
    return render_template("rule_edit.html", rule=rule,
                           format_name=format_name,
                           content=rule.get("raw", ""),
                           is_new=False, config=DASHBOARD_CONFIG)


@app.route("/api/rules/<format_name>/<rule_id>/save", methods=["POST"])
@require_api_key
@csrf_required
def api_rule_save(format_name: str, rule_id: str):
    rm = _get_rm()
    data = request.json or {}
    content = data.get("content", "")
    if not content.strip():
        return jsonify({"error": "Content is empty"}), 400
    try:
        result = rm.save_rule(format_name, rule_id, content)
        return jsonify(result)
    except (ValueError, FileNotFoundError) as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/rules/create", methods=["POST"])
@require_api_key
@csrf_required
def api_rule_create():
    rm = _get_rm()
    data = request.json or {}
    fmt = data.get("format", "semgrep")
    content = data.get("content", "")
    target_dir = data.get("target_dir", "")
    if not content.strip():
        return jsonify({"error": "Content is empty"}), 400
    try:
        result = rm.create_rule(fmt, content, target_dir=target_dir)
        return jsonify(result), 201
    except (ValueError, FileNotFoundError) as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/rules/<format_name>/<rule_id>", methods=["DELETE"])
@require_api_key
@csrf_required
def api_rule_delete(format_name: str, rule_id: str):
    rm = _get_rm()
    try:
        result = rm.delete_rule(format_name, rule_id)
        return jsonify(result)
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404


# ---------------------------------------------------------------------------
# Batch Rule Operations — export / import / bulk delete
# ---------------------------------------------------------------------------

@app.route("/api/rules/bulk/export", methods=["POST"])
@require_api_key
@csrf_required
def api_rules_bulk_export():
    rm = _get_rm()
    data = request.json or {}
    fmt = data.get("format", "")
    rule_ids = data.get("rule_ids")  # None or list
    if not fmt:
        return jsonify({"error": "format required"}), 400
    try:
        zip_bytes = rm.export_rules(fmt, rule_ids)
        return send_file(
            io.BytesIO(zip_bytes),
            mimetype="application/zip",
            as_attachment=True,
            download_name=f"rules-{fmt}-export.zip",
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/rules/bulk/import", methods=["POST"])
@require_api_key
@csrf_required
def api_rules_bulk_import():
    rm = _get_rm()
    fmt = request.form.get("format", "")
    target_dir = request.form.get("target_dir", "")
    if not fmt:
        return jsonify({"error": "format required"}), 400

    if "file" in request.files:
        f = request.files["file"]
        raw = f.read()
        fname = (f.filename or "").lower()
        if fname.endswith(".zip"):
            result = rm.import_rules_from_zip(fmt, raw, target_dir=target_dir)
        else:
            content = raw.decode("utf-8", errors="replace")
            result = rm.import_rules(fmt, content, target_dir=target_dir)
    else:
        data = request.get_json(silent=True) or {}
        content = data.get("content", "")
        if not content.strip():
            return jsonify({"error": "No file or content provided"}), 400
        result = rm.import_rules(fmt, content, target_dir=target_dir)

    return jsonify(result)


@app.route("/api/rules/bulk/delete", methods=["POST"])
@require_api_key
@csrf_required
def api_rules_bulk_delete():
    rm = _get_rm()
    data = request.json or {}
    fmt = data.get("format", "")
    rule_ids = data.get("rule_ids", [])
    if not fmt:
        return jsonify({"error": "format required"}), 400
    if not rule_ids or not isinstance(rule_ids, list):
        return jsonify({"error": "rule_ids must be a non-empty array"}), 400
    result = rm.bulk_delete(fmt, rule_ids)
    return jsonify(result)


# ---------------------------------------------------------------------------
# Rule Scanning — run Nuclei/YARA/Semgrep with custom rules
# ---------------------------------------------------------------------------

def _scan_single_rule(rule_format: str, rule_id: str, target: str,
                      output_dir: str, prog, **kwargs) -> dict:
    """Run a scan with a single rule. Returns results dict."""
    rm = _get_rm()
    rule = rm.get_rule(rule_format, rule_id)
    if not rule:
        return {"error": f"Rule not found: {rule_format}/{rule_id}"}
    filepath = rule.get("filepath", "")
    if not filepath:
        return {"error": "Rule filepath not found"}

    if rule_format == "nuclei":
        from modules.tool_wrappers import nuclei_scan
        result = nuclei_scan(target, template=filepath, output_dir=Path(output_dir))
    elif rule_format == "yara":
        from modules.tool_wrappers import yara_scan
        result = yara_scan(filepath, target)
    elif rule_format == "semgrep":
        from modules.tool_wrappers import semgrep_scan
        result = semgrep_scan(filepath, target)
    elif rule_format == "codeql":
        from modules.tool_wrappers import codeql_scan
        language = kwargs.get("language", "")
        result = codeql_scan(filepath, target, language=language)
    else:
        return {"error": f"Scan not supported for format: {rule_format}"}
    return result


def _scan_all_rules(rule_format: str, target: str,
                    output_dir: str, prog) -> dict:
    """Run a scan with all rules of a given format. Returns results dict."""
    rm = _get_rm()
    from modules.rules_manager import RULE_ROOTS, FLAT_ROOTS

    if rule_format == "nuclei":
        root = RULE_ROOTS.get("nuclei") or FLAT_ROOTS.get("nuclei")
        if not root or not root.exists():
            return {"error": "Nuclei rules directory not found"}
        from modules.tool_wrappers import nuclei_scan
        result = nuclei_scan(target, templates_dir=str(root),
                             output_dir=Path(output_dir))
    elif rule_format == "yara":
        root = RULE_ROOTS.get("yara") or FLAT_ROOTS.get("yara")
        flat = FLAT_ROOTS.get("yara")
        if not root or not root.exists():
            return {"error": "YARA rules directory not found"}
        from modules.tool_wrappers import yara_scan
        result = yara_scan(str(root), target)
    elif rule_format == "semgrep":
        root = RULE_ROOTS.get("semgrep")
        if not root or not root.exists():
            return {"error": "Semgrep rules directory not found"}
        from modules.tool_wrappers import semgrep_scan
        result = semgrep_scan(str(root), target)
    elif rule_format == "codeql":
        root = RULE_ROOTS.get("codeql")
        if not root or not root.exists():
            return {"error": "CodeQL rules directory not found"}
        from modules.tool_wrappers import codeql_scan
        # CodeQL batch scan not supported — must pick a query for a specific language
        result = {"error": "Use single-rule scan for CodeQL (requires language parameter)"}
    else:
        return {"error": f"Scan not supported for format: {rule_format}"}
    return result


@app.route("/api/rules/<format_name>/<rule_id>/scan", methods=["POST"])
@require_api_key
@csrf_required
def api_rule_scan(format_name: str, rule_id: str):
    """Scan a target with a specific rule. Returns job_id for progress tracking."""
    data = request.json or {}
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400
    output_dir = data.get("output_dir", "").strip()

    job_id = _jm.create("rule-scan", f"Scan {target} with {rule_id}",
                        total_steps=5)
    prog = _make_job_progress("", job_id)

    def _run(*, _progress=None):
        try:
            if _progress:
                _progress(current_step=1, message=f"Loading rule {rule_id}...")
            language = data.get("language", "")
            result = _scan_single_rule(format_name, rule_id, target,
                                       output_dir or str(Path.cwd()), _progress, language=language)
            if _progress:
                _progress(current_step=4,
                          message=f"Scan complete: {result.get('finding_count', result.get('total', 'done'))} results")
            if result.get("error"):
                _jm.fail(job_id, result["error"])
            else:
                _jm.complete(job_id, result)
        except Exception as e:
            _jm.fail(job_id, str(e))

    run_in_thread(_jm, job_id, _run, progress_callback=prog)
    return jsonify({"status": "ok", "job_id": job_id}), 202


@app.route("/api/rules/<format_name>/scan-all", methods=["POST"])
@require_api_key
@csrf_required
def api_rule_scan_all(format_name: str):
    """Scan a target with all rules of a format. Returns job_id."""
    data = request.json or {}
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400
    output_dir = data.get("output_dir", "").strip()

    job_id = _jm.create("rule-scan-all", f"Scan {target} with all {format_name} rules",
                        total_steps=5)
    prog = _make_job_progress("", job_id)

    def _run(*, _progress=None):
        try:
            if _progress:
                _progress(current_step=1, message=f"Loading {format_name} rules...")
            result = _scan_all_rules(format_name, target,
                                     output_dir or str(Path.cwd()), _progress)
            if _progress:
                _progress(current_step=4,
                          message=f"Scan complete: {result.get('finding_count', result.get('total', 'done'))} results")
            if result.get("error"):
                _jm.fail(job_id, result["error"])
            else:
                _jm.complete(job_id, result)
        except Exception as e:
            _jm.fail(job_id, str(e))

    run_in_thread(_jm, job_id, _run, progress_callback=prog)
    return jsonify({"status": "ok", "job_id": job_id}), 202


# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------


@app.route("/case/<case_id>/report")
@require_api_key_html
def case_report(case_id: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        info = None
    if not info:
        return render_template("error.html", message="Case not found"), 404
    return render_template("report.html", case=info, config=DASHBOARD_CONFIG)


@app.route("/api/case/<case_id>/report/generate", methods=["POST"])
@require_api_key
@csrf_required
def api_report_generate(case_id: str):
    data = request.json or {}
    fmt = data.get("format", "md")
    markdown_override = data.get("markdown", "")
    html_override = data.get("html", "")
    cm = CaseManager()

    case_dir = cm._case_path(case_id)
    from modules.report_generator import (generate_obsidian_report, _md_to_html_full,
                                          _convert_md_to_docx, _convert_md_to_pdf,
                                          _render_report_markdown, _load_case,
                                          _logo_base64_tag, _add_table_th_styles,
                                          _add_poc_inline_styles)

    # If raw HTML provided (from preview iframe), handle directly for DOCX/PDF/HTML
    if html_override:
        if fmt == "html":
            # Preview HTML has JS PoC fixes baked in; add table header inline styles for pandoc compat
            styled = _add_table_th_styles(html_override)
            styled = _add_poc_inline_styles(styled)
            return jsonify({"status": "ok", "output": styled})
        elif fmt in ("docx", "pdf"):
            try:
                import tempfile
                # Apply inline table header styles so pandoc picks them up
                styled = _add_table_th_styles(html_override)
                tmp_html = tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w", encoding="utf-8")
                tmp_html.write(styled)
                tmp_path = Path(tmp_html.name)
                tmp_html.close()
                out_path = tmp_path.with_suffix(f".{fmt}")
                if fmt == "docx":
                    subprocess.run(["pandoc", str(tmp_path), "-o", str(out_path), "--from", "html"],
                                   capture_output=True, text=True, timeout=60)
                else:
                    from weasyprint import HTML
                    HTML(filename=str(tmp_path)).write_pdf(str(out_path))
                if out_path.exists():
                    mimetypes = {"docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                                 "pdf": "application/pdf"}
                    mime = mimetypes.get(fmt, "application/octet-stream")
                    return send_file(str(out_path), mimetype=mime, as_attachment=True,
                                     download_name=f"report-{case_id}.{fmt}")
                return jsonify({"error": "Conversion failed", "job_id": ""}), 500
            except Exception as e:
                return jsonify({"error": str(e), "job_id": ""}), 500
        # For MD format, fall through to markdownify conversion below

    # If raw HTML provided (for MD format only), convert to markdown via markdownify
    if html_override and fmt == "md":
        from markdownify import markdownify as _md_from_html
        markdown_override = _md_from_html(html_override, heading_style="ATX")

    # If markdown provided directly (or converted from HTML for MD format), process it
    if markdown_override:
        try:
            if fmt == "md":
                return jsonify({"status": "ok", "output": markdown_override})
            elif fmt == "html":
                logo_tag = _logo_base64_tag(case_dir)
                md_with_logo = f"{logo_tag}\n\n{markdown_override}" if logo_tag else markdown_override
                html = _md_to_html_full(md_with_logo, f"Report — {case_id}")
                html = _add_table_th_styles(html)
                html = _add_poc_inline_styles(html)
                return jsonify({"status": "ok", "output": html})
            elif fmt in ("docx", "pdf"):
                import tempfile
                logo_tag = _logo_base64_tag(case_dir)
                md_for_export = f"{logo_tag}\n\n{markdown_override}" if logo_tag else markdown_override
                tmp = tempfile.NamedTemporaryFile(suffix=f".{fmt}", delete=False)
                tmp_path = Path(tmp.name)
                tmp.close()
                if fmt == "docx":
                    _convert_md_to_docx(md_for_export, tmp_path, f"Report — {case_id}", case_dir=case_dir)
                else:
                    _convert_md_to_pdf(md_for_export, tmp_path, f"Report — {case_id}", case_dir=case_dir)
                if tmp_path.exists():
                    mimetypes = {"docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                                 "pdf": "application/pdf"}
                    mime = mimetypes.get(fmt, "application/octet-stream")
                    return send_file(str(tmp_path), mimetype=mime, as_attachment=True,
                                     download_name=f"report-{case_id}.{fmt}")
                return jsonify({"error": "Conversion failed", "job_id": ""}), 500
        except Exception as e:
            return jsonify({"error": str(e), "job_id": ""}), 500

    # For raw markdown, use _render_report_markdown directly (avoids file-path bugs)
    if fmt == "md":
        case_data, findings = _load_case(case_dir)
        md = _render_report_markdown(case_data, findings, case_dir=case_dir)
        return jsonify({"status": "ok", "output": md})

    # Full report generation from case data (original flow for html/docx/pdf)
    job_id = _jm.create("report", f"Generate {fmt.upper()} report for {case_id}", total_steps=5)
    prog = _make_job_progress(case_id, job_id)
    try:
        prog(current_step=1, message="Loading case data...")
        result = generate_obsidian_report(case_dir, formats=[fmt])
        prog(current_step=4, message="Rendering output...")
        output_path = result.get(fmt, "")
        output_path = Path(str(output_path)) if output_path else None
        prog(current_step=5, message="Done")
        if output_path and output_path.exists():
            if fmt in ("md", "html"):
                content = output_path.read_text(encoding="utf-8", errors="replace")
                _jm.complete(job_id, str(output_path))
                return jsonify({"status": "ok", "output": content,
                                "file": str(output_path), "job_id": job_id})
            else:
                mimetypes = {"docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                             "pdf": "application/pdf"}
                mime = mimetypes.get(fmt, "application/octet-stream")
                _jm.complete(job_id, str(output_path))
                return send_file(str(output_path), mimetype=mime, as_attachment=True,
                                 download_name=f"report-{case_id}.{fmt}")
        _jm.complete(job_id, str(output_path) if output_path else "")
        return jsonify({"status": "ok", "output": str(output_path) if output_path else "Report generated",
                        "job_id": job_id})
    except Exception as e:
        _jm.fail(job_id, str(e))
        return jsonify({"error": str(e), "job_id": job_id}), 500


@app.route("/terminal")
@require_api_key_html
def terminal():
    return render_template("terminal.html", config=DASHBOARD_CONFIG)


@app.route("/tools")
@require_api_key_html
def tools_page():
    return render_template("tools.html", config=DASHBOARD_CONFIG)


@app.route("/prompts")
@require_api_key_html
def prompts_page():
    return render_template("prompts.html", config=DASHBOARD_CONFIG)


# ---------------------------------------------------------------------------
# AI Infrastructure dashboard
# ---------------------------------------------------------------------------
def _tmux_running(session: str) -> bool:
    try:
        r = subprocess.run(["tmux", "has-session", "-t", session],
                           capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False

def _ollama_reachable() -> dict:
    try:
        r = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "http://localhost:11434/api/tags"],
            capture_output=True, text=True, timeout=5
        )
        if r.stdout.strip() == "200":
            r2 = subprocess.run(
                ["curl", "-s", "http://localhost:11434/api/tags"],
                capture_output=True, text=True, timeout=5
            )
            try:
                data = json.loads(r2.stdout)
                models = data.get("models", [])
                model_names = [m.get("name", "?") for m in models]
                active_model = model_names[0] if model_names else "unknown"
            except Exception:
                model_names = []
                active_model = "unknown"
            return {"reachable": True, "models": len(model_names),
                    "model": active_model, "model_list": model_names}
        return {"reachable": False, "models": 0, "model": "unknown",
                "http": r.stdout.strip()}
    except Exception as e:
        return {"reachable": False, "models": 0, "model": "unknown",
                "error": str(e)}

def _hexstrike_running() -> bool:
    return _tmux_running("hexstrike")

def _ai_tunnel_running() -> bool:
    return _tmux_running("ai-tunnel")


@app.route("/api/ai/status")
@require_api_key
def api_ai_status():
    """Status of all AI infrastructure components."""
    hexstrike = _hexstrike_running()
    tunnel = _ai_tunnel_running()
    ollama = _ollama_reachable()
    return jsonify({
        "hexstrike": {"running": hexstrike},
        "tunnel": {"running": tunnel},
        "ollama": ollama,
        "all_ready": hexstrike and tunnel and ollama.get("reachable", False),
    })


@app.route("/api/ai/config")
@require_api_key
def api_ai_config():
    """Return the active opencode.json config."""
    try:
        cfg_path = Path.home() / ".config" / "opencode" / "opencode.json"
        if cfg_path.exists():
            return jsonify({"config": cfg_path.read_text()})
        return jsonify({"config": "{}"})
    except Exception as e:
        return jsonify({"config": "{}", "error": str(e)})

@app.route("/api/ai/start", methods=["POST"])
@require_api_key
@csrf_required
def api_ai_start():
    """Start all AI components in sequence."""
    results = {"hexstrike": None, "tunnel": None, "ollama": None}

    # 1. Start hexstrike
    if not _hexstrike_running():
        r = _run_cc_command("infra hexstrike start")
        results["hexstrike"] = {"status": "started" if r["rc"] == 0 else "failed",
                                "output": r["stdout"][:200] or r["stderr"][:200]}
    else:
        results["hexstrike"] = {"status": "already_running"}

    # 2. Start AI tunnel + ollama
    if not _ai_tunnel_running() or not _ollama_reachable().get("reachable"):
        r = _run_cc_command("infra ai-setup up")
        tunnel_ok = _ai_tunnel_running()
        ollama_ok = _ollama_reachable().get("reachable", False)
        results["tunnel"] = {"status": "started" if tunnel_ok else "failed",
                             "output": r["stdout"][:200] or r["stderr"][:200]}
        results["ollama"] = {"status": "reachable" if ollama_ok else "checking",
                             "detail": _ollama_reachable()}
    else:
        results["tunnel"] = {"status": "already_running"}
        results["ollama"] = {"status": "reachable", "detail": _ollama_reachable()}

    all_ok = (_hexstrike_running() and _ai_tunnel_running()
              and _ollama_reachable().get("reachable", False))
    return jsonify({"status": "ready" if all_ok else "partial", **results})


@app.route("/api/ai/stop", methods=["POST"])
@require_api_key
@csrf_required
def api_ai_stop():
    """Stop all AI components."""
    results = {}
    if _hexstrike_running():
        r = _run_cc_command("infra hexstrike stop")
        results["hexstrike"] = r["stdout"][:100] or r["stderr"][:100] or "stopped"
    else:
        results["hexstrike"] = "not_running"
    if _ai_tunnel_running():
        r = _run_cc_command("infra ai-setup down")
        results["tunnel"] = r["stdout"][:100] or r["stderr"][:100] or "stopped"
    else:
        results["tunnel"] = "not_running"
    return jsonify({"status": "stopped", **results})


@app.route("/api/ai/run-opencode", methods=["POST"])
@require_api_key
@csrf_required
def api_ai_run_opencode():
    """Launch opencode in a tmux session (for in-browser terminal access)."""
    if _tmux_running("opencode"):
        return jsonify({"status": "already_running", "session": "opencode"})
    try:
        oc = shutil.which("opencode") or "/usr/bin/opencode"
        r = subprocess.run(
            ["tmux", "new-session", "-d", "-s", "opencode", oc],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            return jsonify({"status": "started", "session": "opencode"})
        else:
            return jsonify({"status": "failed", "error": r.stderr[:200]}), 500
    except Exception as e:
        return jsonify({"status": "failed", "error": str(e)}), 500


@app.route("/api/ai/opencode-output")
@require_api_key
@csrf_required
def api_ai_opencode_output():
    """Return recent output from opencode tmux session (polled for in-browser display)."""
    if not _tmux_running("opencode"):
        return jsonify({"running": False, "output": ""})
    try:
        r = subprocess.run(
            ["tmux", "capture-pane", "-t", "opencode", "-p", "-S", "-50"],
            capture_output=True, text=True, timeout=5
        )
        return jsonify({"running": True, "output": r.stdout[-5000:]})
    except Exception as e:
        return jsonify({"running": False, "output": "", "error": str(e)})


@app.route("/ai")
@require_api_key_html
def ai_dashboard():
    """AI Infrastructure dashboard page."""
    return render_template("ai.html", config=DASHBOARD_CONFIG, ai_tunnel_target=DASHBOARD_CONFIG["ai_tunnel_target"])


# ---------------------------------------------------------------------------
# Job Queue (background tasks with SSE)
# ---------------------------------------------------------------------------
_jm = get_job_manager()


def _make_job_progress(case_id: str, job_id: str):
    """Return a progress callback for use with run_in_thread."""
    def _progress(current_step: int = None, message: str = "",
                  total_steps: int = None):
        _jm.update(job_id, current_step=current_step, message=message,
                    total_steps=total_steps)
    return _progress


@app.route("/jobs")
@require_api_key_html
def jobs_page():
    return render_template("jobs.html", config=DASHBOARD_CONFIG)


@app.route("/api/jobs")
@require_api_key
def api_jobs_list():
    return jsonify(_jm.list_jobs(limit=50))


@app.route("/api/jobs/<job_id>")
@require_api_key
def api_job_status(job_id: str):
    job = _jm.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)


@app.route("/api/jobs/stream")
@require_api_key
def api_jobs_stream():
    """SSE endpoint for real-time job updates."""
    job_ids = request.args.get("job_ids", "").split(",")
    job_ids = [j.strip() for j in job_ids if j.strip()] or None
    return app.response_class(
        _jm.listen(job_ids),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )


@app.route("/api/jobs/create", methods=["POST"])
@require_api_key
@csrf_required
def api_jobs_create():
    data = request.json or {}
    job_type = data.get("type", "custom")
    title = data.get("title", "Untitled Job")
    total_steps = data.get("total_steps", 100)
    job_id = _jm.create(job_type, title, total_steps)
    return jsonify({"job_id": job_id}), 201


@app.route("/api/jobs/<job_id>/cancel", methods=["POST"])
@require_api_key
@csrf_required
def api_job_cancel(job_id: str):
    _jm.cancel(job_id)
    return jsonify({"status": "cancelled"})


# Static file serving for case evidence
@app.route("/cases/<case_id>/<path:subpath>")
@require_api_key_html
def serve_case_file(case_id: str, subpath: str):
    cm = CaseManager()
    try:
        info = cm.info(case_id)
    except Exception:
        info = None
    if not info:
        return "Case not found", 404
    case_dir = cm._case_path(case_id)
    # Prevent path traversal beyond the case directory
    file_path = (case_dir / subpath).resolve()
    if not str(file_path).startswith(str(case_dir.resolve()) + os.sep):
        return "Forbidden", 403
    if not file_path.exists() or not file_path.is_file():
        return "File not found", 404
    return send_file(str(file_path))


# ---------------------------------------------------------------------------
# DNS resolution & monitoring
# ---------------------------------------------------------------------------

@app.route("/flashcards")
@require_api_key_html
def flashcards_page():
    return render_template("flashcards.html", config=DASHBOARD_CONFIG)


@app.route("/api/flashcards")
@require_api_key
def api_flashcards_list():
    decks_dir = CC_DIR / "flashcards"
    decks = []
    if decks_dir.is_dir():
        for f in sorted(decks_dir.glob("*.yaml")):
            try:
                data = yaml.safe_load(f.read_text()) or {}
                decks.append({"id": f.stem, "title": data.get("title", f.stem),
                              "description": data.get("description", ""),
                              "card_count": len(data.get("cards", []))})
            except Exception:
                pass
    return jsonify(decks)


@app.route("/api/flashcards/<name>")
@require_api_key
def api_flashcards_deck(name):
    path = CC_DIR / "flashcards" / f"{name}.yaml"
    if not path.is_file():
        return jsonify({"error": "Deck not found"}), 404
    try:
        data = yaml.safe_load(path.read_text()) or {}
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/dns")
@require_api_key_html
def dns_page():
    return render_template("dns.html", config=DASHBOARD_CONFIG)


@app.route("/api/dns/resolve")
@require_api_key
def api_dns_resolve():
    domain = request.args.get("domain", "")
    types = request.args.get("types", "")
    if not domain:
        return jsonify({"error": "domain parameter required"}), 400
    type_list = types.split(",") if types else None
    from modules.dns_wrapper import resolve as dns_resolve
    return jsonify(dns_resolve(domain, type_list))


@app.route("/api/dns/monitors")
@require_api_key
def api_dns_monitors():
    from modules.dns_wrapper import list_monitors
    return jsonify(list_monitors())


@app.route("/api/dns/monitor", methods=["POST"])
@require_api_key
@csrf_required
def api_dns_start_monitor():
    data = request.get_json() or {}
    domain = data.get("domain", "")
    if not domain:
        return jsonify({"error": "domain required"}), 400
    types = data.get("types")
    interval = int(data.get("interval", 300))
    duration = int(data.get("duration", 0))
    from modules.dns_wrapper import start_monitor, start_background_monitor
    start_background_monitor()
    result = start_monitor(domain, types, interval, duration)
    return jsonify(result)


@app.route("/api/dns/monitor/<path:domain>", methods=["DELETE"])
@require_api_key
@csrf_required
def api_dns_stop_monitor(domain):
    from modules.dns_wrapper import stop_monitor, remove_monitor
    stop_monitor(domain)
    result = remove_monitor(domain)
    return jsonify(result)


@app.route("/api/dns/history/<path:domain>")
@require_api_key
def api_dns_history(domain):
    limit = request.args.get("limit", 100, type=int)
    from modules.dns_wrapper import get_history
    return jsonify(get_history(domain, limit))


# ---------------------------------------------------------------------------
# WiFi Monitor
# ---------------------------------------------------------------------------
@app.route("/wifi-monitor")
@require_api_key_html
def wifi_monitor_page():
    return render_template("wifi_monitor.html", config=DASHBOARD_CONFIG)


@app.route("/api/wifi/monitor/start", methods=["POST"])
@require_api_key
@csrf_required
def api_wifi_monitor_start():
    from modules.wifi_monitor import get_monitor_manager
    data = request.json or {}
    iface = data.get("iface", "wlan0")
    band = data.get("band", "abg")
    target_bssid = data.get("target_bssid", "")
    target_essid = data.get("target_essid", "")
    session_id = data.get("session_id", f"wifi-{int(time.time())}")
    mgr = get_monitor_manager()
    r = mgr.start_session(session_id, iface, band, target_bssid, target_essid)
    if r.get("error"):
        return jsonify(r), 400
    return jsonify(r)


@app.route("/api/wifi/monitor/stop", methods=["POST"])
@require_api_key
@csrf_required
def api_wifi_monitor_stop():
    from modules.wifi_monitor import get_monitor_manager
    data = request.json or {}
    session_id = data.get("session_id", "")
    force = data.get("force", False)
    mgr = get_monitor_manager()
    if session_id:
        sess = mgr.get_session(session_id)
        if not sess:
            return jsonify({"error": "Session not found"}), 404
        r = sess.force_kill() if force else sess.stop()
    else:
        active = mgr.get_active_session()
        if not active:
            return jsonify({"error": "No active session"}), 400
        r = active.force_kill() if force else active.stop()
    return jsonify(r)


@app.route("/api/wifi/monitor/status")
@require_api_key
def api_wifi_monitor_status():
    from modules.wifi_monitor import get_monitor_manager
    mgr = get_monitor_manager()
    session_id = request.args.get("session_id", "")
    if session_id:
        sess = mgr.get_session(session_id)
        if not sess:
            return jsonify({"error": "Session not found"}), 404
        return jsonify(sess.status_info())
    active = mgr.get_active_session()
    if not active:
        return jsonify({"status": "no_active_session"})
    return jsonify(active.status_info())


@app.route("/api/wifi/monitor/data")
@require_api_key
def api_wifi_monitor_data():
    from modules.wifi_monitor import get_monitor_manager
    mgr = get_monitor_manager()
    session_id = request.args.get("session_id", "")
    if session_id:
        sess = mgr.get_session(session_id)
    else:
        sess = mgr.get_active_session()
    if not sess:
        return jsonify({"error": "No session found"}), 404
    return jsonify(sess.get_data())


@app.route("/api/wifi/monitor/sessions")
@require_api_key
def api_wifi_monitor_sessions():
    from modules.wifi_monitor import get_monitor_manager
    mgr = get_monitor_manager()
    return jsonify(mgr.list_sessions())


@app.route("/api/wifi/monitor/parse-pcap", methods=["POST"])
@require_api_key
@csrf_required
def api_wifi_monitor_parse_pcap():
    from modules.wifi_monitor import get_monitor_manager
    mgr = get_monitor_manager()
    session_id = (request.json or {}).get("session_id", "")
    if session_id:
        sess = mgr.get_session(session_id)
    else:
        sess = mgr.get_active_session()
    if not sess:
        return jsonify({"error": "No session found"}), 404
    r = sess.parse_pcap_now()
    return jsonify(r)


@app.route("/api/wifi/monitor/deauth", methods=["POST"])
@require_api_key
@csrf_required
def api_wifi_monitor_deauth():
    """Send deauth packets to force client reconnection and trigger 4-way handshake capture."""
    from modules.wifi_monitor import get_monitor_manager
    mgr = get_monitor_manager()
    session_id = (request.json or {}).get("session_id", "")
    if session_id:
        sess = mgr.get_session(session_id)
    else:
        sess = mgr.get_active_session()
    if not sess:
        return jsonify({"error": "No active or specified session"}), 404
    bssid = (request.json or {}).get("bssid", "")
    client = (request.json or {}).get("client", "")
    count = (request.json or {}).get("count", 5)
    if not bssid:
        return jsonify({"error": "bssid is required"}), 400
    r = sess.deauth(bssid, client=client, count=count)
    return jsonify(r)


@app.route("/api/wifi/monitor/interfaces")
@require_api_key
def api_wifi_monitor_interfaces():
    """List available wireless interfaces."""
    import subprocess
    try:
        r = subprocess.run(["iwconfig"], capture_output=True, text=True, timeout=5)
        ifaces = []
        for line in r.stdout.splitlines():
            if "IEEE 802.11" in line:
                name = line.split()[0]
                ifaces.append(name)
        if not ifaces:
            # Fallback: list all wireless interfaces
            r2 = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
            for line in r2.stdout.splitlines():
                if "Interface" in line:
                    ifaces.append(line.split()[-1])
        return jsonify(ifaces)
    except Exception:
        return jsonify(["wlan0"])


@app.route("/api/wifi/monitor/cleanup-orphans", methods=["POST"])
@require_api_key
@csrf_required
def api_wifi_monitor_cleanup_orphans():
    """Find and clean up leftover monitor-mode interfaces not in use by any active session."""
    from modules.wifi_monitor import get_monitor_manager
    import subprocess
    mgr = get_monitor_manager()
    active = mgr.get_active_session()
    active_in_use = {active.mon_iface, active.iface} if active else set()
    cleaned = []
    try:
        r = subprocess.run(["iwconfig"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            if "Mode:Monitor" in line:
                iface = line.split()[0]
                if iface in active_in_use:
                    continue
                subprocess.run(["airmon-ng", "stop", iface],
                               capture_output=True, timeout=5)
                cleaned.append(iface)
        return jsonify({"status": "ok", "cleaned": cleaned})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Prompt Library API
# ---------------------------------------------------------------------------
import yaml

PROMPTS_DIR = CC_DIR / "prompts"

@app.route("/api/prompts", methods=["GET", "POST"])
@csrf_required
@require_api_key
def api_prompts():
    if request.method == "POST":
        data = request.get_json(force=True)
        name = data.get("id") or data.get("title", "").lower().replace(" ", "-").replace(r"[^a-z0-9-]", "")
        if not name:
            return jsonify({"error": "Name is required"}), 400
        path = PROMPTS_DIR / f"{name}.yaml"
        if path.exists():
            return jsonify({"error": f"Prompt '{name}' already exists"}), 409
        doc = {
            "title": data.get("title", name),
            "description": data.get("description", ""),
            "tags": data.get("tags", []),
            "prompt": data.get("prompt", ""),
        }
        PROMPTS_DIR.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.dump(doc, default_flow_style=False, allow_unicode=True))
        return jsonify({"id": name, "title": doc["title"]}), 201

    prompts = []
    if PROMPTS_DIR.exists():
        for f in sorted(PROMPTS_DIR.glob("*.yaml")):
            try:
                data = yaml.safe_load(f.read_text())
                prompts.append({
                    "id": f.stem,
                    "title": data.get("title", f.stem),
                    "description": data.get("description", ""),
                    "tags": data.get("tags", []),
                    "prompt": data.get("prompt", "").strip(),
                })
            except Exception as e:
                prompts.append({"id": f.stem, "title": f.stem, "error": str(e)})
    return jsonify(prompts)


@app.route("/api/prompts/<name>", methods=["PUT", "DELETE"])
@csrf_required
@require_api_key
def api_prompt_detail(name):
    path = PROMPTS_DIR / f"{name}.yaml"
    if request.method == "DELETE":
        if not path.exists():
            return jsonify({"error": "Not found"}), 404
        path.unlink()
        return jsonify({"status": "deleted"})
    if not path.exists():
        return jsonify({"error": "Not found"}), 404
    data = request.get_json(force=True)
    current = yaml.safe_load(path.read_text()) or {}
    current.update({
        "title": data.get("title", current.get("title", name)),
        "description": data.get("description", current.get("description", "")),
        "tags": data.get("tags", current.get("tags", [])),
        "prompt": data.get("prompt", current.get("prompt", "")),
    })
    path.write_text(yaml.dump(current, default_flow_style=False, allow_unicode=True))
    return jsonify({"id": name, "title": current["title"]})


# ---------------------------------------------------------------------------
# Dashboard API
# ---------------------------------------------------------------------------
@app.route("/api/dashboard/stats")
@require_api_key
def api_dashboard_stats():
    cm = CaseManager()
    cases = cm.list_cases()
    cases_by_status: dict = {}
    cases_by_type: dict = {}
    all_findings = []

    cases_list = []
    for c in cases:
        st = c.get("status", "unknown")
        cases_by_status[st] = cases_by_status.get(st, 0) + 1
        tp = c.get("type", "unknown")
        cases_by_type[tp] = cases_by_type.get(tp, 0) + 1
        cid = c.get("case_id", "")
        db = FindingsDB(cm._case_path(cid))
        c_findings = db.list()
        c_finding_sev = {}
        for ff in c_findings:
            s = ff.get("severity", "info")
            c_finding_sev[s] = c_finding_sev.get(s, 0) + 1
        cases_list.append({
            "case_id": cid,
            "client": c.get("client", ""),
            "type": tp,
            "status": st,
            "created": c.get("created", ""),
            "findings": len(c_findings),
            "findings_by_severity": c_finding_sev,
            "critical": c_finding_sev.get("critical", 0),
            "high": c_finding_sev.get("high", 0),
        })
        for f in c_findings:
            f["_case_id"] = cid
            f["_case_title"] = c.get("client", cid)
            all_findings.append(f)

    by_severity: dict = {}
    by_status: dict = {}
    cve_counts: dict = {}
    for f in all_findings:
        sev = f.get("severity", "info")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        st = f.get("status", "unvalidated")
        by_status[st] = by_status.get(st, 0) + 1
        cve = f.get("cve", "").strip()
        if cve:
            cve_counts[cve] = cve_counts.get(cve, 0) + 1

    # Recent 10 findings (by updated timestamp)
    recent_findings = sorted(
        all_findings, key=lambda x: x.get("updated", ""), reverse=True
    )[:10]

    # Build activity timeline from case modified + finding updates
    activity = []
    for c in cases:
        modified = c.get("modified", c.get("created", ""))
        if modified:
            activity.append({
                "ts": modified,
                "type": "case_update",
                "case_id": c.get("case_id", ""),
                "client": c.get("client", ""),
                "status": c.get("status", ""),
                "detail": f"Case {c.get('case_id', '')} updated",
            })
    for f in recent_findings:
        activity.append({
            "ts": f.get("updated", f.get("created", "")),
            "type": "finding",
            "case_id": f.get("_case_id", ""),
            "client": f.get("_case_title", ""),
            "severity": f.get("severity", ""),
            "detail": f.get("title", ""),
        })
    activity.sort(key=lambda x: x.get("ts", ""), reverse=True)

    return jsonify({
        "cases": {
            "total": len(cases),
            "by_status": cases_by_status,
            "by_type": cases_by_type,
            "list": cases_list,
        },
        "findings": {
            "total": len(all_findings),
            "by_severity": by_severity,
            "by_status": by_status,
            "recent": recent_findings,
        },
        "top_cves": dict(sorted(cve_counts.items(), key=lambda x: -x[1])[:10]),
        "recent_activity": activity[:20],
    })


@app.route("/api/dashboard/layout", methods=["GET"])
@require_api_key
def api_dashboard_layout_get():
    return jsonify({"widgets": _load_dashboard_layout()})


@app.route("/api/dashboard/layout", methods=["POST"])
@require_api_key
@csrf_required
def api_dashboard_layout_save():
    data = request.json or {}
    widgets = data.get("widgets", [])
    _save_dashboard_layout(widgets)
    return jsonify({"status": "saved"})


# ---------------------------------------------------------------------------
# Loot Database
# ---------------------------------------------------------------------------

_LOOT = None

def _get_loot_db():
    global _LOOT
    if _LOOT is None:
        from modules.tool_wrappers import LootDB
        from modules.constants import CC_DIR
        _LOOT = LootDB(CC_DIR / "loot.db")
    return _LOOT


@app.route("/loot")
@require_api_key_html
def loot_page():
    return render_template("loot.html", config=DASHBOARD_CONFIG)


@app.route("/api/loot")
@require_api_key
def api_loot_list():
    q = request.args.get("q", "")
    if q:
        results = _get_loot_db().search(q)
        return jsonify(results)
    creds = _get_loot_db().list_credentials(limit=200)
    return jsonify({"credentials": creds})


@app.route("/api/loot", methods=["POST"])
@require_api_key
@csrf_required
def api_loot_add():
    data = request.json or {}
    source = data.get("source", "").strip()
    target = data.get("target", "").strip()
    username = data.get("username", "").strip()
    if not source or not target or not username:
        return jsonify({"error": "source, target, username required"}), 400
    db = _get_loot_db()
    cid = db.add_credential(
        source=source, target=target, username=username,
        password=data.get("password", ""),
        hash=data.get("hash", ""), hash_type=data.get("hash_type", ""),
        domain=data.get("domain", ""), protocol=data.get("protocol", ""),
        port=int(data["port"]) if data.get("port") else 0,
        notes=data.get("notes", ""),
    )
    return jsonify({"status": "ok", "id": cid}), 201


@app.route("/api/loot/<int:cred_id>", methods=["DELETE"])
@require_api_key
@csrf_required
def api_loot_delete(cred_id: int):
    db = _get_loot_db()
    conn = db._conn
    cur = conn.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
    conn.commit()
    if cur.rowcount == 0:
        return jsonify({"error": "Credential not found"}), 404
    return jsonify({"status": "deleted"})


@app.route("/api/loot/<int:cred_id>", methods=["PUT"])
@require_api_key
@csrf_required
def api_loot_update(cred_id: int):
    """Update a single field on a loot credential (inline editing)."""
    data = request.get_json(silent=True) or {}
    field = data.get("field")
    value = data.get("value")
    if not field or field not in ("source", "target", "username", "password", "hash", "hash_type", "protocol", "port", "domain", "notes"):
        return jsonify({"error": "Invalid field"}), 400
    db = _get_loot_db()
    conn = db._conn
    if field == "port":
        try:
            value = int(value) if value else None
        except (ValueError, TypeError):
            return jsonify({"error": "Port must be an integer"}), 400
    cur = conn.execute(f"UPDATE credentials SET {field} = ? WHERE id = ?", (value, cred_id))
    conn.commit()
    if cur.rowcount == 0:
        return jsonify({"error": "Credential not found"}), 404
    return jsonify({"status": "updated"})


@app.route("/api/loot/tokens")
@require_api_key
def api_loot_tokens():
    db = _get_loot_db()
    rows = db._conn.execute(
        "SELECT * FROM tokens ORDER BY discovered DESC LIMIT 200"
    ).fetchall()
    return jsonify([dict(zip(["id","source","token_type","token_value","target","expires","notes","discovered"], r)) for r in rows])


@app.route("/api/loot/tokens", methods=["POST"])
@require_api_key
@csrf_required
def api_loot_token_add():
    data = request.json or {}
    source = data.get("source", "").strip()
    token_type = data.get("token_type", "").strip()
    token_value = data.get("token_value", "").strip()
    if not source or not token_type or not token_value:
        return jsonify({"error": "source, token_type, token_value required"}), 400
    db = _get_loot_db()
    tid = db.add_token(
        source=source, token_type=token_type, token_value=token_value,
        target=data.get("target", ""), expires=data.get("expires", ""),
        notes=data.get("notes", ""),
    )
    return jsonify({"status": "ok", "id": tid}), 201


@app.route("/api/loot/tokens/<int:token_id>", methods=["DELETE"])
@require_api_key
@csrf_required
def api_loot_token_delete(token_id: int):
    db = _get_loot_db()
    cur = db._conn.execute("DELETE FROM tokens WHERE id = ?", (token_id,))
    db._conn.commit()
    if cur.rowcount == 0:
        return jsonify({"error": "Token not found"}), 404
    return jsonify({"status": "deleted"})


@app.route("/api/loot/sessions")
@require_api_key
def api_loot_sessions():
    db = _get_loot_db()
    rows = db._conn.execute(
        "SELECT * FROM sessions ORDER BY discovered DESC LIMIT 200"
    ).fetchall()
    return jsonify([dict(zip(["id","source","session_id","target","protocol","data","discovered"], r)) for r in rows])


@app.route("/api/loot/sessions", methods=["POST"])
@require_api_key
@csrf_required
def api_loot_session_add():
    data = request.json or {}
    source = data.get("source", "").strip()
    session_id = data.get("session_id", "").strip()
    if not source or not session_id:
        return jsonify({"error": "source, session_id required"}), 400
    db = _get_loot_db()
    sid = db.add_session(
        source=source, session_id=session_id,
        target=data.get("target", ""), protocol=data.get("protocol", ""),
        data=data.get("data", ""),
    )
    return jsonify({"status": "ok", "id": sid}), 201


@app.route("/api/loot/sessions/<int:sid>", methods=["DELETE"])
@require_api_key
@csrf_required
def api_loot_session_delete(sid: int):
    db = _get_loot_db()
    cur = db._conn.execute("DELETE FROM sessions WHERE id = ?", (sid,))
    db._conn.commit()
    if cur.rowcount == 0:
        return jsonify({"error": "Session not found"}), 404
    return jsonify({"status": "deleted"})


# ---------------------------------------------------------------------------
# API Documentation
# ---------------------------------------------------------------------------
@app.route("/docs")
@require_api_key_html
def docs_page():
    return render_template("docs.html", config=DASHBOARD_CONFIG)


@app.route("/api/routes")
@require_api_key
def api_routes():
    """Return all registered API routes grouped by category for documentation."""
    import re as _re
    skip_patterns = _re.compile(r"^(/static/|/cases/)")
    groups = {}
    for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
        path = rule.rule
        if skip_patterns.match(path) or path == "/api/routes":
            continue
        endpoint = rule.endpoint
        methods = sorted(m for m in rule.methods if m not in ("HEAD", "OPTIONS"))
        if not methods:
            continue
        # Get docstring from view function
        fn = app.view_functions.get(endpoint)
        doc = (fn.__doc__ or "").strip().split("\n")[0] if fn else ""
        is_api = path.startswith("/api/")
        # Derive category from path
        parts = [p for p in path.split("/") if p]
        if is_api and len(parts) >= 2:
            cat = parts[1].capitalize()
        elif not is_api and parts:
            cat = "Pages"
        else:
            cat = "Other"
        groups.setdefault(cat, []).append({
            "path": path,
            "methods": methods,
            "description": doc[:120],
        })
    # Sort categories
    result = []
    for cat in sorted(groups, key=lambda c: (c != "Pages", c)):
        result.append({"category": cat, "routes": groups[cat]})
    return jsonify(result)


# ---------------------------------------------------------------------------
# MCP Resources — browse and read MCP resources from the web UI
# ---------------------------------------------------------------------------

_RESOURCE_CATALOG = [
    {"uri": "cc://cases/list", "title": "Case List", "description": "All cases with status, type, creation date", "category": "Cases"},
    {"uri": "cc://cases/{case_id}", "title": "Case Detail", "description": "Full case info including findings summary, scope, tasks, and file sizes", "category": "Cases"},
    {"uri": "cc://cases/{case_id}/findings", "title": "Case Findings", "description": "All structured findings for a case", "category": "Cases"},
    {"uri": "cc://cases/{case_id}/notes", "title": "Case Notes", "description": "All case notes with timestamps and tags", "category": "Cases"},
    {"uri": "cc://cases/{case_id}/scope", "title": "Case Scope", "description": "In-scope and out-of-scope targets", "category": "Cases"},
    {"uri": "cc://cases/{case_id}/tasks", "title": "Case Tasks", "description": "Task checklist with completion status and priority", "category": "Cases"},
    {"uri": "cc://cases/{case_id}/runbook/log", "title": "Runbook Execution Log", "description": "Runbook/playbook execution results", "category": "Cases"},
    {"uri": "cc://flashcards", "title": "Flashcard Deck List", "description": "All available flashcard decks with card counts", "category": "Flashcards"},
    {"uri": "cc://flashcards/{name}", "title": "Flashcard Deck Detail", "description": "Full flashcard deck with all questions and answers", "category": "Flashcards"},
    {"uri": "cc://playbooks", "title": "Playbook List", "description": "All available YAML playbooks/runbooks", "category": "Playbooks"},
    {"uri": "cc://prompts", "title": "Prompt Template List", "description": "All available AI prompt templates", "category": "Prompts"},
    {"uri": "cc://findings/stats", "title": "Findings Statistics", "description": "Aggregated findings statistics across all cases", "category": "Findings"},
    {"uri": "cc://loot/credentials", "title": "Loot Credentials", "description": "All captured credentials in the loot database", "category": "Loot"},
    {"uri": "cc://loot/tokens", "title": "Loot Tokens", "description": "All captured tokens in the loot database", "category": "Loot"},
    {"uri": "cc://loot/sessions", "title": "Loot Sessions", "description": "All captured sessions in the loot database", "category": "Loot"},
]


@app.route("/mcp-resources")
@require_api_key_html
def mcp_resources_page():
    return render_template("mcp_resources.html", config=DASHBOARD_CONFIG)


@app.route("/api/mcp/resources")
@require_api_key
def api_mcp_resources_list():
    return jsonify(_RESOURCE_CATALOG)


@app.route("/api/mcp/resources/read", methods=["POST"])
@require_api_key
def api_mcp_resources_read():
    uri = (request.json or {}).get("uri", "")
    if not uri:
        return jsonify({"error": "uri parameter required"}), 400
    try:
        content = _read_mcp_resource(uri)
        return jsonify({"uri": uri, "content": content})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _read_mcp_resource(uri: str) -> str:
    """Read an MCP resource by URI — shared logic with cc_mcp_server.py."""
    import yaml
    from modules.case_manager import CaseManager
    from modules.constants import CASES_DIR, CC_DIR
    from modules.findings_db import FindingsDB
    from modules.tool_wrappers import LootDB
    import json as _json

    # Static resources (no parameters)
    static: dict[str, str] = {
        "cc://cases/list": lambda: _json.dumps(
            CaseManager().list_cases(), indent=2, default=str
        ),
        "cc://flashcards": lambda: _json.dumps([
            {"id": f.stem, "title": (yaml.safe_load(f.read_text()) or {}).get("title", f.stem),
             "description": (yaml.safe_load(f.read_text()) or {}).get("description", ""),
             "card_count": len((yaml.safe_load(f.read_text()) or {}).get("cards", []))}
            for f in sorted((CC_DIR / "flashcards").glob("*.yaml"))
            if (CC_DIR / "flashcards").is_dir()
        ], indent=2),
        "cc://playbooks": lambda: _read_mcp_playbooks(),
        "cc://prompts": lambda: _read_mcp_prompts(),
        "cc://findings/stats": lambda: _read_mcp_findings_stats(),
        "cc://loot/credentials": lambda: _read_mcp_loot_credentials(),
        "cc://loot/tokens": lambda: _read_mcp_loot_tokens(),
        "cc://loot/sessions": lambda: _read_mcp_loot_sessions(),
    }

    if uri in static:
        return static[uri]()

    # Template resources (with parameters)
    parts = uri.split("/")
    if uri.startswith("cc://cases/") and len(parts) >= 4:
        case_id = parts[3]
        cm = CaseManager()
        if not cm._manifest_path(case_id).exists():
            raise ValueError(f"Case '{case_id}' not found.")

        if len(parts) == 4:
            return _json.dumps(cm.info(case_id), indent=2, default=str)
        sub = parts[4] if len(parts) > 4 else ""

        if sub == "findings":
            db = FindingsDB(CASES_DIR / case_id)
            return _json.dumps(db._read().get("findings", []), indent=2, default=str)
        elif sub == "notes":
            return _json.dumps(cm.get_notes(case_id), indent=2, default=str)
        elif sub == "scope":
            info = cm.info(case_id)
            scope = info.get("scope", {}) if info else {}
            return _json.dumps(scope, indent=2, default=str)
        elif sub == "tasks":
            info = cm.info(case_id)
            tasks = info.get("tasks", []) if info else []
            return _json.dumps(tasks, indent=2, default=str)
        elif sub == "runbook" and len(parts) >= 6 and parts[5] == "log":
            log_path = cm._case_path(case_id) / "runbook-log.json"
            if not log_path.exists():
                raise ValueError("No runbook log found for this case.")
            return _json.dumps(_json.loads(log_path.read_text()), indent=2, default=str)

    if uri.startswith("cc://flashcards/") and len(parts) >= 4:
        name = parts[3]
        path = CC_DIR / "flashcards" / f"{name}.yaml"
        if not path.is_file():
            raise ValueError(f"Deck '{name}' not found.")
        return _json.dumps(yaml.safe_load(path.read_text()) or {}, indent=2)

    raise ValueError(f"Unknown resource URI: {uri}")


def _read_mcp_playbooks() -> str:
    import yaml
    from modules.playbook_engine import RunbookEngine
    engine = RunbookEngine()
    books = engine.list_runbooks()
    results = []
    for b in sorted(books, key=lambda x: x.name):
        try:
            data = yaml.safe_load(b.read_text()) or {}
            results.append({"name": b.name, "description": (data.get("description") or "")[:120],
                            "step_count": len(data.get("steps", []))})
        except Exception:
            results.append({"name": b.name, "description": "", "step_count": 0})
    import json as _json
    return _json.dumps(results, indent=2)


def _read_mcp_prompts() -> str:
    import yaml
    from modules.constants import CC_DIR
    prompts_dir = CC_DIR / "prompts"
    if not prompts_dir.is_dir():
        return "[]"
    results = []
    for f in sorted(prompts_dir.glob("*.yaml")):
        try:
            data = yaml.safe_load(f.read_text()) or {}
            results.append({"id": f.stem, "title": data.get("title", f.stem),
                            "description": (data.get("description") or "")[:120]})
        except Exception:
            results.append({"id": f.stem, "title": f.stem, "description": ""})
    import json as _json
    return _json.dumps(results, indent=2)


def _read_mcp_findings_stats() -> str:
    from modules.findings_db import FindingsDB
    total = 0
    by_severity = {}
    by_case = {}
    if CASES_DIR.is_dir():
        for case_dir in sorted(CASES_DIR.iterdir()):
            if case_dir.is_dir():
                db = FindingsDB(case_dir)
                data = db._read()
                findings = data.get("findings", [])
                if findings:
                    by_case[case_dir.name] = len(findings)
                    total += len(findings)
                    for f in findings:
                        s = f.get("severity", "unknown")
                        by_severity[s] = by_severity.get(s, 0) + 1
    import json as _json
    return _json.dumps({"total_findings": total, "by_severity": by_severity, "by_case": by_case}, indent=2)


def _read_mcp_loot_credentials() -> str:
    from modules.tool_wrappers import LootDB
    import json as _json
    db = LootDB(CC_DIR / "loot.db")
    try:
        return _json.dumps(db.list_credentials(limit=999), indent=2, default=str)
    finally:
        db.close()


def _read_mcp_loot_tokens() -> str:
    from modules.tool_wrappers import LootDB
    import json as _json
    db = LootDB(CC_DIR / "loot.db")
    try:
        rows = db._conn.execute("SELECT * FROM tokens ORDER BY discovered DESC").fetchall()
        results = [dict(zip(["id","source","token_type","token_value","target","expires","notes","discovered"], r)) for r in rows]
        return _json.dumps(results, indent=2, default=str)
    finally:
        db.close()


def _read_mcp_loot_sessions() -> str:
    from modules.tool_wrappers import LootDB
    import json as _json
    db = LootDB(CC_DIR / "loot.db")
    try:
        rows = db._conn.execute("SELECT * FROM sessions ORDER BY discovered DESC").fetchall()
        results = [dict(zip(["id","source","session_id","target","protocol","data","discovered"], r)) for r in rows]
        return _json.dumps(results, indent=2, default=str)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Burp Suite Pro — Web Dashboard
# ---------------------------------------------------------------------------

def _burp_client():
    from modules.burp_client import BurpClient
    return BurpClient(
        api_url=DASHBOARD_CONFIG["burp_api_url"],
        api_key=DASHBOARD_CONFIG["burp_api_key"],
    )

@app.route("/burp")
@require_api_key_html
def burp_dashboard():
    return render_template("burp_dashboard.html", config=DASHBOARD_CONFIG)

@app.route("/burp/scans")
@require_api_key_html
def burp_scans():
    return render_template("burp_scans.html", config=DASHBOARD_CONFIG)

@app.route("/burp/settings")
@require_api_key_html
def burp_settings():
    return render_template("burp_settings.html", config=DASHBOARD_CONFIG)

# --- API endpoints ---

@app.route("/api/burp/health")
@require_api_key
def api_burp_health():
    bc = _burp_client()
    h = bc.health()
    v = bc.versions()
    return jsonify({
        "health": h,
        "versions": v,
        "connected": "status" not in h or h.get("status") == "ok",
    })

@app.route("/api/burp/scans/<scan_id>")
@require_api_key
def api_burp_scan_detail(scan_id: str):
    bc = _burp_client()
    status = bc.scan_status(scan_id)
    issues = bc.issues_list(scan_id)
    return jsonify({"status": status, "issues": issues})

@app.route("/api/burp/scan/start", methods=["POST"])
@require_api_key
@csrf_required
def api_burp_scan_start():
    data = request.get_json(force=True) or {}
    urls = data.get("urls", [])
    if isinstance(urls, str):
        urls = [u.strip() for u in urls.split(",") if u.strip()]
    if not urls:
        return jsonify({"error": "No URLs provided"}), 400
    bc = _burp_client()
    r = bc.scan_start(urls)
    if "error" in r:
        return jsonify({"error": r["error"]}), 500
    return jsonify(r)

@app.route("/api/burp/scan/<scan_id>/stop", methods=["POST"])
@require_api_key
@csrf_required
def api_burp_scan_stop(scan_id: str):
    bc = _burp_client()
    r = bc.scan_stop(scan_id)
    if "error" in r:
        return jsonify({"error": r["error"]}), 500
    return jsonify(r)

@app.route("/api/burp/config")
@require_api_key
def api_burp_config():
    return jsonify({
        "api_url": DASHBOARD_CONFIG["burp_api_url"],
        "api_key": DASHBOARD_CONFIG["burp_api_key"][:8] + "..." if DASHBOARD_CONFIG["burp_api_key"] else "",
        "proxy_url": DASHBOARD_CONFIG["burp_proxy_url"],
    })

@app.route("/api/burp/config", methods=["POST"])
@require_api_key
@csrf_required
def api_burp_config_update():
    data = request.get_json(force=True) or {}
    cfg = load_config()
    if "api_url" in data:
        cfg["burp_api_url"] = data["api_url"]
        DASHBOARD_CONFIG["burp_api_url"] = data["api_url"]
    if "api_key" in data:
        cfg["burp_api_key"] = data["api_key"]
        DASHBOARD_CONFIG["burp_api_key"] = data["api_key"]
    if "proxy_url" in data:
        cfg["burp_proxy_url"] = data["proxy_url"]
        DASHBOARD_CONFIG["burp_proxy_url"] = data["proxy_url"]
    from modules.constants import CONFIG_FILE
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    return jsonify({"status": "ok"})


# ---------------------------------------------------------------------------
# Debug log viewer
# ---------------------------------------------------------------------------
@app.route("/debug")
@require_api_key_html
def debug_page():
    return render_template("debug.html", config=DASHBOARD_CONFIG)


@app.route("/api/debug/log")
@require_api_key
def api_debug_log():
    """Return recent debug log entries as JSON."""
    level = request.args.get("level", "").upper()
    lines = DEBUG_LOG[:]
    if level:
        lines = [l for l in lines if l[1] == level]
    # Return newest first
    lines.reverse()
    return jsonify({"entries": lines[:200], "total": len(DEBUG_LOG)})


@app.route("/api/debug/flush", methods=["POST"])
@require_api_key
@csrf_required
def api_debug_flush():
    DEBUG_LOG.clear()
    return jsonify({"status": "ok"})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Start WebSocket terminal server
    ws_port = int(os.environ.get("CC_WS_PORT", 5001))
    ws_term = None
    if HAS_WS_TERMINAL:
        ws_term = WSTerminalServer(host="0.0.0.0", port=ws_port)
        ws_term.start()
    else:
        print("WS Terminal: unavailable (pip install websockets)")

    host = DASHBOARD_CONFIG["listen_host"]
    port = DASHBOARD_CONFIG["listen_port"]
    debug = DASHBOARD_CONFIG["debug"]
    print(f"CC Dashboard: http://{host}:{port}  (debug={debug})")
    if HAS_WS_TERMINAL:
        print(f"WS Terminal:  ws://{host}:{ws_port}")
    if API_KEY:
        print("API key auth enabled — pass X-API-Key header")
    try:
        app.run(host=host, port=port, debug=debug)
    finally:
        if ws_term:
            ws_term.stop()
