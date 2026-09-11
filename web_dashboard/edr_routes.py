"""EDR Dashboard Integration — Flask Blueprint for the Kali web dashboard.

Provides 4 sub-pages: Agent List, Agent Detail, Alert Browser, and Threat Hunt.
Talks to the EDR server API (configurable via EDR_SERVER_URL env var).

To register this blueprint in app.py, add:
    from web_dashboard.edr_routes import edr_bp
    app.register_blueprint(edr_bp, url_prefix="/edr")
"""

import json
import os
import secrets
import urllib.error
import urllib.parse
import urllib.request
from functools import wraps

from flask import (
    Blueprint,
    redirect,
    render_template,
    request,
    jsonify,
    session,
    url_for,
)

edr_bp = Blueprint("edr", __name__, template_folder="templates")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
EDR_SERVER_URL = os.environ.get("EDR_SERVER_URL", "http://127.0.0.1:8900")
EDR_ADMIN_API_KEY = os.environ.get("EDR_ADMIN_API_KEY", "")


# ---------------------------------------------------------------------------
# Auth helpers — mirror app.py's _check_auth pattern
# ---------------------------------------------------------------------------
def _dashboard_check_auth():
    """Check session login OR API key header (same as app.py)."""
    if not EDR_ADMIN_API_KEY:
        return True
    if session.get("_authed"):
        return True
    key = request.headers.get("X-API-Key", "")
    if EDR_ADMIN_API_KEY and secrets.compare_digest(key, EDR_ADMIN_API_KEY):
        return True
    csrf_hdr = request.headers.get("X-CSRF-Token", "")
    sess_token = session.get("_csrf_token", "")
    if csrf_hdr and sess_token and secrets.compare_digest(csrf_hdr, sess_token):
        return True
    return False


def _require_auth(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not _dashboard_check_auth():
            return redirect(url_for("login", next=request.path))
        return f(*a, **kw)
    return wrapper


def _require_auth_json(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not _dashboard_check_auth():
            return jsonify({"error": "Unauthorized"}), 401
        return f(*a, **kw)
    return wrapper


# ---------------------------------------------------------------------------
# EDR Server API helpers
# ---------------------------------------------------------------------------
def _api_get(path, params=None):
    """Make authenticated GET to EDR server API."""
    url = f"{EDR_SERVER_URL.rstrip('/')}{path}"
    if params:
        url += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    headers = {"Accept": "application/json"}
    if EDR_ADMIN_API_KEY:
        headers["X-API-Key"] = EDR_ADMIN_API_KEY
    try:
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:500]
        return {"error": f"EDR server returned {e.code}: {body}"}
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        return {"error": f"EDR server unreachable: {e}"}
    except Exception as e:
        return {"error": str(e)}


def _api_post(path, data=None):
    """Make authenticated POST to EDR server API."""
    url = f"{EDR_SERVER_URL.rstrip('/')}{path}"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if EDR_ADMIN_API_KEY:
        headers["X-API-Key"] = EDR_ADMIN_API_KEY
    body = json.dumps(data or {}).encode()
    try:
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode(errors="replace")[:500]
        return {"error": f"EDR server returned {e.code}: {body_text}"}
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        return {"error": f"EDR server unreachable: {e}"}
    except Exception as e:
        return {"error": str(e)}


def _api_put(path, data=None):
    """Make authenticated PUT to EDR server API."""
    url = f"{EDR_SERVER_URL.rstrip('/')}{path}"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if EDR_ADMIN_API_KEY:
        headers["X-API-Key"] = EDR_ADMIN_API_KEY
    body = json.dumps(data or {}).encode()
    try:
        req = urllib.request.Request(url, data=body, headers=headers, method="PUT")
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode(errors="replace")[:500]
        return {"error": f"EDR server returned {e.code}: {body_text}"}
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        return {"error": f"EDR server unreachable: {e}"}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Page routes — Agent List
# ---------------------------------------------------------------------------
@edr_bp.route("/agents")
@_require_auth
def agents_list():
    return render_template("edr/agents.html")


@edr_bp.route("/api/agents")
@_require_auth_json
def api_agents_list():
    """Proxy: fetch agents from EDR server with optional status/os filters."""
    params = {}
    status = request.args.get("status", "").strip()
    os_filter = request.args.get("os", "").strip()
    if status:
        params["status"] = status
    if os_filter:
        params["os"] = os_filter
    return jsonify(_api_get("/api/admin/devices", params or None))


# ---------------------------------------------------------------------------
# Page routes — Agent Detail
# ---------------------------------------------------------------------------
@edr_bp.route("/agents/<uuid>")
@_require_auth
def agent_detail(uuid):
    return render_template("edr/agent_detail.html", agent_uuid=uuid)


@edr_bp.route("/api/agents/<uuid>")
@_require_auth_json
def api_agent_detail(uuid):
    """Fetch single device detail from EDR server."""
    return jsonify(_api_get(f"/api/admin/devices/{uuid}"))


@edr_bp.route("/api/agents/<uuid>/baseline")
@_require_auth_json
def api_agent_baseline(uuid):
    """Fetch baseline status for a device."""
    return jsonify(_api_get(f"/api/admin/devices/{uuid}/baseline"))


@edr_bp.route("/api/agents/<uuid>/alerts")
@_require_auth_json
def api_agent_alerts(uuid):
    """Fetch recent alerts for a device."""
    limit = request.args.get("limit", "20")
    return jsonify(_api_get(f"/api/admin/alerts", {"device_uuid": uuid, "limit": limit}))


@edr_bp.route("/agents/<uuid>/quarantine", methods=["POST"])
@_require_auth_json
def agent_quarantine(uuid):
    """Quarantine a device."""
    return jsonify(_api_post(f"/api/admin/devices/{uuid}/quarantine"))


@edr_bp.route("/agents/<uuid>/unquarantine", methods=["POST"])
@_require_auth_json
def agent_unquarantine(uuid):
    """Unquarantine a device."""
    return jsonify(_api_post(f"/api/admin/devices/{uuid}/unquarantine"))


@edr_bp.route("/agents/<uuid>/config-push", methods=["POST"])
@_require_auth_json
def agent_config_push(uuid):
    """Force config update on a device."""
    return jsonify(_api_post(f"/api/admin/devices/{uuid}/config-push"))


@edr_bp.route("/agents/<uuid>/baseline-reset", methods=["POST"])
@_require_auth_json
def agent_baseline_reset(uuid):
    """Reset baseline for a specific table on a device."""
    data = request.get_json(silent=True) or {}
    table_name = data.get("table_name", "")
    return jsonify(_api_post(f"/api/admin/devices/{uuid}/baseline-reset", {"table_name": table_name}))


# ---------------------------------------------------------------------------
# Page routes — Alert Browser
# ---------------------------------------------------------------------------
@edr_bp.route("/alerts")
@_require_auth
def alerts_list():
    return render_template("edr/alerts.html")


@edr_bp.route("/api/alerts")
@_require_auth_json
def api_alerts_list():
    """Fetch alerts with filters from EDR server."""
    params = {}
    for key in ("severity", "device", "status", "start_date", "end_date",
                "acknowledged", "limit", "offset"):
        val = request.args.get(key, "").strip()
        if val:
            params[key] = val
    return jsonify(_api_get("/api/admin/alerts", params or None))


@edr_bp.route("/alerts/<int:alert_id>")
@_require_auth
def alert_detail(alert_id):
    return render_template("edr/alert_detail.html", alert_id=alert_id)


@edr_bp.route("/api/alerts/<int:alert_id>")
@_require_auth_json
def api_alert_detail(alert_id):
    """Fetch single alert from EDR server."""
    return jsonify(_api_get(f"/api/admin/alerts/{alert_id}"))


@edr_bp.route("/alerts/<int:alert_id>/acknowledge", methods=["POST"])
@_require_auth_json
def alert_acknowledge(alert_id):
    """Acknowledge an alert."""
    return jsonify(_api_post(f"/api/admin/alerts/{alert_id}/acknowledge"))


@edr_bp.route("/alerts/<int:alert_id>/resolve", methods=["POST"])
@_require_auth_json
def alert_resolve(alert_id):
    """Resolve an alert."""
    return jsonify(_api_post(f"/api/admin/alerts/{alert_id}/resolve"))


@edr_bp.route("/alerts/stats")
@_require_auth_json
def alert_stats():
    """Return alert statistics JSON for dashboard charts."""
    return jsonify(_api_get("/api/admin/alerts/stats"))


# ---------------------------------------------------------------------------
# Page routes — Threat Hunt
# ---------------------------------------------------------------------------
@edr_bp.route("/hunt", methods=["GET", "POST"])
@_require_auth
def hunt():
    """Threat hunt page. GET renders the form; POST is not used (client-side AJAX)."""
    return render_template("edr/hunt.html")


@edr_bp.route("/api/hunt", methods=["POST"])
@_require_auth_json
def api_hunt():
    """Execute an osquery SQL query via the EDR server."""
    data = request.get_json(silent=True) or {}
    sql = data.get("sql", "").strip()
    device_uuid = data.get("device_uuid", "").strip()
    if not sql:
        return jsonify({"error": "SQL query required"}), 400
    payload = {"sql": sql}
    if device_uuid:
        payload["device_uuid"] = device_uuid
    return jsonify(_api_post("/api/hunt", payload))


@edr_bp.route("/api/hunt/devices")
@_require_auth_json
def api_hunt_devices():
    """Fetch list of devices for the hunt dropdown."""
    return jsonify(_api_get("/api/admin/devices"))
