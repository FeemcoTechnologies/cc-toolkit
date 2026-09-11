"""Ghidra Headless — dashboard integration (Route B).

Thin read/write surface over the headless Ghidra service so the cc-toolkit
web dashboard can list binaries, inspect fingerprints/reviews, run
version-diffs, and submit new analysis jobs without the GUI.

To register this blueprint in app.py, add:
    from web_dashboard.ghidra_routes import ghidra_bp
    app.register_blueprint(ghidra_bp, url_prefix="/ghidra")
"""

import json
import os
import sys

from flask import Blueprint, jsonify, request

_SVC = os.environ.get("GHIDRA_SERVICE_DIR", "/opt/ghidra/service")
if _SVC not in sys.path:
    sys.path.insert(0, _SVC)

from ghidra_service import GhidraService  # noqa: E402

ghidra_bp = Blueprint("ghidra", __name__)
_ghidra_svc = GhidraService()


def _auth_ok():
    # mirror app.py: session login OR API-key header
    try:
        from flask import session
    except Exception:
        session = None
    if session and session.get("_authed"):
        return True
    dash_secret = os.environ.get("CC_DASHBOARD_KEY", "")
    if dash_secret:
        return request.headers.get("X-API-Key") == dash_secret
    # no API key configured — allow (local/docker dev); production should set CC_DASHBOARD_KEY
    return True


@ghidra_bp.before_request
def _ghidra_auth():
    if not _auth_ok():
        return jsonify({"error": "unauthorized"}), 401


@ghidra_bp.get("/programs")
def ghidra_programs():
    return jsonify(_ghidra_svc.reg.programs(
        family=request.args.get("family", ""),
        project=request.args.get("project", "")))


@ghidra_bp.get("/families")
def ghidra_families():
    return jsonify(_ghidra_svc.reg.family_list())


@ghidra_bp.get("/jobs")
def ghidra_jobs():
    try:
        limit = max(1, min(int(request.args.get("limit", 20)), 200))
    except ValueError:
        limit = 20
    return jsonify(_ghidra_svc.reg.jobs(
        kind=request.args.get("kind", ""),
        status=request.args.get("status", ""),
        limit=limit))


@ghidra_bp.get("/fingerprint")
def ghidra_fingerprint():
    try:
        limit = max(1, min(int(request.args.get("limit", 25)), 1000))
    except ValueError:
        limit = 25
    fp = _ghidra_svc.fingerprint(request.args.get("project", ""),
                                 request.args.get("name", ""))
    if "error" in fp:
        return jsonify(fp), 404
    funcs = fp.pop("functions", [])
    funcs = sorted(funcs, key=lambda f: f.get("size", 0), reverse=True)
    fp["function_total"] = len(funcs)
    fp["functions"] = funcs[:limit]
    return jsonify(fp)


@ghidra_bp.get("/review")
def ghidra_review():
    r = _ghidra_svc.review(request.args.get("project", ""),
                           request.args.get("name", ""))
    if "error" in r:
        return jsonify(r), 404
    return jsonify(r)


@ghidra_bp.get("/diff")
def ghidra_diff():
    d = _ghidra_svc.diff(
        (request.args.get("a_project", ""), request.args.get("a_name", "")),
        (request.args.get("b_project", ""), request.args.get("b_name", "")),
    )
    if "error" in d:
        return jsonify(d), 404
    return jsonify(d)


@ghidra_bp.get("/family")
def ghidra_family_report():
    return jsonify(_ghidra_svc.family_report(request.args.get("family", "")))


@ghidra_bp.post("/submit")
def ghidra_submit():
    body = request.get_json(silent=True) or {}
    try:
        res = _ghidra_svc.submit(
            body.get("kind", "analyze"),
            family=body.get("family", ""),
            version=body.get("version", ""),
            source_path=body.get("source_path", ""),
            project=body.get("project", ""),
            program_name=body.get("name", ""),
            reanalyze=bool(body.get("reanalyze", False)),
        )
        return jsonify(res), 202
    except ValueError as ex:
        return jsonify({"error": str(ex)}), 400