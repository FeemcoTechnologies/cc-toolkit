"""Headless Ghidra service MCP server (Route B).

Leans on the supported Ghidra 11.3.2 headless Jython engine behind a
Python job queue + SQLite registry. Lets opencode/cc-toolkit:
  - submit import+analysis of any binary (stored as a Ghidra project)
  - fingerprint a program (per-function byte/mnemonic hashes)
  - get a structured review (sections/imports/exports/functions/strings/decomp)
  - diff two saved programs (identical / changed / moved / added / removed)
  - track versions across a driver family over time

Register in opencode.json:
{
  "mcp": {
    "ghidra": {
      "type": "local",
      "command": ["python3", "./ghidra_mcp.py"],
      "environment": {
        "GHIDRA_SERVICE_DIR": "/opt/ghidra/service"
      },
      "enabled": true
    }
  }
}
"""

import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
_SVC = os.environ.get("GHIDRA_SERVICE_DIR", "/opt/ghidra/service")
if _SVC not in sys.path:
    sys.path.insert(0, _SVC)

from mcp.server.fastmcp import FastMCP

_HAS_GHIDRA = False
_build_program_key = None
try:
    from ghidra_service import GhidraService, build_program_key
    _HAS_GHIDRA = True
    _build_program_key = build_program_key
except Exception:
    pass

mcp = FastMCP("Ghidra Headless")

SVC = None
if _HAS_GHIDRA:
    SVC = GhidraService()

    # reset crashes: any job left 'running' by a dead MCP process is stale
    try:
        for j in SVC.reg.jobs(status="running"):
            SVC.reg.add_job(j["kind"], j["payload"], program_id=j["program_id"])
            SVC.reg.db.execute("UPDATE jobs SET status='failed', error='stale after restart'"
                               " WHERE id=?", (j["id"],))
        SVC.reg.db.commit()
    except Exception:
        pass


def _ghidra_unavailable() -> str:
    return json.dumps({
        "error": "Ghidra service not available",
        "hint": ("Set GHIDRA_SERVICE_DIR to the directory containing "
                 "ghidra_service.py and ensure it is importable. "
                 f"Current value: {_SVC}"),
    })


def _p(a, b):
    """(project, name) tuple for the service API."""
    return (a, b)


@mcp.tool()
def ghidra_submit_analyze(source_path: str, family: str = "", version: str = "",
                          project: str = "", reanalyze: bool = False) -> str:
    """Import a binary into a Ghidra project, run full analysis, fingerprint
    every function, and produce a review JSON. Returns a job id (poll with
    ghidra_job_status). family/version default to path heuristics."""
    if not SVC:
        return _ghidra_unavailable()
    return json.dumps(SVC.submit("analyze", family=family, version=version,
                                 source_path=source_path, project=project,
                                 reanalyze=reanalyze))


@mcp.tool()
def ghidra_submit_fingerprint(project: str, name: str) -> str:
    """(Re)compute fingerprints for an already-registered program."""
    if not SVC:
        return _ghidra_unavailable()
    return json.dumps(SVC.submit("fingerprint", project=project,
                                 program_name=name))


@mcp.tool()
def ghidra_submit_review(project: str, name: str) -> str:
    """(Re)generate the structured review for an already-registered program."""
    if not SVC:
        return _ghidra_unavailable()
    return json.dumps(SVC.submit("review", project=project, program_name=name))


@mcp.tool()
def ghidra_job_status(job_id: int) -> str:
    """Status of a submitted job: queued/running/done/failed + details."""
    if not SVC:
        return _ghidra_unavailable()
    return json.dumps(SVC.reg.job(job_id))


@mcp.tool()
def ghidra_jobs(kind: str = "", status: str = "", limit: int = 20) -> str:
    """List recent jobs (filter by kind=analyze/fingerprint/review, status)."""
    if not SVC:
        return _ghidra_unavailable()
    return json.dumps(SVC.reg.jobs(kind=kind, status=status, limit=min(limit, 100)))


@mcp.tool()
def ghidra_programs(family: str = "", project: str = "") -> str:
    """List registered programs in the headless project store."""
    if not SVC:
        return _ghidra_unavailable()
    return json.dumps(SVC.reg.programs(family=family, project=project))


@mcp.tool()
def ghidra_families() -> str:
    """List families (grouping key for version-diff tracking) with counts."""
    if not SVC:
        return _ghidra_unavailable()
    return json.dumps(SVC.reg.family_list())


@mcp.tool()
def ghidra_seed(project: str, name: str, family: str = "", version: str = "",
                source_path: str = "") -> str:
    """Register an existing program in a Ghidra project so fingerprint/review
    jobs can run against it without re-importing."""
    if not SVC:
        return _ghidra_unavailable()
    pid = SVC.reg.seed_program(project, name, family=family, version=version,
                               source_path=source_path)
    return json.dumps({"program_id": pid,
                       "program_key": build_program_key(project, name)})


@mcp.tool()
def ghidra_fingerprint(project: str, name: str, limit: int = 25) -> str:
    """Fingerprint record for a program (per-function hashes). Returns summary
    + first `limit` functions. Use limit=-1 for everything."""
    if not SVC:
        return _ghidra_unavailable()
    fp = SVC.fingerprint(project, name)
    if "error" in fp:
        return json.dumps(fp)
    n = len(fp.get("functions", []))
    out = {k: v for k, v in fp.items() if k != "functions"}
    funcs = sorted(fp.get("functions", []), key=lambda f: f.get("size", 0),
                   reverse=True)
    out["function_total"] = n
    out["sample"] = funcs[:limit] if limit >= 0 else funcs
    return json.dumps(out)


@mcp.tool()
def ghidra_review(project: str, name: str) -> str:
    """Structured review of an analyzed program: sections, imports, exports,
    functions (by size), strings, optional decompilation."""
    if not SVC:
        return _ghidra_unavailable()
    return json.dumps(SVC.review(project, name))


@mcp.tool()
def ghidra_diff(project_a: str, name_a: str,
                project_b: str, name_b: str) -> str:
    """Diff two fingerprinted programs. Categories: identical / changed /
    moved / added / removed + similarity score + samples."""
    if not SVC:
        return _ghidra_unavailable()
    return json.dumps(SVC.diff(_p(project_a, name_a), _p(project_b, name_b)))


@mcp.tool()
def ghidra_family_report(family: str) -> str:
    """Version-tracking report across all registered versions of a family,
    with pairwise change summaries between consecutive versions."""
    if not SVC:
        return _ghidra_unavailable()
    return json.dumps(SVC.family_report(family))


if __name__ == "__main__":
    mcp.run()