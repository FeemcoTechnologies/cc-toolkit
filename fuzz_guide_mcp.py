"""AI-guided blackbox fuzzing MCP server.

Exposes a small, token-efficient toolset for coverage-guided fuzzing of
native binaries (ELF/PE) on this host using AFL++ + r2 + angr + gdb.

Register in opencode.json:
{
  "mcp": {
    "fuzz-guide": {
      "type": "local",
      "command": ["python3", "/share/git-repo/Scripts/ai-combined-tools/fuzz_guide_mcp.py"],
      "environment": { "FUZZ_GUIDE_WORKDIR": "/tmp/fuzz_guide_workdir" },
      "enabled": true
    }
  }
}

Tools follow a cheap-first workflow so the AI burns minimal tokens:
  enumerate -> classify (on demand) -> function_list -> input_surface
    -> harness_gen/setup_campaign -> run -> coverage/status -> crash triage
"""

import json
import os
import shlex
import sys
import subprocess

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from mcp.server.fastmcp import FastMCP

from fuzz_guide_modules import classifier, function_analyzer, input_surface
from fuzz_guide_modules import harness_factory, coverage_tracker, crash_analyzer
from fuzz_guide_modules import language_profile, remote_surface
from fuzz_guide_modules import r2util

mcp = FastMCP("Fuzz Guide")

# clear any r2 orphans left behind by a crashed/killed server instance
r2util.sweep_stale_r2()


# ----------------------------------------------------------------------
# Discovery / classification
# ----------------------------------------------------------------------

@mcp.tool()
def fuzz_enumerate(folder: str, max_files: int = 500) -> str:
    """List fuzzable binaries under a folder (ELF/PE/Java/Archive). Cheap.

    Returns path, type, size, and `file` info for each candidate.
    """
    return json.dumps(classifier.enumerate_binaries(folder, max_files), indent=1)[:18000]


@mcp.tool()
def fuzz_classify(path: str) -> str:
    """Deep-classify ONE binary: arch, bits, stripped, mitigations,
    function count. Also stores the result in the workflow tracker.
    """
    r = classifier.classify_binary(path)
    if r.get("exists"):
        coverage_tracker.update_binary_state(
            path,
            classify=r,
            status="classified",
            input_methods=r.get("type", "?"),
        )
    return json.dumps(r, indent=1)[:18000]


# ----------------------------------------------------------------------
# Function analysis
# ----------------------------------------------------------------------

@mcp.tool()
def fuzz_function_list(
    path: str,
    mode: str = "all",
    max_funcs: int = 60,
    filter_str: str = "",
) -> str:
    """List functions in a binary. mode: all|exported|imported|large|entry|calls|net.
    filter_str: case-insensitive substring on name/address.
    """
    r = function_analyzer.list_functions(path, mode, max_funcs, filter_str)
    return json.dumps(r, indent=1)[:18000]


@mcp.tool()
def fuzz_function_detail(path: str, addr: str) -> str:
    """Disassembly + xrefs + arg info for ONE function by address (hex).
    Use with fuzz_angr_trace to decide whether a page of code can be reached.
    """
    r = function_analyzer.get_function_detail(path, addr)
    return json.dumps(r, indent=1)[:18000]


@mcp.tool()
def fuzz_angr_trace(binary_path: str, target: str, max_steps: int = 2000) -> str:
    """Check whether a target instruction address is reachable by symbolic
    execution (angr). Returns path length + constraint count so the AI can
    judge which function is worth fuzzing.
    """
    r = function_analyzer.angr_trace_to(binary_path, target, max_steps)
    return json.dumps(r, indent=1)[:18000]


# ----------------------------------------------------------------------
# Language / remote surface
# ----------------------------------------------------------------------

import importlib as _importlib

_RELOAD_MODULES = [r2util, language_profile, remote_surface, classifier,
                   function_analyzer, input_surface, harness_factory,
                   coverage_tracker, crash_analyzer]
_RELOAD_MTIMES: dict[str, float] = {}


def _ensure_fresh() -> None:
    """Hot-reload tracked modules when their on-disk source changes.

    The tool handlers call module functions lazily, so an importlib.reload in
    dependency order makes every subsequent MCP call pick up the latest code
    without an opencode/server restart.
    """
    dirty = False
    for mod in _RELOAD_MODULES:
        p = getattr(mod, "__file__", None)
        if not p:
            continue
        try:
            mt = os.path.getmtime(p)
        except OSError:
            continue
        if _RELOAD_MTIMES.get(p) != mt:
            _RELOAD_MTIMES[p] = mt
            dirty = True
    if not dirty:
        return
    for mod in (r2util, language_profile, remote_surface, classifier,
                function_analyzer, input_surface, harness_factory,
                coverage_tracker, crash_analyzer):
        try:
            _importlib.reload(mod)
        except Exception:
            pass
        p = getattr(mod, "__file__", None)
        if p:
            try:
                _RELOAD_MTIMES[p] = os.path.getmtime(p)
            except OSError:
                pass


@mcp.tool()
def fuzz_lang_profile(path: str) -> str:
    """Detect the implementation language (Go/Rust/C/C++/C#) of a binary,
    its real entry-point seams (main / runtime.main / lang_start), and what
    symbol index is available. Cheap & bounded — safe on huge binaries.
    """
    _ensure_fresh()
    r = language_profile.detect_language(path)
    coverage_tracker.update_binary_state(
        path,
        language=r.get("language"),
        entry_candidates=r.get("entry_candidates", []),
    )
    return json.dumps(r, indent=1)[:18000]


@mcp.tool()
def fuzz_remote_surface(path: str, max_sinks: int = 16) -> str:
    """Rank REMOTELY-controlled fuzz entry points for a binary: index symbols
    cheaply (incl. .gopclntab name recovery for stripped Go), classify
    network/parser/archive sinks, walk callers upward from the sinks, and emit
    ranked targets + a remote-fuzzability verdict.
    Start here when deciding whether a live service is worth network fuzzing.
    """
    _ensure_fresh()
    r = remote_surface.analyze_remote_surface(path, max_sinks)
    if r.get("remote_fuzzable"):
        coverage_tracker.update_binary_state(path, status="remote_target")
    return json.dumps(r, indent=1)[:18000]


# ----------------------------------------------------------------------
# Input surface
# ----------------------------------------------------------------------

@mcp.tool()
def fuzz_input_surface(path: str) -> str:
    """How does this binary take input? Imports grouped by risk category
    (network/file/stdin/env/registry), input_methods, interesting strings.
    """
    r = input_surface.analyze_input_surface(path)
    coverage_tracker.update_binary_state(
        path,
        input_methods=r.get("input_methods", []),
        network_capable=r.get("network_capable", False),
        fuzzable=r.get("fuzzable", False),
        status="surface_analyzed",
    )
    return json.dumps(r, indent=1)[:18000]


# ----------------------------------------------------------------------
# Harness / campaign setup
# ----------------------------------------------------------------------

@mcp.tool()
def fuzz_harness_gen(
    binary: str,
    input_type: str = "stdin",
    seeds: str = "",
    n_seeds: int = 8,
    timeout_ms: int = 1000,
    args: str = "",
    net_target: str = "127.0.0.1:5555",
) -> str:
    """Build an AFL++ campaign for a target and return the run command.
    input_type: stdin|file|dlopen|net_basic. For file mode put "@@" where the
    filename goes (e.g. lexer @@ ). dlopen builds an exports-first harness
    (readelf-based, no r2). net_basic builds a TCP client driver that connects
    to net_target (host:port) and pumps fuzz bytes — start the target listener
    first, e.g. run it under the driver against 127.0.0.1:5555.
    """
    r = harness_factory.setup_campaign(binary, input_type, seeds, n_seeds, timeout_ms, net_target, args)
    if not r.get("error"):
        coverage_tracker.log_campaign(binary, r)
        coverage_tracker.update_binary_state(binary, status="campaign_ready")
    return json.dumps(r, indent=1)[:18000]


@mcp.tool()
def fuzz_run(
    binary: str,
    input_type: str = "stdin",
    duration_s: int = 60,
    seeds: str = "",
    args: str = "",
    timeout_ms: int = 1000,
    net_target: str = "127.0.0.1:5555",
) -> str:
    """Run a short AFL++ campaign (blocking, duration_s) and return the result
    summary: execs/sec, coverage, crashes found. Use for quick feedback; scale
    up duration for real campaigns. For net_basic the target service must
    already be listening on net_target.
    """
    r = harness_factory.setup_campaign(binary, input_type, seeds, 8, timeout_ms, net_target, args)
    if r.get("error"):
        return json.dumps(r)[:18000]

    cmd = r["run_command"]
    if not cmd:
        return json.dumps({
            "error": "input_type not runnable directly (net_basic/dlopen). "
                     "Use fuzz_harness_gen and run the resulting command/script."
        })[:18000]

    # Build command as a list (shell=False) to avoid injection
    cmd_list = r.get("run_command_list")
    if cmd_list:
        cmd_list = list(cmd_list)
        # insert -V seconds before "--" so AFL exits cleanly and writes fuzzer_stats
        try:
            dd_idx = cmd_list.index("--")
            cmd_list.insert(dd_idx, "-V")
            cmd_list.insert(dd_idx + 1, str(duration_s))
        except ValueError:
            cmd_list += ["-V", str(duration_s)]
    else:
        # Fallback: parse the string command with shlex
        cmd_list = shlex.split(cmd)
        try:
            dd_idx = cmd_list.index("--")
            cmd_list.insert(dd_idx, "-V")
            cmd_list.insert(dd_idx + 1, str(duration_s))
        except ValueError:
            cmd_list += ["-V", str(duration_s)]

    env = {**os.environ, "AFL_SKIP_CPUFREQ": "1",
           "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1"}

    try:
        proc = subprocess.run(
            cmd_list,
            shell=False,
            text=True,
            capture_output=True,
            timeout=duration_s + 15,
            cwd=r["campaign_dir"],
            env=env,
        )
        out_text = (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        out_text = "(afl-fuzz still running; stats below may be partial)"
    except Exception as e:
        return json.dumps({"error": f"run failed: {e}"})[:18000]

    stats = harness_factory.read_fuzzer_stats(r["out_dir"])

    crashes = os.path.join(r["out_dir"], "crashes")
    crash_count = 0
    if os.path.isdir(crashes):
        crash_count = len([x for x in os.listdir(crashes) if x != "README.txt"])

    result = {
        "binary": binary,
        "input_type": input_type,
        "inst_mode": r.get("inst_mode", "?"),
        "campaign_dir": r["campaign_dir"],
        "duration_s": duration_s,
        "stats": {
            "execs_done": stats.get("execs_done"),
            "execs_per_sec": stats.get("execs_per_sec"),
            "paths_total": stats.get("paths_total"),
            "edges_found": stats.get("edges_found") if stats.get("edges_found", "0") != "0" else None,
            "corpus_count": stats.get("corpus_count"),
            "saved_crashes": stats.get("saved_crashes"),
            "last_update": stats.get("last_update"),
        },
        "raw_crash_count": crash_count,
        "coverage_guidance": "yes" if r.get("inst_mode", "").lower() in ("qemu", "frida", "unicorn") else "NO (dumb mode - consider compiling with afl-gcc, building qemu-mode, or using fuzz_harness_gen for .so)",
        "afl_excerpt": out_text[-700:],
        "next": "call fuzz_crash_analyze on crash files, or fuzz_workflow_status",
    }
    coverage_tracker.log_campaign(binary, {"out": r["out_dir"], "duration_s": duration_s, **result.get("stats", {})})
    return json.dumps(result, indent=1)[:18000]


# ----------------------------------------------------------------------
# Coverage / workflow tracking
# ----------------------------------------------------------------------

@mcp.tool()
def fuzz_coverage(binary: str) -> str:
    """Read current coverage/exec stats for a binary's latest campaign."""
    state = coverage_tracker.get_binary_state(binary)
    out = state.get("last_campaign") or state.get("campaigns", [{}])[-1].get("out")
    stats = harness_factory.read_fuzzer_stats(out) if out else {}
    return json.dumps({"binary": binary, "last_campaign": out, "stats": stats}, indent=1)[:18000]


@mcp.tool()
def fuzz_workflow_status(binary: str = "") -> str:
    """One-call status of the fuzzing workflow for a binary (or all tracked
    binaries if binary is empty). Use this to decide the next step.
    """
    if binary:
        state = coverage_tracker.get_status(binary)
        summarized = {
            "binary": binary,
            "status": state.get("status", "new"),
            "classify": {k: state.get("classify", {}).get(k) for k in ("type", "arch", "bits", "stripped", "num_functions")},
            "input_methods": state.get("input_methods"),
            "times_run": state.get("times_run", 0),
            "last_campaign": state.get("last_campaign"),
            "notes": state.get("notes", ""),
        }
        return json.dumps(summarized, indent=1)[:8000]

    return json.dumps(coverage_tracker.list_tracked_binaries(), indent=1)[:12000]


@mcp.tool()
def fuzz_note(binary: str, note: str) -> str:
    """Attach a short note to a binary's workflow state (keep it concise)."""
    coverage_tracker.update_binary_state(binary, notes=note)
    return json.dumps({"binary": binary, "note": note})[:2000]


# ----------------------------------------------------------------------
# Crash triage
# ----------------------------------------------------------------------

@mcp.tool()
def fuzz_crash_analyze(
    binary: str,
    crash_file: str = "",
    crash_dir: str = "",
    args: str = "",
) -> str:
    """Triage crash(es) with GDB: signal, faulting instruction, registers,
    backtrace. Provide crash_file (single) or crash_dir (batch).
    """
    if crash_dir:
        r = crash_analyzer.analyze_corpus(binary, crash_dir, args)
    else:
        r = crash_analyzer.analyze_crash(binary, crash_file, args)
    return json.dumps(r, indent=1)[:18000]


# ----------------------------------------------------------------------
# main
# ----------------------------------------------------------------------

def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()