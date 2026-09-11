"""Function enumeration and call-graph analysis via r2pipe + angr."""

import json
import os
import re
import subprocess

from . import r2util


def list_functions(
    path: str,
    mode: str = "all",
    max_funcs: int = 60,
    filter_str: str = "",
) -> list[dict]:
    """Return compact function list for a binary.

    Modes
    -----
    all        every function r2 finds
    exported   only exported symbols
    imported   only imported functions
    large      sorted by code size descending
    entry      first 10 functions (near entry)
    calls      functions sorted by number of cross-references
    net        functions that reference network-related symbols

    Huge binaries (>40MB) skip r2's ``aaa`` (minutes) and use the symtab
    from ``readelf -Ws`` instead; modes that need CFG (calls/net) degrade.
    """
    if r2util.is_huge(path):
        flist = _fast_symtab_functions(path, max_funcs=max_funcs, filter_str=filter_str)
        entry = {
            "note": "size-guard fast path: symtab FUNC symbols only, no CFG",
            "count": len(flist),
            "functions": flist,
        }
        if mode == "imported":
            entry["functions"] = [f for f in flist if f["type"] == "imported"]
        return [entry]

    r2 = _r2_open(path)
    if isinstance(r2, dict):
        return [r2]

    try:
        r2.cmd("aaa")
        funcs = json.loads(r2.cmd("aflj"))
    except Exception as e:
        r2.quit()
        return [{"error": f"aflj failed: {e}"}]

    result = []
    for f in funcs:
        addr = f.get("addr") or f.get("offset", 0)
        name = f.get("name", f"sub_{addr:x}")

        finfo = {}
        try:
            finfo = json.loads(r2.cmd(f"afij @ {addr}"))[0]
        except Exception:
            pass

        result.append(
            {
                "addr": hex(addr),
                "name": name,
                "size": f.get("size", 0),
                "cc": finfo.get("cc", 0),
                "nargs": finfo.get("nargs", 0),
                "nbbs": finfo.get("nbbs", 0),
                "xrefs_to": len(finfo.get("refs", []) if isinstance(finfo.get("refs"), list) else []),
                "type": f.get("type", "unknown"),
            }
        )

    # -- mode filtering --
    if mode == "exported":
        try:
            exports = json.loads(r2.cmd("iEj"))
            exp_addrs = {e.get("vaddr", 0) for e in exports}
            result = [f for f in result if int(f["addr"], 16) in exp_addrs]
        except Exception:
            pass
    elif mode == "imported":
        result = [f for f in result if f["type"] in ("imported", "IMPORT")]
    elif mode == "large":
        result.sort(key=lambda x: x["size"], reverse=True)
    elif mode == "entry":
        result = result[:10]
    elif mode == "calls":
        result.sort(key=lambda x: x["xrefs_to"], reverse=True)
    elif mode == "net":
        net_kw = ("recv", "send", "socket", "connect", "bind", "listen",
                   "accept", "http", "wsa", "inet", "gethostby", "curl")
        result = [f for f in result if any(kw in f["name"].lower() for kw in net_kw)]

    # optional substring filter
    if filter_str:
        fl = filter_str.lower()
        result = [f for f in result if fl in f["name"].lower() or fl in f["addr"]]

    r2.quit()
    return result[:max_funcs]


def get_function_detail(path: str, addr: str) -> dict:
    """Return detailed info for a single function: disassembly, xrefs, args."""
    r2 = _r2_open(path)
    if isinstance(r2, dict):
        return r2

    try:
        r2.cmd("aaa")
        a = int(addr, 16) if addr.startswith("0x") else int(addr, 16)
        finfo = json.loads(r2.cmd(f"afij @ {a}"))[0]
        disasm = r2.cmd(f"pdfj @ {a}")
        dis_json = json.loads(disasm) if disasm else {}
        ops = dis_json.get("ops", [])

        # Compact disassembly: just mnemonic + references
        compact = []
        for op in ops[:80]:
            compact.append(
                f"{op.get('type','?')} {op.get('disasm','')}"
            )

        result = {
            "addr": hex(a),
            "name": finfo.get("name", ""),
            "size": finfo.get("size", 0),
            "nargs": finfo.get("nargs", 0),
            "cc": finfo.get("cc", 0),
            "nbbs": finfo.get("nbbs", 0),
            "xrefs_to": [
                {"from": hex(r.get("addr", 0)), "type": r.get("type", "")}
                for r in (finfo.get("refs", []) or [])[:20]
            ],
            "disasm_preview": compact,
        }
    except Exception as e:
        result = {"addr": addr, "error": str(e)[:200]}
    finally:
        r2.quit()

    return result


def get_exports(path: str) -> list[dict]:
    """Return export symbols (compact)."""
    r2 = _r2_open(path)
    if isinstance(r2, dict):
        return [r2]
    try:
        r2.cmd("aaa")
        exports = json.loads(r2.cmd("iEj"))
        return [
            {"addr": hex(e.get("vaddr", 0)), "name": e.get("name", ""), "type": e.get("type", "")}
            for e in exports[:80]
        ]
    except Exception as e:
        return [{"error": str(e)[:200]}]
    finally:
        r2.quit()


def angr_trace_to(binary_path: str, target: str, max_steps: int = 2000) -> dict:
    """Use angr symbolic execution to check reachability of a target address.

    Returns path length, feasibility, and number of constraints.
    """
    if r2util.is_huge(binary_path):
        return {"error": "angr symbolic execution skipped on >40MB binary "
                         "(prohibitive memory/time). Narrow the target instead."}

    try:
        import angr
    except ImportError:
        return {"error": "angr not installed"}

    try:
        a = int(target, 16) if target.startswith("0x") else int(target, 16)
        proj = angr.Project(binary_path, auto_load_libs=False)
        state = proj.factory.entry_state()
        simgr = proj.factory.simulation_manager(state)

        steps = 0
        found = None
        while steps < max_steps and not found:
            chunk = min(max_steps - steps, 50)
            if chunk <= 0:
                break
            simgr.explore(find=a)
            steps += chunk
            if simgr.found:
                found = simgr.found[0]
            elif not simgr.active:
                break

        if found:
            return {
                "reachable": True,
                "path_length": len(found.history.bbl_addrs),
                "num_constraints": len(found.solver.constraints),
                "steps_used": steps,
            }
        else:
            return {
                "reachable": False,
                "steps_used": steps,
                "note": "No path found within step limit",
            }
    except Exception as e:
        return {"error": str(e)[:300]}


# ------------------------------------------------------------------
# helpers
# ------------------------------------------------------------------

def _r2_open(path: str):
    """Open a binary with r2pipe (watchdog-bounded); return dict on error."""
    try:
        return r2util.open_r2(path)
    except Exception as e:
        return {"error": f"r2 open failed: {e}"}


def _fast_symtab_functions(path: str, max_funcs: int = 60, filter_str: str = "") -> list[dict]:
    """List FUNC symbols from the ELF symtab without any analysis (huge binaries)."""
    funcs = []
    try:
        out = subprocess.check_output(
            ["readelf", "-Ws", path], text=True, timeout=12, stderr=subprocess.DEVNULL)
    except Exception:
        return [{"error": "readelf -Ws failed"}]

    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[2] == "FUNC":
            try:
                addr = int(parts[1], 16)
            except Exception:
                continue
            name = parts[-1]
            if filter_str and filter_str.lower() not in name.lower():
                continue
            typ = "imported" if parts[4] == "UND" else "local" if parts[3] == "LOCAL" else "global"
            funcs.append({
                "addr": hex(addr),
                "name": name.split("@")[0],
                "size": int(parts[5], 16) if parts[5].startswith(("0x", "0X")) else 0,
                "type": typ,
                "nargs": 0,
                "note": "symtab (no CFG)",
            })
            if len(funcs) >= max_funcs:
                break
    return funcs[:max_funcs]
