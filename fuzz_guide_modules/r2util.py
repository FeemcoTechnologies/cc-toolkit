"""Shared radare2 helpers: hard time budgets + fast non-r2 fallback for huge binaries.

Design notes
------------
- radare2 is pathologically slow on very large binaries (e.g. 142MB apps): even
  ``ij`` takes ~45s and ``aaa`` minutes, because rabin2 walks strings/relocs.
  We therefore refuse to run r2 on files above ``SIZE_GUARD`` and fall back to
  cheap ``readelf``/``file`` parsing instead.
- When r2 *is* used, a watchdog thread kills every radare2 process pointing at
  the binary after ``budget_s`` seconds, so a timed-out MCP request never leaves
  an orphaned r2 hogging CPU/RAM (see ``kill_r2_for`` / ``open_r2``).
"""

import json
import os
import re
import subprocess
import threading
import time

SIZE_GUARD = 40 * 1024 * 1024  # 40 MB
_DEFAULT_BUDGET = 75  # seconds for a full r2 session


def is_huge(path: str) -> bool:
    try:
        return os.path.getsize(path) > SIZE_GUARD
    except Exception:
        return False


# ------------------------------------------------------------------.
# fast non-r2 path (readelf/file) for huge binaries
# ------------------------------------------------------------------
def fast_elf_info(path: str) -> dict:
    """Cheap ELF info for huge binaries where r2 is unusable.

    Uses file + readelf only.  Function count comes from the symtab
    (``readelf -Ws``) and is capped at a small number of FUNC entries to
    keep the pipe fast; DO NOT trust it as exhaustive on stripped files.
    """
    info: dict = {"fast_path": True}
    try:
        out = subprocess.check_output(["file", path], text=True, timeout=5).strip()
        info["file_info"] = out
    except Exception:
        info["file_info"] = "unknown"

    low = info["file_info"].lower()
    info["type"] = "ELF" if "elf" in low else ("PE" if ("pe32" in low or "pe64" in low) else "Unknown")
    info["arch"] = "x86" if " x86-64 " in low or "intel 80386" in low else (
        "arm" if " arm " in low or "aarch64" in low else "?")
    info["bits"] = 64 if ("64-bit" in low or "aarch64" in low) else (
        32 if "32-bit" in low else 0)
    info["stripped"] = "not stripped" not in low
    info["endian"] = "little" if "little endian" in low else (
        "big" if "big endian" in low else "?")
    info["entry"] = "?"

    try:
        h = subprocess.check_output(
            ["readelf", "-h", path], text=True, timeout=10, stderr=subprocess.DEVNULL)
        m = re.search(r"^  Entry point address:\s+(0x[0-9a-fA-F]+)", h, re.M)
        if m:
            info["entry"] = m.group(1)
        info["type"] = ("PIE/DYN" if "DYN" in (
            re.search(r"^  Type:\s+(\S+)", h, re.M).group(1) if re.search(
                r"^  Type:\s+(\S+)", h, re.M) else "") else info["type"])
    except Exception:
        pass

    # mitigation-ish hints for _sections that readelf exposes without heavy work
    try:
        s = subprocess.check_output(
            ["readelf", "-lW", path], text=True, timeout=10, stderr=subprocess.DEVNULL)
        info["nx"] = "GNU_STACK" not in s or " RW " not in s
        # GNU_RELRO present -> partial/full relro likely
        info["relro"] = "GNU_RELRO" in s and "relro"
    except Exception:
        info["nx"], info["relro"] = None, None

    # capped FUNC count from symtab
    try:
        out = subprocess.check_output(
            ["readelf", "-Ws", path], text=True, timeout=12, stderr=subprocess.DEVNULL)
        funcs = 0
        for line in out.splitlines():
            # Num: Value Size Type Bind Vis Ndx Name
            if " FUNC " in line and line.split()[0].rstrip(":").isdigit():
                funcs += 1
        info["num_functions"] = funcs
    except Exception:
        info["num_functions"] = None

    info["sections"] = []
    info["note"] = (
        "Huge binary: r2 deep analysis skipped (size guard). Use readelf/objdump or "
        "targeted fuzz_function_detail on small addresses if really needed."
    )
    return info


# ------------------------------------------------------------------.
# watchdog r2 wrapper
# ------------------------------------------------------------------
def _arg_refs(args: list[str], path: str) -> bool:
    """True when *path* appears as a WHOLE argv element (or as the same file
    after realpath). Substring matches are intentionally rejected so shared
    path prefixes never cause another session to be misidentified."""
    if path in args:
        return True
    try:
        canon = os.path.realpath(path)
    except OSError:
        return False
    for a in args:
        if a.startswith(("/", "~", os.path.expanduser("~"))):
            try:
                if os.path.realpath(a) == canon:
                    return True
            except OSError:
                continue
    return False


def _r2_procs_for(path: str) -> list[int]:
    """Find PIDs of radare2 processes whose argv references *path* (exact match)."""
    pids = []
    if os.name != "posix" or not os.path.isdir("/proc"):
        return pids  # /proc scan is Linux-specific; nothing we can watch elsewhere
    try:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            cmdline_f = f"/proc/{entry}/cmdline"
            try:
                with open(cmdline_f, "rb") as f:
                    raw = f.read()
                args = [a.decode("utf-8", "replace") for a in raw.split(b"\x00") if a]
                if not args:
                    continue
                if not os.path.basename(args[0]).startswith("radare2"):
                    continue
                if _arg_refs(args, path):
                    pids.append(int(entry))
            except (IOError, ValueError, PermissionError, OSError):
                continue
    except Exception:
        pass
    return pids


def kill_r2_for(path: str, sig: int = 9) -> dict:
    """SIGKILL (default) all radare2 processes analyzing *path*."""
    pids = _r2_procs_for(path)
    for pid in pids:
        try:
            os.kill(pid, sig)
        except (ProcessLookupError, PermissionError):
            pass
    return {"killed": pids}


def _is_scripted_r2(args: list[str]) -> bool:
    """True if a radare2 argv looks like an r2pipe session ('-2 -q0')."""
    return "-2" in args and "-q0" in args


def _fuzz_workdir() -> str:
    return os.environ.get("FUZZ_GUIDE_WORKDIR", "/tmp/fuzz_guide_workdir")


def sweep_stale_r2() -> dict:
    """Kill stale *scripted* radare2 sessions — but ONLY sessions whose argv
    references a file inside the fuzz-guide workdir (exact match).

    r2pipe spawns r2 with ``-2 -q0``; when the MCP server dies mid-analysis
    the print-level child is adopted by init and keeps eating CPU for hours
    (observed: 2h05m on a truncated ELF).  Interactive r2 sessions, and any
    scripted r2 a different project started outside the workdir, are never
    touched.
    """
    killed = []
    kept = []
    if os.name != "posix" or not os.path.isdir("/proc"):
        return {"killed_r2": killed, "untouched_interactive_r2": kept,
                "note": "no /proc scan available on this platform"}
    workdir = _fuzz_workdir()
    try:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                with open(f"/proc/{entry}/cmdline", "rb") as f:
                    raw = f.read()
                args = [a.decode("utf-8", "replace") for a in raw.split(b"\x00") if a]
                if not args or not os.path.basename(args[0]).startswith("radare2"):
                    continue
                if not _is_scripted_r2(args):
                    kept.append(int(entry))  # interactive r2: leave alone
                    continue
                if _arg_refs(args, workdir):
                    try:
                        os.kill(int(entry), 9)
                        killed.append(int(entry))
                    except (ProcessLookupError, PermissionError, ValueError):
                        pass
                else:
                    kept.append(int(entry))  # other project's session: leave alone
            except (IOError, OSError, ValueError, PermissionError):
                continue
    except Exception:
        pass
    return {"killed_r2": killed, "untouched_interactive_r2": kept}


def open_r2(path: str, budget_s: int = _DEFAULT_BUDGET, flags: list | None = None):
    """Open r2pipe with a hard time budget.

    The returned object behaves like an r2pipe (``.cmd`` / ``.quit`` / ``.flush``),
    but a watchdog kills any r2 process on *path* after ``budget_s`` seconds,
    so timeouts cannot orphan runaway analysis.
    """
    import r2pipe  # deferred: only needed on small binaries

    # never start a new session while orphans from a crashed server exist
    sweep_stale_r2()

    _flags = flags or []
    r2 = r2pipe.open(path, flags=["-2", "-e", "scr.color=false", "-e", "bin.strings=false", *_flags])
    deadline = time.time() + budget_s

    stop = threading.Event()

    def watchdog():
        target = budget_s
        waited = 0.0
        while waited < target + 2 and not stop.is_set():
            time.sleep(1)
            waited += 1
        if not stop.is_set():
            kill_r2_for(path)

    t = threading.Thread(target=watchdog, daemon=True)
    t.start()

    orig_cmd = r2.cmd

    def _cmd(c):
        if time.time() > deadline or stop.is_set():
            kill_r2_for(path)
            return json.dumps({"error": "r2 budget exceeded"})
        return orig_cmd(c)

    r2.cmd = _cmd
    orig_quit = r2.quit

    def _quit():
        stop.set()
        return orig_quit()

    r2.quit = _quit
    return r2