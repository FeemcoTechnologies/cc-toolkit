"""Crash triage for AFL++ findings using GDB batch mode.

Reads a crash file, runs GDB on the target with it, and returns the
faulting instruction + stack so the AI can immediately reason about it.
"""

import os
import re
import shutil
import subprocess


def analyze_crash(
    binary: str,
    crash_file: str,
    args: str = "",
    timeout_s: int = 30,
) -> dict:
    """Triage a single crashing input against a binary via GDB."""
    if not os.path.isfile(binary):
        return {"error": f"Binary not found: {binary}"}
    if not os.path.isfile(crash_file):
        return {"error": f"Crash file not found: {crash_file}"}

    gdb = shutil.which("gdb") or "gdb"

    # Build the run target command. For file-mode, pass crash path as arg.
    if args and "@@" in args:
        run_args = args.replace("@@", crash_file)
    elif args:
        run_args = f"{args} < {crash_file}"
    else:
        run_args = f"< {crash_file}"

    script = f"""
set pagination off
set confirm off
run {run_args}
bt 12
info registers
info args
quit
"""

    try:
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".gdb", delete=False) as gf:
            gf.write(script)
            script_path = gf.name
        out = subprocess.run(
            [gdb, "-q", "-batch", binary, "-x", script_path],
            text=True, timeout=timeout_s, capture_output=True,
        )
        text = out.stdout + out.stderr
        os.unlink(script_path)
    except subprocess.TimeoutExpired:
        return {
            "binary": binary,
            "crash_file": crash_file,
            "timeout": True,
            "note": "GDB timed out; check output dir for hangs",
        }
    except Exception as e:
        return {"error": f"gdb failed: {e}"}

    # ---- parse the interesting bits ----
    signal = _extract_signal(text)
    faulting_insn = _extract_rip_instruction(text)
    stack = _extract_backtrace(text)
    regs = _extract_regs(text)

    return {
        "binary": binary,
        "crash_file": crash_file,
        "signal": signal,
        "faulting_instruction": faulting_insn,
        "registers": regs,
        "backtrace": stack[:14],
        "gdb_excerpt": text[:800],
    }


def analyze_corpus(
    binary: str,
    crash_dir: str,
    args: str = "",
    max_crashes: int = 8,
) -> dict:
    """Triage up to N crash files from an AFL output dir."""
    if not os.path.isdir(crash_dir):
        return {"error": f"Crash dir not found: {crash_dir}"}

    files = sorted(
        f for f in os.listdir(crash_dir)
        if os.path.isfile(os.path.join(crash_dir, f)) and f != "README.txt"
    )
    if not files:
        return {"crash_dir": crash_dir, "count": 0}

    results = []
    unique_signals: dict = {}
    for f in files[:max_crashes]:
        path = os.path.join(crash_dir, f)
        r = analyze_crash(binary, path, args)
        key = r.get("signal", "?") + "|" + (r.get("faulting_instruction") or "")[:40]
        if key not in unique_signals:
            unique_signals[key] = True
        results.append({"file": f, **r})

    return {
        "crash_dir": crash_dir,
        "count": len(files),
        "analyzed": len(results),
        "unique_signatures": len(unique_signals),
        "crashes": results,
    }


# ------------------------------------------------------------------
# parsing helpers
# ------------------------------------------------------------------

def _extract_signal(text: str) -> str:
    m = re.search(r"Program received signal (\S+),|Program terminated with signal (\S+)", text)
    if m:
        return "signal " + (m.group(1) or m.group(2))
    m = re.search(r"SIG[A-Z]+", text)
    return m.group(0) if m else "unknown"


def _extract_rip_instruction(text: str) -> str:
    # e.g.  RIP ?: 0x401234 : mov byte ptr [rax], 0
    for line in text.splitlines():
        if re.search(r"\b(RIP|EIP|PC)\b.*:", line) and "=>" in line or re.search(r"^\s*=>.*:\s*0x", line):
            return line.strip()[:120]
    for line in text.splitlines():
        if re.search(r"0x[0-9a-f]+\s+in\s+", line):
            return line.strip()[:120]
    return ""


def _extract_backtrace(text: str) -> list[str]:
    frames = []
    in_bt = False
    for line in text.splitlines():
        if line.startswith("#0") or line.startswith("=> #0"):
            in_bt = True
        if in_bt:
            frames.append(line.strip()[:160])
            if len(frames) >= 14:
                break
    return frames


def _extract_regs(text: str) -> str:
    regs = []
    for line in text.splitlines():
        if re.match(r"^\s*(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|rip|eax|ebx|ecx|edx|esi|edi|ebp|esp|eip)\s*[=\s]", line):
            regs.append(line.strip())
    return " ".join(regs[:20])