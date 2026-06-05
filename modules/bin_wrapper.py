"""Wrapper for ai-bug-bounty/bin-tools.py binary analysis toolkit.

Calls bin-tools.py as a subprocess with --json and returns dicts.
Gracefully handles missing binary or bin-tools.py not being present.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

_TOOL = None

def _find_bin_tools() -> str | None:
    global _TOOL
    if _TOOL is not None:
        return _TOOL
    candidates = [
        str(Path(__file__).resolve().parent.parent.parent / "ai-bug-bounty" / "bin-tools.py"),
        str(Path.home() / "ai-bug-bounty" / "bin-tools.py"),
        "/opt/ai-bug-bounty/bin-tools.py",
    ]
    for c in candidates:
        if os.path.isfile(c):
            _TOOL = c
            return _TOOL
    _TOOL = False
    return None


def _run(args: list[str], timeout: int = 300) -> dict:
    tool = _find_bin_tools()
    if not tool:
        return {"error": "bin-tools.py not found. Expected at ../ai-bug-bounty/bin-tools.py"}
    if not shutil.which("python3") and not shutil.which("python"):
        return {"error": "python3 not found in PATH"}
    py = shutil.which("python3") or shutil.which("python") or "python3"
    cmd = [py, tool] + args + ["--json"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0:
            return {"error": (r.stderr or r.stdout or f"Exit code {r.returncode}")[:1000]}
        return json.loads(r.stdout) if r.stdout.strip() else {"stdout": r.stdout, "stderr": r.stderr}
    except subprocess.TimeoutExpired:
        return {"error": f"Command timed out after {timeout}s"}
    except json.JSONDecodeError:
        return {"stdout": r.stdout[:2000], "stderr": r.stderr[:2000]}
    except FileNotFoundError as e:
        return {"error": f"Binary not found: {e}"}
    except Exception as e:
        return {"error": str(e)[:1000]}


def _run_text(args: list[str], timeout: int = 300) -> dict:
    """Run without --json flag and return raw text output."""
    tool = _find_bin_tools()
    if not tool:
        return {"error": "bin-tools.py not found"}
    py = shutil.which("python3") or shutil.which("python") or "python3"
    cmd = [py, tool] + args
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"stdout": r.stdout[:5000], "stderr": r.stderr[:1000], "returncode": r.returncode}
    except subprocess.TimeoutExpired:
        return {"error": f"Command timed out after {timeout}s"}
    except FileNotFoundError as e:
        return {"error": f"Binary not found: {e}"}
    except Exception as e:
        return {"error": str(e)[:1000]}


def check() -> dict:
    """Check what binary exploitation tools are available."""
    return _run(["check"])


def analyze(binary: str) -> dict:
    """Full binary analysis: file info, security, vulns, exploitability, tool analysis."""
    return _run(["analyze", binary])


def vulns(binary: str) -> dict:
    """Vulnerability scan for dangerous functions, format strings, shell exec, etc."""
    return _run(["vulns", binary])


def summary(binary: str) -> dict:
    """Concise markdown summary of binary analysis (AI-friendly)."""
    return _run_text(["summary", binary])


def checksec(binary: str) -> dict:
    """Security mitigations check: NX, Canary, RELRO, PIE."""
    return _run(["checksec", binary])


def gadgets(binary: str) -> dict:
    """Find ROP gadgets via ropper or ROPgadget."""
    return _run(["gadgets", binary])


def exploit(binary: str) -> dict:
    """Exploit strategy: scoring, technique suggestions, ROP chain strategy."""
    return _run(["exploit", binary])


def functions(binary: str) -> dict:
    """List functions in binary (from symbols or nm/objdump)."""
    return _run_text(["funcs", binary])


def strings(binary: str) -> dict:
    """Extract printable strings from binary."""
    return _run_text(["strings", binary])


def fmtstr(binary: str) -> dict:
    """Format string vulnerability analysis with offset guide and techniques."""
    return _run(["fmtstr", binary])


def heap(binary: str) -> dict:
    """Heap analysis: allocator detection, exploitation techniques."""
    return _run(["heap", binary])


def angr(binary: str, target_func: str = "system") -> dict:
    """Symbolic execution with angr: path finding, function discovery."""
    return _run(["symbolic", "--target", target_func, binary])


def fuzz(binary: str) -> dict:
    """Generate fuzzing harness (AFL++ C + Python + README)."""
    return _run_text(["fuzz", binary])


def cyclic(length: int) -> dict:
    """Generate cyclic pattern of given length."""
    return _run_text(["cyclic", str(length)])


def pattern_offset(value: str) -> dict:
    """Find offset of a value in cyclic pattern."""
    return _run_text(["pattern", "-v", value])


def net(target: str) -> dict:
    """Network service analysis for a binary or host:port target."""
    return _run(["net", target])
