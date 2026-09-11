"""Binary classification: enumerate folder contents and classify binary type/arch/stripping."""

import json
import os
import subprocess

from . import r2util


def enumerate_binaries(folder: str, max_files: int = 500) -> list[dict]:
    """Walk a folder and return executables/libraries with basic metadata.

    Uses the ``file`` command to filter to interesting binaries.
    Returns compact summaries to keep token usage low.
    """
    if not os.path.isdir(folder):
        return [{"error": f"Not a directory: {folder}"}]

    results = []
    seen = 0
    for root, _dirs, files in os.walk(folder):
        for fname in files:
            if seen >= max_files:
                return results
            path = os.path.join(root, fname)
            try:
                out = subprocess.check_output(
                    ["file", "--brief", path], text=True, timeout=5
                )
                low = out.lower()
                if any(
                    kw in low
                    for kw in (
                        "elf",
                        "pe32",
                        "pe64",
                        "executable",
                        "shared object",
                        "dll",
                        "archive",
                        "java",
                        "python",
                        "mach-o",
                        "dotnet",
                        ".net",
                    )
                ):
                    results.append(
                        {
                            "path": path,
                            "type": _quick_type(low),
                            "info": out.strip()[:120],
                            "size": os.path.getsize(path),
                            "rel": os.path.relpath(path, folder),
                        }
                    )
                    seen += 1
            except Exception:
                pass
    return results


def classify_binary(path: str) -> dict:
    """Deep classification of a single binary.

    Uses r2pipe for ELF/PE deep analysis (arch, bits, stripping, mitigations,
    sections, function count).  Returns compact JSON.
    """
    if not os.path.isfile(path):
        return {"path": path, "exists": False}

    result: dict = {"path": path, "exists": True, "size": os.path.getsize(path)}

    try:
        result["file_info"] = (
            subprocess.check_output(["file", path], text=True, timeout=5).strip()
        )
    except Exception:
        result["file_info"] = "unknown"

    low = result["file_info"].lower()
    result["type"] = _quick_type(low)

    # r2 deep analysis for native binaries
    if result["type"] in ("ELF", "PE"):
        if r2util.is_huge(path):
            result.update(r2util.fast_elf_info(path))
            result["sec"] = {
                "canary": None,
                "nx": result.get("nx"),
                "pic": None,
                "relro": result.get("relro", "?"),
            }
            return result
        try:
            r2 = r2util.open_r2(path)
            r2.cmd("aaa")
            info = json.loads(r2.cmd("ij"))
            b = info.get("bin", {})

            result["arch"] = b.get("arch", "?")
            result["bits"] = b.get("bits", 0)
            result["endian"] = b.get("endian", "?")
            result["stripped"] = b.get("stripped", False)
            result["entry"] = hex(b.get("entry", 0))
            result["pic"] = b.get("pic", False)

            result["sec"] = {
                "canary": b.get("canary", False),
                "nx": b.get("nx", False),
                "pic": b.get("pic", False),
                "relro": b.get("relro", "?"),
            }

            # Detect .NET / Java subtypes via imports
            imports_raw = r2.cmd("ii") or ""
            il = imports_raw.lower()
            if "mscoree" in il or "mscorlib" in il or "_ CorExeMain" in imports_raw:
                result["subtype"] = "dotnet"
            elif "javax" in il or "java/" in il or "javaw" in il:
                result["subtype"] = "java"

            # Quick function count
            try:
                funcs = json.loads(r2.cmd("aflj"))
                result["num_functions"] = len(funcs)
            except Exception:
                result["num_functions"] = 0

            # Sections (compact)
            try:
                secs = json.loads(r2.cmd("iSj"))
                result["sections"] = [
                    {"n": s.get("name", ""), "s": s.get("size", 0), "p": s.get("perm", "")}
                    for s in secs[:15]
                ]
            except Exception:
                result["sections"] = []

            r2.quit()
        except Exception as e:
            result["r2_error"] = str(e)[:200]

    elif result["type"] == "Archive":
        try:
            out = subprocess.check_output(
                ["file", path], text=True, timeout=5
            ).strip()
            if "zip" in out.lower() or "jar" in out.lower():
                # Check for Java class files inside
                zout = subprocess.check_output(
                    ["unzip", "-l", path], text=True, timeout=10, stderr=subprocess.DEVNULL
                )
                if ".class" in zout:
                    result["subtype"] = "java-jar"
                elif any(x in zout for x in (".dll", ".exe", ".config", ".manifest")):
                    result["subtype"] = "dotnet-assembly"
        except Exception:
            pass

    return result


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _quick_type(file_info_lower: str) -> str:
    """Map `file` output to a simple type tag."""
    if "elf" in file_info_lower:
        return "ELF"
    if "pe32" in file_info_lower or "pe64" in file_info_lower or "ms-dos" in file_info_lower:
        return "PE"
    if "java" in file_info_lower:
        return "Java"
    if "archive" in file_info_lower or "zip" in file_info_lower:
        return "Archive"
    if "python" in file_info_lower:
        return "Python"
    if "mach-o" in file_info_lower:
        return "Mach-O"
    return "Unknown"
