"""Compiled-artifact security scanner.

Walks a tree of compiled binaries and library/object files (ELF, PE/DLL,
Mach-O, .NET assemblies, Java class/jar, Python bytecode) and flags issues
that are visible in compiled form without needing source code:

  * mitigation gaps - NX, PIE/ASLR, stack canary, FORTIFY, RELRO/GNU_RELRO,
    PE DYNAMIC_BASE (ASLR), NX_COMPAT (DEP), GUARD_CF (CFG)
  * command/code-execution sinks - system(), exec*, popen, WinExec/ShellExecute
  * insecure library loading - LoadLibrary*/dlopen from variable/relative
    paths, SetDllDirectory (weakens search order), ELF RPATH/RUNPATH
  * process-injection APIs - VirtualAllocEx/WriteProcessMemory/CreateRemoteThread
    and related primitives
  * weak cryptography - MD5/RC4/DES imports and strings; weak PRNG (rand)
  * dangerous memory functions - strcpy/strcat/sprintf/gets/scanf
  * hardcoded secrets in embedded strings - cloud tokens, JWTs, private key
    blocks, user:pass@ URLs, plaintext password=/secret= pairs
  * TLS certificate-verification bypass strings (sslmode=disable, ...)
  * .NET deserialization sinks (BinaryFormatter via strings)
  * optional YARA pass over the bundled rules/yara set (packers/malware)

Uses binutils, pefile and r2 when available, and degrades to compact
pure-Python ELF/PE/Mach-O parsing so the same rules run on Kali, Windows
and minimal hosts.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import struct
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .bin_surface import (_run, _py_strings, detect_type, _rglob_depth,
                          DEFAULT_EXCLUDE_DIRS)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"info": 1, "warning": 2, "error": 3}
DEFAULT_YARA_DIR = Path(__file__).resolve().parent.parent / "rules" / "yara"

# Extra bytecode magics beyond bin_surface's ELF/PE/Mach-O map.
BYTECODE_MAGIC = [
    (b"\xca\xfe\xba\xbe", "CLASS"),
    (b"\x61\x0d\x0d\x0a", "PYC"),
    (b"\x63\x0d\x0d\x0a", "PYC"),
    (b"\x55\x0d\x0d\x0a", "PYC"),
    (b"\x42\x0d\x0d\x0a", "PYC"),
    (b"\x03\xf3\x0d\x0a", "PYC"),
]

MAX_STRINGS_SIZE = 200 * 1024 * 1024   # skip full strings() past this size
MAX_DIR_LIMIT = 500                     # max files per directory scan

# -- exec / command-injection sinks (import names) -------------------------
EXEC_SINKS = {
    "system", "_system", "popen", "_popen", "execl", "execle", "execlp",
    "execv", "execve", "execvp", "execvpe", "posix_spawn", "__libc_system",
    "WinExec", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA",
    "ShellExecuteExW", "CreateProcessA", "CreateProcessW", "_wsystem",
    "Winexec", "system@plt",
}

# -- insecure / variable DLL loading ----------------------------------------
DLL_LOAD_APIS = {
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "LdrLoadDll", "LoadPackagedLibrary",
}
WEAKENED_SEARCH = {"SetDllDirectoryA", "SetDllDirectoryW", "AddDllDirectoryW"}
DLL_FETCH = {"SearchPathA", "SearchPathW", "FindFirstFileA", "FindFirstFileW"}
INDIRECT_LOAD = {"dlopen", "dlopen64", "LoadLibrary", "LoadLibraryEx"}

# -- process injection primitives -------------------------------------------
INJECTION_APIS = {
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "QueueUserAPC", "SetWindowsHookExA", "SetWindowsHookExW",
    "RtlCreateUserThread", "NtCreateThreadEx", "ZwCreateThreadEx",
    "NtMapViewOfSection", "ZwMapViewOfSection", "NtWriteVirtualMemory",
    "ZwWriteVirtualMemory", "VirtualProtectEx", "ReadProcessMemory",
    "WriteProcessMemory", "OpenProcess", "DebugActiveProcess",
    "VexAllocatePoolType", "DuplicateHandle",
}
INJECTION_TRIAD = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}

# -- weak crypto -------------------------------------------------------------
WEAK_CRYPTO = {
    "MD5Init", "MD5Update", "MD5Final", "MD5_Init", "MD5_Update",
    "MD5_Final", "EVP_MD5", "EVP_md5", "SHA_Init", "SHA1_Init",
    "RC4", "EVP_rc4", "MD4", "EVP_md4", "MD2Init", "DES_set_key",
    "DES_ecb_encrypt", "DES_cbc_encrypt", "des_key_sched", "rand",
    "srand", "random", "arc4random_buf",
}

# -- dangerous memory / format functions ------------------------------------
DANGEROUS_MEM = {
    "strcpy", "strcat", "sprintf", "gets", "scanf", "fscanf", "vscanf",
    "wscanf", "swscanf", "wscat", "wcscpy", "wcscat", "strtok", "strncpy",
    "memcpy", "vsprintf",
}
FORTIFY_MARKERS = {"__sprintf_chk", "__snprintf_chk", "__strcpy_chk",
                   "__memcpy_chk", "__strncpy_chk", "__memset_chk",
                   "__fgets_chk", "__gets_chk", "__vsnprintf_chk",
                   "__stack_chk_fail"}

# -- managed (Java/.NET) process-execution sinks (string-detected) ----------
JAVA_EXEC_SINKS = {
    "Runtime.getRuntime().exec", "ProcessBuilder",
    "java.lang.Runtime", "javax.script.ScriptEngineManager",
    "Process exec", "Runtime.exec",
}
DOTNET_RUNTIME_SINKS = {
    "System.Diagnostics.Process", "Process.Start", "ProcessStartInfo",
}

# -- string IOCs --------------------------------------------------------------
AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GOOGLE_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")
SLACK_TOKEN_RE = re.compile(r"\b(xox[baprs]-)[0-9A-Za-z-]{10,}\b")
GH_TOKEN_RE = re.compile(r"\b(ghp_|gho_|ghu_|ghs_|github_pat_)[0-9A-Za-z_-]{20,}\b")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._/-]{10,}\b")
PRIVKEY_RE = re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
URL_CRED_RE = re.compile(r"://[^@/\s:]+:[^@/\s]+@")
PAIR_RE = re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token|access[_-]?key)\s*[=:]\s*([^\s\"'{}>,;:]+)")
TLS_BYPASS_RE = re.compile(
    r"(?i)(sslmode[\s=]+disable|ssl[\s-]*verif(y|ication)[\s=]+(0|false|off|no)|"
    r"verify_peer[\s=]+false|verifypeer[\s=]+false|verify[\s=]+none|"
    r"validateservercertificate[\s=]+false|insecureskipverify|"
    r"rejectunauthorized[\s=]+false|disable[\s-]*certificate[\s-]*validation|"
    r"ssl[\s=]+no|check[\s-]*ssl[\s=]+(false|0))")
SQL_RE = re.compile(r"(?is)(SELECT\s+.+?\s+FROM\s+.+?\s+WHERE)")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

DOTNET_SER_SINKS = ["BinaryFormatter", "ObjectStateFormatter", "LosFormatter",
                    "NetDataContractSerializer", "SoapFormatter"]

# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def sha256_first(path: Path) -> str:
    try:
        with path.open("rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return ""


def _arch(path: Path, ftype: str) -> str:
    if ftype == "ELF" and shutil.which("readelf"):
        out, _ = _run(["readelf", "-hW", str(path)], timeout=30)
        m = re.search(r"Machine:\s+(.+)$", out, re.MULTILINE)
        if m:
            arch = m.group(1).strip()
            return {"Advanced Micro Devices X86-64": "x86-64",
                    "Intel 80386": "x86", "AArch64": "AArch64",
                    "ARM": "ARM", "RISC-V": "RISC-V",
                    "PowerPC64": "PowerPC64", "EM_X86-64": "x86-64",
                    "EM_386": "x86"}.get(arch, arch)
        return ""
    elif ftype == "PE":
        try:
            import pefile  # type: ignore
            pe = pefile.PE(str(path), fast_load=True)
            m = {0x014C: "x86", 0x8664: "x86-64", 0x01C0: "ARM",
                 0xAA64: "AArch64", 0x01F0: "ARM64EC"}.get(
                     pe.FILE_HEADER.Machine, f"0x{pe.FILE_HEADER.Machine:x}")
            pe.close()
            return m
        except Exception:
            pass
    return ""


def _elf_analysis(path: Path) -> dict:
    mit: Dict[str, object] = {"format": "ELF"}
    rpath = []
    runpath = []
    needed = []
    imports = []
    arch = ""

    if shutil.which("readelf"):
        hout, _ = _run(["readelf", "-hW", str(path)], timeout=30)
        m = re.search(r"Machine:\s+(.+)$", hout, re.MULTILINE)
        if m:
            arch = m.group(1).strip()
            arch = {"Advanced Micro Devices X86-64": "x86-64",
                    "Intel 80386": "x86", "AArch64": "AArch64",
                    "ARM": "ARM", "RISC-V": "RISC-V",
                    "PowerPC64": "PowerPC64"}.get(arch, arch)
        m = re.search(r"Type:\s+(\S+)", hout)
        etype = m.group(1) if m else ""
        mit["pie"] = (etype == "DYN") if etype else None
        mit["type"] = etype

        lout, _ = _run(["readelf", "-lW", str(path)], timeout=30)
        stack_exe = False
        for ln in lout.splitlines():
            if "GNU_STACK" in ln:
                flags = ln.split()[-1] if ln.split() else ""
                stack_exe = "E" in flags
                break
        mit["nx"] = not stack_exe

        dout, _ = _run(["readelf", "-dW", str(path)], timeout=30)
        bind_now = False
        has_relro = False
        for ln in dout.splitlines():
            if "RPATH" in ln:
                rpath.append(ln.split("[", 1)[-1].rstrip("]"))
            elif "RUNPATH" in ln:
                runpath.append(ln.split("[", 1)[-1].rstrip("]"))
            elif "BIND_NOW" in ln:
                bind_now = True
            elif "GNU_RELRO" in ln:
                has_relro = True
            m = re.search(r"NEEDED\s+.*\[(.*?)\]", ln)
            if m:
                needed.append(m.group(1))
        if has_relro:
            mit["relro"] = "full" if bind_now else "partial"
        else:
            mit["relro"] = None

        sout, _ = _run(["readelf", "-sW", str(path)], timeout=30)
        mit["canary"] = "__stack_chk_fail" in sout
        mit["fortify"] = any(m in sout for m in FORTIFY_MARKERS
                             if m != "__stack_chk_fail")

        # dynamic undefined symbols = imports
        if shutil.which("nm"):
            nout, _ = _run(["nm", "-D", "--undefined-only", str(path)],
                           timeout=30)
            for ln in nout.splitlines():
                m = re.search(r"\bU\s+([\w.]+)", ln)
                if m:
                    imports.append(m.group(1))
    else:
        # Minimal pure-Python ELF header: class, e_type, machine.
        try:
            with path.open("rb") as f:
                data = f.read(64)
            if len(data) >= 40:
                etype = struct.unpack_from("<H", data, 16)[0]
                mach = struct.unpack_from("<H", data, 18)[0]
                mit["pie"] = (etype == 3)
                mit["type"] = "EXEC" if etype == 2 else ("DYN" if etype == 3 else f"{etype}")
                arch = {0x3E: "x86-64", 0x03: "x86", 0xB7: "AArch64"}.get(mach, f"0x{mach:x}")
        except OSError:
            pass

    # resolve loading-risk verdicts
    findings = _elf_loading_findings(rpath, runpath, imports)
    return {"mit": mit, "rpath": rpath, "runpath": runpath,
            "needed": needed, "imports": imports, "arch": arch,
            "load_findings": findings}


def _elf_loading_findings(rpath, runpath, imports) -> List[dict]:
    findings = []
    for kind, entries in (("RPATH", rpath), ("RUNPATH", runpath)):
        for e in entries:
            if kind == "RUNPATH" and (e in ("", ".") or e.startswith("./")):
                findings.append(_finding(
                    "load.runpath-relative", "error",
                    f"relative RUNPATH entry '{e}' - trivial library hijacking",
                    evidence=e))
            elif kind == "RPATH" and (e in ("", ".") or e.startswith("./")):
                findings.append(_finding(
                    "load.rpath-relative", "error",
                    f"relative RPATH entry '{e}' - trivial library hijacking",
                    evidence=e))
            elif e.startswith("$ORIGIN") or e.startswith("${ORIGIN"):
                findings.append(_finding(
                    "load.rpath-origin", "info",
                    f"{kind} uses $ORIGIN ('{e}') - organic but audit locations",
                    evidence=e))
            elif not e.startswith(("/usr", "/lib", "/lib64", "/opt", "/etc")):
                findings.append(_finding(
                    "load.rpath-custom", "warning",
                    f"non-standard {kind} entry '{e}' - audit for hijack primitives",
                    evidence=e))
    if "dlopen" in imports or "dlopen64" in imports:
        findings.append(_finding(
            "load.dlopen", "warning",
            "uses dlopen() - flag if any call passes a variable/relative path",
            evidence="dlopen"))
    return findings


def _pe_analysis(path: Path) -> dict:
    mit: Dict[str, object] = {"format": "PE"}
    imports = []
    dlls = []
    dotnet = False
    arch = ""
    try:
        import pefile  # type: ignore
        pe = pefile.PE(str(path), fast_load=False)
        fh = pe.FILE_HEADER
        opt = pe.OPTIONAL_HEADER
        mit["magic"] = "PE32+" if opt.Magic == 0x20B else "PE32"
        arch = {0x014C: "x86", 0x8664: "x86-64", 0x01C0: "ARM",
                0xAA64: "AArch64"}.get(fh.Machine, f"0x{fh.Machine:x}")
        dc = opt.DllCharacteristics or 0
        mit["aslr"] = bool(dc & 0x0040)            # DYNAMIC_BASE
        mit["high_entropy"] = bool(dc & 0x0020)
        mit["dep"] = bool(dc & 0x0100)             # NX_COMPAT
        mit["cfg"] = bool(dc & 0x4000)             # GUARD_CF
        mit["force_integrity"] = bool(dc & 0x0080)
        mit["no_seh"] = bool(dc & 0x0400)
        try:
            clr = opt.DATA_DIRECTORY[14]
            dotnet = bool(clr.VirtualAddress)
        except Exception:
            pass
        mit["dotnet"] = dotnet
        try:
            for e in pe.DIRECTORY_ENTRY_IMPORT:
                dll = e.dll.decode(errors="replace") if e.dll else ""
                dlls.append(dll)
                for imp in e.imports:
                    nm = imp.name.decode(errors="replace") if imp.name else ""
                    if nm:
                        imports.append(nm)
        except Exception:
            pass
        canary = False
        for nm in imports:
            if nm in ("__security_cookie", "__security_init_cookie",
                      "__GSHandlerCheck", "__GSHandlerCheckCommon"):
                canary = True
        mit["canary"] = canary
        try:
            pe.close()
        except Exception:
            pass
    except Exception:
        # fallback: objdump -p (binutils)
        dlls, imports = _pe_objdump(path)
        mit["aslr"] = mit["dep"] = mit["cfg"] = mit["canary"] = None
    return {"mit": mit, "imports": imports, "dlls": dlls, "arch": arch,
            "dotnet": dotnet}


def _pe_objdump(path: Path) -> Tuple[List[str], List[str]]:
    dlls, imports = [], []
    if not shutil.which("objdump"):
        return dlls, imports
    out, _ = _run(["objdump", "-p", str(path)], timeout=60)
    for ln in out.splitlines():
        m = re.match(r"\s*DLL Name:\s*(.+)$", ln)
        if m:
            dlls.append(m.group(1).strip())
        elif "Import Address Table" in ln or "Import Table" in ln:
            continue
        else:
            m = re.match(r"\s*[0-9a-fA-F]+\s+([\w.@]+)$", ln)
            if m and m.group(1) and "." not in m.group(1):
                imports.append(m.group(1))
    return dlls, imports


def _macho_analysis(path: Path) -> dict:
    mit: Dict[str, object] = {"format": "Mach-O"}
    imports: List[str] = []
    try:
        with path.open("rb") as f:
            data = f.read(32)
        magic = struct.unpack_from("<I", data, 0)[0]
        # fat binary: first cputype list; skip deep parse
        flags = None
        if magic in (0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE):
            if magic in (0xFEEDFACE, 0xCEFAEDFE):   # 32 / 64 LE
                flags = struct.unpack_from("<I", data, 18)[0]
            else:                                   # 32 / 64 BE
                flags = struct.unpack_from(">I", data, 18)[0]
        if flags is not None:
            mit["pie"] = bool(flags & 0x00200000)        # MH_PIE
            mit["nx"] = not bool(flags & 0x00020000)     # MH_ALLOW_STACK_EXECUTION
        else:
            mit["pie"] = None
            mit["nx"] = None
        mit["fat"] = magic == 0xCAFEBABE
    except Exception:
        pass
    if shutil.which("rabin2"):
        out, _ = _run(["rabin2", "-i", str(path)], timeout=30)
        for ln in out.splitlines():
            if "imports" in ln.lower() or ln.strip().startswith("["):
                continue
            m = re.search(r"\].*?\s(\w+)\s*$", ln)
            if m:
                imports.append(m.group(1))
    return {"mit": mit, "imports": imports, "arch": ""}


def _binary_strings(path: Path, min_len: int = 8) -> List[str]:
    size = 0
    try:
        size = path.stat().st_size
    except OSError:
        return []
    if size > MAX_STRINGS_SIZE:
        return [f"<skipped strings: file too large ({size})>"]
    out: List[str] = []
    if shutil.which("strings"):
        o, _ = _run(["strings", "-a", "-n", str(min_len), str(path)], timeout=120)
        out.extend(o.splitlines())
        # UTF-16 pass for .NET/Windows PE strings
        o2, _ = _run(["strings", "-el", "-n", str(min_len), str(path)], timeout=120)
        out.extend(o2.splitlines())
    else:
        out = _py_strings(path, min_len)
    return out


# ---------------------------------------------------------------------------
# Java class constant-pool analysis
# ---------------------------------------------------------------------------

class _CPTable:
    """Minimal Java classfile constant pool iterator."""

    _SIZES = {
        3: 4, 4: 4, 5: 8, 6: 8, 9: 4, 10: 4, 11: 4, 12: 4,
        17: 4, 18: 4,
    }

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 10  # magic(4) + minor(2) + major(2) + cp_count(2)
        self.utf8: List[str] = []

    def _utf8(self, n: int) -> str:
        b = self.data[self.pos:self.pos + n]
        self.pos += n
        try:
            return b.decode("utf-8", "surrogatepass")
        except Exception:
            return b.decode("latin-1", "replace")

    def parse(self) -> List[str]:
        if len(self.data) < 10:
            return []
        count = int.from_bytes(self.data[8:10], "big")
        idx = 1
        while idx < count:
            if self.pos + 1 > len(self.data):
                break
            tag = self.data[self.pos]
            self.pos += 1
            if tag == 1:                      # Utf8
                n = int.from_bytes(self.data[self.pos:self.pos + 2], "big")
                self.pos += 2
                self.utf8.append(self._utf8(n))
            elif tag in (5, 6):               # long/double take 2 slots
                self.pos += 8
                idx += 1
            elif tag in self._SIZES:
                self.pos += self._SIZES[tag]
            elif tag in (15, 19, 20):         # MethodHandle / Module / Package
                self.pos += 3 if tag == 15 else 2
            elif tag in (7, 8, 16):           # Class / String / MethodType
                self.pos += 2
            else:
                return self.utf8
            idx += 1
        return self.utf8


def _java_findings(path: Path) -> List[dict]:
    try:
        data = path.open("rb").read(2 * 1024 * 1024)
    except OSError:
        return []
    pool = _CPTable(data).parse()
    if not pool:
        return []
    ps = set(pool)
    joined = "\n".join(pool)
    findings: List[dict] = []
    runtime = bool(ps & {"java/lang/Runtime", "java/lang/ProcessBuilder"})
    if runtime and "exec" in ps:
        findings.append(_finding(
            "exec.java-sink", "warning",
            "Java process-execution sink referenced (Runtime/ProcessBuilder "
            "with exec) - verify input is not attacker-controlled",
            evidence="Runtime.exec"))
    if runtime and "getRuntime" in ps and "exec" not in ps:
        findings.append(_finding(
            "exec.java-runtime", "info",
            "java.lang.Runtime referenced without adjacent exec",
            evidence="Runtime"))
    if "java/lang/Class" in ps and ({"forName", "loadClass", "getDeclaredMethod"}
                                    & ps):
        findings.append(_finding(
            "java.reflection", "info",
            "reflective class loading / method access via Class.forName "
            "family - review reachable user input",
            evidence="Class.forName"))
    obj_in = {"java/io/ObjectInputStream", "java/io/Serializable",
              "java/lang/reflect/InvocationHandler"}
    if ps & obj_in and "readObject" in ps:
        findings.append(_finding(
            "java.deserialization", "warning",
            "deserialization entrypoint (readObject / ObjectInputStream) - "
            "untrusted streams risk gadget abuse",
            evidence="readObject"))
    if "java/net/URLClassLoader" in ps or "URLClassLoader" in ps:
        findings.append(_finding(
            "java.urlclassloader", "info",
            "URLClassLoader referenced - remote code loading avenue if fed "
            "untrusted URLs",
            evidence="URLClassLoader"))
    for m in PAIR_RE.finditer(joined):
        val = m.group(2)
        if re.match(r".{6,}", val) and not re.search(
                r"(?i)(changeme|example|xxx|filler)", val):
            findings.append(_finding("secret.plaintext-pair", "info",
                                     "config-style credential assignment in class "
                                     "constant pool",
                                     evidence=m.group(0)[:80]))
            break
    for pat, label in ((AWS_KEY_RE, "aws-access-key"), (GH_TOKEN_RE, "github-token"),
                       (GOOGLE_KEY_RE, "google-api-key"), (TLS_BYPASS_RE, "tls-verify")):
        m = pat.search(joined)
        if m and label != "tls-verify":
            findings.append(_finding(f"secret.{label}", "warning",
                                     f"secret material in class constant pool",
                                     evidence=m.group(0)[:80]))
        elif m:
            findings.append(_finding("tls.verify-disabled", "warning",
                                     "TLS certificate verification disabled marker",
                                     evidence=m.group(0)[:80]))
    return findings


def _string_findings(path: Path, ftype: str = "") -> List[dict]:
    strs = _binary_strings(path)
    blob = "\n".join(strs[:20000])
    findings: List[dict] = []
    for label, pat, sev, cat in [
        ("aws-access-key", AWS_KEY_RE, "error", "hardcoded AWS access key (AKIA)"),
        ("google-api-key", GOOGLE_KEY_RE, "warning", "hardcoded Google API key"),
        ("slack-token", SLACK_TOKEN_RE, "warning", "hardcoded Slack token"),
        ("github-token", GH_TOKEN_RE, "warning", "hardcoded GitHub token"),
        ("jwt-token", JWT_RE, "warning", "hardcoded JWT (possibly long-lived)"),
    ]:
        m = pat.search(blob)
        if m:
            findings.append(_finding(f"secret.{label}", sev, cat,
                                     evidence=m.group(0)[:80]))
    if PRIVKEY_RE.search(blob):
        findings.append(_finding("secret.private-key", "error",
                                 "embedded private key material",
                                 evidence=PRIVKEY_RE.search(blob).group(0)))
    if URL_CRED_RE.search(blob):
        findings.append(_finding("secret.url-credentials", "warning",
                                 "credentials embedded in URL", evidence="user:pass@"))
    # plaintext password= / secret=  pairs (skip obvious placeholders)
    for m in PAIR_RE.finditer(blob):
        val = m.group(2)
        if re.match(r".{6,}", val) and not re.search(r"(?i)(changeme|example|xxx|filler)", val):
            findings.append(_finding("secret.plaintext-pair", "info",
                                     "config-style credential assignment in binary",
                                     evidence=m.group(0)[:80]))
            break
    m = TLS_BYPASS_RE.search(blob)
    if m:
        findings.append(_finding("tls.verify-disabled", "warning",
                                 "TLS certificate verification disabled marker",
                                 evidence=m.group(0)[:80]))
    m = SQL_RE.search(blob)
    if m:
        findings.append(_finding("sql.dynamic-select", "info",
                                 "dynamic SELECT ... WHERE string - review for concat SQLi",
                                 evidence=m.group(0)[:80]))
    ips_seen = set()
    ctx_words = ("host", "server", "addr", "connect", "db", "uri", "target",
                 "endpoint", "proxy", "listen", "bind", "mysql", "redis", "postgres")
    real = []
    for m in IPV4_RE.finditer(blob):
        ip = m.group(0)
        if ip in ips_seen:
            continue
        ips_seen.add(ip)
        if ip.startswith(("192.168.", "10.", "172.", "127.", "0.0.0.0", "255.")):
            continue
        # require config-ish neighborhood to skip version/constant false positives
        ctx = blob[max(0, m.start() - 60):m.end() + 60].lower()
        if any(w in ctx for w in ctx_words):
            real.append(ip)
    for ip in real[:3]:
        findings.append(_finding("secret.hardcoded-ip", "info",
                                 f"hardcoded IP near connection keywords: {ip}",
                                 evidence=ip))
    java = sorted(s for s in JAVA_EXEC_SINKS if s in blob)
    if java:
        findings.append(_finding(
            "exec.java-sink", "warning",
            f"Java process-execution sink referenced ({', '.join(java[:4])}) - "
            "verify input is not attacker-controlled",
            evidence=", ".join(java[:4])))
    dotnet = sorted(s for s in DOTNET_RUNTIME_SINKS if s in blob)
    if dotnet and ftype != "PE":  # managed PEs handled by _dotnet_findings
        findings.append(_finding(
            "exec.dotnet-sink", "warning",
            f".NET process-start sink referenced ({', '.join(dotnet[:3])}) - "
            "verify argument handling (command injection)",
            evidence=", ".join(dotnet[:3])))
    return findings


def _finding(fid: str, severity: str, title: str, evidence: str = "") -> dict:
    return {"id": fid, "severity": severity, "title": title,
            "evidence": (evidence or "")[:160]}


def _import_findings(imports: List[str], mit: dict) -> List[dict]:
    findings: List[dict] = []
    names = {i for i in imports}
    # command / code execution
    exec_hits = sorted(names & EXEC_SINKS)
    if exec_hits:
        sev = "error"
        # mitigations reduce real-world exploitability
        if mit.get("nx") and mit.get("pie"):
            sev = "warning"
        findings.append(_finding(
            "exec.command-injection-sink", sev,
            f"command-execution sink: {', '.join(exec_hits[:6])} - "
            "verify inputs reaching it are not attacker-controlled",
            evidence=", ".join(exec_hits[:6])))
    # DLL / library loading
    ll = sorted(names & DLL_LOAD_APIS)
    if ll:
        findings.append(_finding(
            "load.loadlibrary", "warning",
            f"LoadLibrary API present ({', '.join(ll)}) - require absolute "
            "paths / manifest, else DLL-search-order hijack is possible",
            evidence=", ".join(ll)))
    weak = sorted(names & WEAKENED_SEARCH)
    if weak:
        findings.append(_finding(
            "load.search-order-weak", "warning",
            f"{', '.join(weak)} weakens DLL search order (removes app/locked dirs) - "
            "sets up DLL hijacking",
            evidence=", ".join(weak)))
    fetch = sorted(names & DLL_FETCH)
    if fetch and (ll or weak):
        findings.append(_finding(
            "load.searchpath", "info",
            "SearchPath/FindFirstFile used alongside dynamic loading - "
            "audit for hijackable resolution", evidence=", ".join(fetch)))
    # injection primitives
    inj = sorted(names & INJECTION_APIS)
    triad = sorted(INJECTION_TRIAD & names)
    if len(triad) >= 3:
        findings.append(_finding(
            "inject.remote-thread-triad", "error",
            "classic remote-injection triad present "
            "(VirtualAllocEx+WriteProcessMemory+CreateRemoteThread)",
            evidence=", ".join(triad)))
    elif inj:
        findings.append(_finding(
            "inject.process-injection-api", "warning",
            f"process-injection primitives present: {', '.join(inj[:6])} - "
            "flag if paired with a remote target",
            evidence=", ".join(inj[:6])))
    # weak crypto
    wc = sorted(names & WEAK_CRYPTO)
    if wc:
        weak_sev = "warning" if any(
            x in wc for x in ("MD5Init", "MD5_Init", "RC4", "EVP_rc4")) else "info"
        findings.append(_finding(
            "crypto.weak", weak_sev,
            f"weak/legacy crypto primitives: {', '.join(wc[:6])}",
            evidence=", ".join(wc[:6])))
    # dangerous memory functions
    mem = sorted(names & DANGEROUS_MEM)
    dangerous_hits = [x for x in mem if x in
                      ("strcpy", "strcat", "sprintf", "gets", "scanf",
                       "fscanf", "wcscpy", "wcscat", "vsprintf")]
    if dangerous_hits:
        sev = "warning"
        if mit.get("fortify") is True:
            sev = "info"
        findings.append(_finding(
            "mem.dangerous", sev,
            f"unbounded memory functions: {', '.join(dangerous_hits[:6])} - "
            "layout-dependent overflow risk",
            evidence=", ".join(dangerous_hits[:6])))
    return findings


def _mitigation_findings(mit: dict) -> List[dict]:
    findings = []
    fmt = mit.get("format", "")
    checks = [
        ("nx", "NX (non-exec stack)", "error"),
        ("pie", "PIE", "warning"),
        ("canary", "stack canary", "warning"),
    ]
    for key, label, sev in checks:
        val = mit.get(key)
        if val is None:
            continue
        if not val:
            findings.append(_finding(f"mit.{key}-missing", sev,
                                     f"{label} missing - truncates exploit defense"))
    relro = mit.get("relro")
    if relro == "partial":
        findings.append(_finding("mit.relro-partial", "warning",
                                 "partial RELRO only - bulk GOT overwrite viable"))
    elif relro is None and fmt == "ELF":
        pass  # many older/all-static ELF lack RELRO tags
    if fmt == "PE":
        if mit.get("aslr") is False:
            findings.append(_finding("mit.aslr-missing", "error",
                                     "ASLR (DYNAMIC_BASE) not set - predictable image base"))
        if mit.get("dep") is False:
            findings.append(_finding("mit.dep-missing", "error",
                                     "DEP (NX_COMPAT) not set - stack/data execution permitted"))
        if mit.get("cfg") is False:
            findings.append(_finding("mit.cfg-missing", "warning",
                                     "Control Flow Guard (GUARD_CF) not enabled"))
    if mit.get("fortify") is False:
        findings.append(_finding("mit.fortify", "info",
                                 "FORTIFY_SOURCE not detected - safer libc wrappers absent"))
    return findings


def _dotnet_findings(path: Path, imports: List[str]) -> List[dict]:
    findings = []
    blob = "\n".join(_binary_strings(path, min_len=10)[:8000])
    seen = [s for s in DOTNET_SER_SINKS if s in blob]
    if seen:
        findings.append(_finding(
            "dotnet.deserialization", "error",
            f".NET unsafe deserializer referenced: {', '.join(seen)} - "
            "ysoserial-style gadget abuse common",
            evidence=", ".join(seen)))
    if re.search(r"\bProcess\.Start\b", blob) or "System.Diagnostics.Process" in blob:
        findings.append(_finding(
            "dotnet.process-start", "warning",
            "System.Diagnostics.Process start sinks - verify argument "
            "handling (command injection)", evidence="Process.Start"))
    if re.search(r"\bMicrosoft\.VBScript|WScript\.Shell\b", blob):
        findings.append(_finding(
            "dotnet.script-engine", "warning",
            "COM script engine (VBScript.Shell) referenced", evidence="VBScript.Shell"))
    return findings


# ---------------------------------------------------------------------------
# YARA pass
# ---------------------------------------------------------------------------

def _yara_scan(path: Path, rules_dir: Path) -> List[dict]:
    findings = []
    try:
        import yara  # type: ignore
    except Exception:
        return findings
    if not rules_dir.is_dir():
        return findings
    rule_files = sorted(rules_dir.glob("*.yar*"))
    if not rule_files:
        return findings
    broken = []
    for i, f in enumerate(rule_files):
        try:
            rules = yara.compile(filepaths={str(i): str(f)})
            for m in rules.match(str(path), timeout=15):
                meta = m.meta or {}
                sev = str(meta.get("severity", "warning")).lower()
                if sev not in SEVERITY_ORDER:
                    sev = "warning"
                findings.append(_finding(
                    "yara.match", sev, f"YARA rule '{m.rule}' matched",
                    evidence=meta.get("description", "")))
        except Exception as e:
            broken.append(f"{f.name}: {str(e)[:60]}")
    if broken:
        findings.append(_finding(
            "yara.set-incomplete", "info",
            f"{len(broken)} bundled YARA rule file(s) failed to compile - "
            "skipped for this scan",
            evidence="; ".join(broken)[:160]))
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_artifact(path: Path) -> str:
    t = detect_type(path)
    if t == "Mach-O fat" and path.suffix.lower() == ".class":
        return "CLASS"
    if t != "unknown":
        return t
    try:
        head = path.open("rb").read(4)
    except OSError:
        return "unknown"
    for magic, label in BYTECODE_MAGIC:
        if head.startswith(magic):
            return label
    # Python bytecode: magic words 3.7-3.10 store as 3x 0d 0d 0a; 3.11+
    # reordered to 55 0a 0d <minor-tweak> with a PEP-552 flag bit variant.
    if (head[1:4] in (b"\x0d\x0d\x0a",) and head[0:1] in
            (b"\x42", b"\x55", b"\x61", b"\x6f", b"\xa0", b"\xb0", b"\xcb",
             b"\xd0", b"\xf0")):
        return "PYC"
    if (head[0:1] == b"\x55" and head[1:2] == b"\x0a" and head[2:3] == b"\x0d"):
        return "PYC"
    return "unknown"


def scan_binary(path: Path, with_yara: bool = False,
                yara_rules_dir: Optional[Path] = None) -> dict:
    """Analyze a single compiled artifact and return its findings."""
    ftype = detect_artifact(path)
    if ftype == "unknown":
        try:
            if path.suffix.lower() in (".jar", ".war", ".ear", ".apk",
                                       ".msi", ".nupkg") and \
               path.open("rb").read(4).startswith(b"PK"):
                ftype = "ARCHIVE"
            else:
                return {"file": str(path), "type": "unknown",
                        "findings": [], "skipped": "not a compiled artifact"}
        except OSError:
            return {"file": str(path), "type": "unknown", "findings": [],
                    "skipped": "unreadable"}

    info: dict = {
        "file": str(path),
        "name": path.name,
        "type": ftype,
        "size": path.stat().st_size,
        "sha256": sha256_first(path)[:32],
        "arch": "",
        "mit": {},
        "libraries": [],
        "imports": [],
        "findings": [],
    }

    if ftype == "ELF":
        a = _elf_analysis(path)
        info.update(a)
        info["imports"] = a["imports"]
        info["libraries"] = a["needed"]
    elif ftype == "PE":
        a = _pe_analysis(path)
        info.update({"mit": a["mit"], "imports": a["imports"],
                     "libraries": a["dlls"], "arch": a["arch"]})
        info["dotnet"] = a["dotnet"]
    elif ftype == "Mach-O" or ftype.startswith("Mach-O"):
        a = _macho_analysis(path)
        info.update({"mit": a["mit"], "imports": a["imports"], "arch": a["arch"]})
    else:
        info["mit"] = {"format": ftype}

    f = []
    f += _mitigation_findings(info.get("mit", {}))
    f += _import_findings(info.get("imports", []), info.get("mit", {}))
    f += _string_findings(path, ftype)
    if ftype == "CLASS":
        f += _java_findings(path)
    if ftype in ("ELF", "PE"):
        for lf in info.get("load_findings", []):
            f.append(lf)
    if info.get("dotnet"):
        f += _dotnet_findings(path, info.get("imports", []))
    if with_yara:
        f += _yara_scan(path, yara_rules_dir or DEFAULT_YARA_DIR)

    info["findings"] = f
    # runtime fingerprint for the report
    if ftype == "PYC":
        info["runtime"] = "python-bytecode"
    elif "go1." in "\n".join(_binary_strings(path, 4)[:4000]):
        info["runtime"] = "go"
    elif "rustc" in "\n".join(_binary_strings(path, 4)[:4000]):
        info["runtime"] = "rust"
    return info


def _filtered(f_indings: List[dict], min_severity: str) -> List[dict]:
    want = SEVERITY_ORDER.get(min_severity, 0)
    return [x for x in f_indings if SEVERITY_ORDER.get(x["severity"], 0) >= want]


def scan_directory(root: Path, max_depth: int = 4, with_yara: bool = False,
                   min_severity: str = "info",
                   exclude_dirs: Optional[Set[str]] = None,
                   limit: int = MAX_DIR_LIMIT) -> dict:
    """Scan a directory tree of compiled artifacts.  Returns structured report."""
    root = Path(root)
    ex = set(exclude_dirs) if exclude_dirs is not None else set(DEFAULT_EXCLUDE_DIRS)
    results: List[dict] = []
    errors: List[dict] = []
    found = 0
    try:
        entries = _rglob_depth(root, max_depth if max_depth > 0 else 10 ** 9, ex)
    except OSError as e:
        return {"target": str(root), "scanned": 0, "results": [], "errors": [],
                "summary": {"error": str(e)}}
    for p in entries[:limit * 4]:
        if not p.is_file():
            continue
        try:
            if p.stat().st_size > 4 * 1024 * 1024 * 1024:
                continue
        except OSError:
            continue
        t = detect_artifact(p)
        if t == "unknown":
            continue
        found += 1
        try:
            res = scan_binary(p, with_yara=with_yara)
            res["findings"] = _filtered(res.get("findings", []), min_severity)
            results.append(res)
        except Exception as e:  # noqa: BLE001
            errors.append({"file": str(p), "error": str(e)})
        if found >= limit:
            break

    summary = _summarize(results)
    return {"target": str(root), "scanned": found, "results": results,
            "errors": errors, "summary": summary}


def scan_target(target: str, max_depth: int = 4, with_yara: bool = False,
                min_severity: str = "info") -> dict:
    """Scan a file or directory (returns directory-style report)."""
    p = Path(target)
    if p.is_file():
        res = scan_binary(p, with_yara=with_yara)
        res["findings"] = _filtered(res.get("findings", []), min_severity)
        return {"target": str(p), "scanned": 1, "results": [res], "errors": [],
                "summary": _summarize([res])}
    return scan_directory(p, max_depth=max_depth, with_yara=with_yara,
                          min_severity=min_severity)


def _summarize(results: List[dict]) -> dict:
    by_sev: Dict[str, int] = {"error": 0, "warning": 0, "info": 0}
    by_cat: Dict[str, int] = {}
    top: List[dict] = []
    for r in results:
        for f in r.get("findings", []):
            sev = f["severity"]
            by_sev[sev] = by_sev.get(sev, 0) + 1
            cat = (f.get("id") or "?").split(".", 1)[0]
            by_cat[cat] = by_cat.get(cat, 0) + 1
        if r.get("type") == "unknown":
            continue
        top.append({"file": r["name"], "type": r.get("type", ""),
                    "n": len(r.get("findings", [])),
                    "max_sev": max((f["severity"] for f in r.get("findings", [])),
                                   key=lambda s: SEVERITY_ORDER.get(s, 0))
                    if r.get("findings") else "info"})
    top.sort(key=lambda x: (-SEVERITY_ORDER.get(x["max_sev"], 0), -x["n"]))
    return {"files": len(results), "findings": sum(by_sev.values()),
            "severity": by_sev, "categories": dict(
                sorted(by_cat.items(), key=lambda kv: -kv[1])),
            "top_files": top[:25]}


def format_report(r: Dict) -> str:
    if isinstance(r, dict) and r.get("summary", {}).get("error"):
        return f"Error: {r['summary']['error']}"
    lines = [f"Compiled-artifact scan of {r.get('target')}: {r.get('scanned')} "
             f"artifact(s)"]
    s = r.get("summary", {})
    sev = s.get("severity", {})
    lines.append(f"  findings: {s.get('findings', 0)} total "
                 f"({sev.get('error', 0)} error, {sev.get('warning', 0)} warning, "
                 f"{sev.get('info', 0)} info)")
    cats = s.get("categories", {})
    if cats:
        lines.append("  categories: " + ", ".join(f"{k}={v}" for k, v in cats.items()))
    for b in r.get("results", []):
        fs = b.get("findings", [])
        lines.append("")
        lines.append(f"== {b.get('name', b.get('file', '?'))} ({b.get('type', '?')}"
                     f"{'/' + b.get('arch', '') if b.get('arch') else ''}, "
                     f"{b.get('size', 0)} B) sha={b.get('sha256', '')[:12]}")
        mit = b.get("mit", {})
        if mit:
            mm = []
            for k in ("nx", "pie", "canary", "aslr", "dep", "cfg", "relro"):
                v = mit.get(k)
                if v is not None:
                    mm.append(f"{k}={v}")
            if mm:
                lines.append("  mitigations: " + ", ".join(mm))
        if b.get("libraries"):
            lines.append("  libs: " + ", ".join(b["libraries"][:12]))
        if b.get("rpath") or b.get("runpath"):
            lines.append("  rpath/runpath: "
                         + "; ".join((b.get("rpath") or [])[:3]
                                     + (b.get("runpath") or [])[:3]))
        if b.get("runtime"):
            lines.append(f"  runtime: {b['runtime']}")
        order = {"error": 0, "warning": 1, "info": 2}
        for f in sorted(fs, key=lambda x: order.get(x["severity"], 3)):
            ev = f"  [{f['evidence']}]" if f.get("evidence") else ""
            lines.append(f"  [{f['severity']}] {f['id']}: {f['title']}{ev}")
    for e in r.get("errors", [])[:5]:
        lines.append(f"  ERR {e['file']}: {e['error']}")
    return "\n".join(lines)