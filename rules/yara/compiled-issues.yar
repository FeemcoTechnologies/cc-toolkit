/*
 * compiled-issues.yar
 * Security-issue signatures for compiled artifacts (PE/ELF/Mach-O/.NET/.pyc/etc).
 * Complementary to the python heuristic pass in modules/compiled_scan.py.
 * NOTE: YARA sees strings/patterns, not dataflow - treat matches as leads,
 * not proof. A '%s' next to system() is interesting; a lone "system" import
 * usually is not.
 */
rule win_exec_command_sink
{
  meta:
    description = "Common command-execution API surface in a compiled binary (system/WinExec/ShellExecute/CreateProcess/popen). Review whether input reaches these."
    author = "cc-toolkit"
    severity = "warning"
    reference = "MITRE ATT&CK T1059; CWE-78"
    date = "2026-09-08"
  strings:
    $s1 = "system(" ascii wide nocase
    $s2 = "_wsystem" ascii wide nocase
    $s3 = "popen(" ascii wide nocase
    $s4 = "WinExec" ascii wide 
    $s5 = "ShellExecute" ascii wide
    $s6 = "CreateProcess" ascii wide
    $s7 = "Process.Start" ascii wide
    $s8 = "/bin/sh" ascii wide nocase
    $s9 = "cmd.exe" ascii wide nocase
    $s10 = "powershell" ascii wide nocase
  condition:
    2 of them
}

rule process_injection_remote_thread
{
  meta:
    description = "Remote-thread process injection triad (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)."
    author = "cc-toolkit"
    severity = "error"
    reference = "MITRE ATT&CK T1055.001; CWE-749"
    date = "2026-09-08"
  strings:
    $alloc = "VirtualAllocEx" ascii wide
    $write = "WriteProcessMemory" ascii wide
    $thread = "CreateRemoteThread" ascii wide
  condition:
    all of them
}

rule process_injection_apc
{
  meta:
    description = "APC process-injection indicators (QueueUserAPC with remote-vm write primitives)."
    author = "cc-toolkit"
    severity = "warning"
    reference = "MITRE ATT&CK T1055.004; CWE-749"
    date = "2026-09-08"
  strings:
    $apc = "QueueUserAPC" ascii wide
    $alloc = "VirtualAllocEx" ascii wide
    $protect = "VirtualProtectEx" ascii wide
    $nwrite = "NtWriteVirtualMemory" ascii wide
    $write = "WriteProcessMemory" ascii wide
  condition:
    $apc and any of ($alloc, $protect, $nwrite, $write)
}

rule process_hollowing_runpe
{
  meta:
    description = "Process hollowing / RunPE indicators (unmap + process-memory writes + thread context)."
    author = "cc-toolkit"
    severity = "warning"
    reference = "MITRE ATT&CK T1055.012; CWE-749"
    date = "2026-09-08"
  strings:
    $unmap = "NtUnmapViewOfSection" ascii wide
    $zwunmap = "ZwUnmapViewOfSection" ascii wide
    $ctx = "SetThreadContext" ascii wide
    $write = "WriteProcessMemory" ascii wide
    $create = "CreateProcess" ascii wide
    $resume = "ResumeThread" ascii wide
  condition:
    (any of ($unmap, $zwunmap)) and any of ($ctx, $write) and any of ($create, $resume)
}

rule win_hook_injection
{
  meta:
    description = "Windows hook / message-queue DLL injection indicators."
    author = "cc-toolkit"
    severity = "warning"
    reference = "MITRE ATT&CK T1055.003; CWE-749"
    date = "2026-09-08"
  strings:
    $hook = "SetWindowsHookEx" ascii wide
    $load = "LoadLibrary" ascii wide
    $ule = "UnhookWindowsHookEx" ascii wide
    $burp = "NtQueueApcThread" ascii wide
  condition:
    $hook and (any of ($load, $ule, $burp))
}

rule insecure_dll_load
{
  meta:
    description = "Unsafely-loaded DLLs: dynamic/variable LoadLibrary-family use, relative search, or a call that weakens the DLL search order (DLL hijacking risk)."
    author = "cc-toolkit"
    severity = "warning"
    reference = "CWE-114; CWE-427; MITRE ATT&CK T1574.001/T1574.002"
    date = "2026-09-08"
  strings:
    $load1 = "LoadLibrary" ascii wide
    $load2 = "LdrLoadDll" ascii wide
    $load3 = "LoadPackagedLibrary" ascii wide
    $dlopen = "dlopen" ascii wide nocase
    $weak1 = "SetDllDirectory" ascii wide
    $weak2 = "AddDllDirectory" ascii wide
    $rel = /[\\\/][A-Za-z0-9_.-]+\.(dll|so)\b/ ascii wide nocase
  condition:
    ((any of ($load1, $load2, $load3) or $dlopen) and $rel) or
    (any of ($weak1, $weak2) and any of ($load1, $load2, $load3))
}

rule search_path_dll_fetch
{
  meta:
    description = "DLL resolved via filesystem search then loaded - weak search-order / binary-planting risk."
    author = "cc-toolkit"
    severity = "info"
    reference = "CWE-426; MITRE ATT&CK T1574.001"
    date = "2026-09-08"
  strings:
    $load = "LoadLibrary" ascii wide
    $dlopen = "dlopen" ascii wide nocase
    $search = "SearchPath" ascii wide
    $find = "FindFirstFile" ascii wide
  condition:
    (any of ($load, $dlopen)) and (any of ($search, $find))
}

rule weak_crypto_primitives
{
  meta:
    description = "Weak/deprecated crypto primitives referenced (MD5/SHA1/RC4/DES, weak RNG)."
    author = "cc-toolkit"
    severity = "warning"
    reference = "CWE-327; CWE-338"
    date = "2026-09-08"
  strings:
    $s1 = "MD5" ascii wide nocase
    $s2 = "MD4" ascii wide nocase
    $s3 = "SHA1" ascii wide nocase
    $s4 = "EVP_sha1" ascii wide nocase
    $s5 = "RC4" ascii wide nocase
    $s6 = "DES_set_key" ascii wide nocase
    $s7 = "EVP_des" ascii wide nocase
    $s8 = "srand(" ascii wide nocase
    $s9 = "rand(" ascii wide nocase
    $s10 = "arc4random_buf" ascii wide nocase
    $s11 = "openssl/md5" ascii wide nocase
    $s12 = "openssl/rc4" ascii wide nocase
  condition:
    2 of them
}

rule hardcoded_secrets_binary
{
  meta:
    description = "Hardcoded credential/secret signature embedded in the binary (API keys, JWT, private keys)."
    author = "cc-toolkit"
    severity = "error"
    reference = "CWE-798"
    date = "2026-09-08"
  strings:
    $awskey = /AKIA[0-9A-Z]{16}/ ascii
    $ghpat  = /(ghp_|gho_|ghu_|ghs_|github_pat_)[0-9A-Za-z_-]{20,}/ ascii
    $slack  = /xox[baprs]-[0-9A-Za-z-]{10,}/ ascii
    $jwt    = /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._\/-]{10,}/ ascii
    $priv   = /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/ ascii
  condition:
    any of them
}

rule url_embedded_credentials
{
  meta:
    description = "URL with embedded user:pass@ (credentials in a URI). Often benign defaults/examples in help text - verify it's not shipped config."
    author = "cc-toolkit"
    severity = "warning"
    reference = "CWE-798"
    date = "2026-09-08"
  strings:
    $urlcred = /[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^@\/\s:]+:[^@\/\s]+@/ ascii nocase
  condition:
    any of them
}

rule dangerous_memory_functions_unmitigated
{
  meta:
    description = "Unbounded copy/format functions present WITHOUT glibc fortify/_chk variants (classic overflow sinks)."
    author = "cc-toolkit"
    severity = "warning"
    reference = "CWE-120; CWE-121; CWE-787"
    date = "2026-09-08"
  strings:
    $d1 = "strcpy" ascii wide nocase
    $d2 = "strcat" ascii wide nocase
    $d3 = "sprintf" ascii wide nocase
    $d4 = "vsprintf" ascii wide nocase
    $d5 = "gets(" ascii wide nocase
    $d6 = "strtok(" ascii wide nocase
    $d7 = "wcscpy" ascii wide nocase
    $d8 = "memcpy" ascii wide
    $f1 = "__strcpy_chk" ascii
    $f2 = "__sprintf_chk" ascii
    $f3 = "__vsnprintf_chk" ascii
    $f4 = "__memcpy_chk" ascii
    $f5 = "__stack_chk_fail" ascii
  condition:
    any of ($d*) and not any of ($f*)
}

rule executable_memory_alloc
{
  meta:
    description = "Alloc + memory-protection + thread/exec linked to executable pages (RWX pattern, shellcode exec, self-inject)."
    author = "cc-toolkit"
    severity = "warning"
    reference = "CWE-749; MITRE ATT&CK T1055"
    date = "2026-09-08"
  strings:
    $alloc = "VirtualAlloc" ascii wide
    $vprot = "VirtualProtect" ascii wide
    $flprot = "flProtect" ascii wide
    $exej = "PAGE_EXECUTE" ascii wide nocase
    $thread = "CreateThread" ascii wide
    $nmalloc = "NtAllocateVirtualMemory" ascii wide
  condition:
    ((any of ($alloc, $nmalloc)) or $vprot) and ($flprot or $exej or $thread)
}

rule packed_or_obfuscated_binary
{
  meta:
    description = "Packed / VM-protected binary markers (UPX, Themida, VMProtect, .NET re-packing)."
    author = "cc-toolkit"
    severity = "info"
    reference = "CWE-920; MITRE ATT&CK T1027.002"
    date = "2026-09-08"
  strings:
    $upx0 = "UPX0" ascii
    $upx1 = "UPX1" ascii
    $upx2 = "UPX2" ascii
    $upxmagic = "UPX!" ascii
    $themida = ".themida" ascii nocase
    $vmp = "VMProtect" ascii nocase
    $aspack = ".aspack" ascii nocase
    $pecompact = ".pec1" ascii nocase
    $mpress = ".MPRESS1" ascii nocase
  condition:
    ($upx0 and $upx1 and $upx2) or any of ($upxmagic, $themida, $vmp, $aspack, $pecompact, $mpress)
}

rule at_execcalled_via_export
{
  meta:
    description = "Indirectly-called AT/command-scheduler or service-control primitives commonly abused for persistence (AT, schtasks, service creation APIs)."
    author = "cc-toolkit"
    severity = "info"
    reference = "MITRE ATT&CK T1053/T1543"
    date = "2026-09-08"
  strings:
    $s1 = "schtasks" ascii wide nocase
    $s2 = "CreateService" ascii wide
    $s3 = "OpenSCManager" ascii wide
    $s4 = "NetUserAdd" ascii wide
    $s5 = "WNetAddConnection" ascii wide
    $s6 = "wmic " ascii wide nocase
    $s7 = "certutil" ascii wide nocase
  condition:
    2 of them
}