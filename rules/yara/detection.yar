rule webshell_detect_common
{
  meta:
    description = "Detect common PHP/JSP/ASP webshell patterns"
    author = "cc-toolkit"
    reference = "MITRE ATT&CK T1500"
    date = "2026-06-03"
  strings:
    $php1 = "eval($_" ascii nocase
    $php2 = "system($_" ascii nocase
    $php3 = "exec($_" ascii nocase
    $php4 = "shell_exec($_" ascii nocase
    $php5 = "assert($_" ascii nocase
    $php6 = "popen($_" ascii nocase
    $php7 = "passthru($_" ascii nocase
    $php8 = "base64_decode($_" ascii nocase
    $jsp1 = "Runtime.getRuntime().exec" ascii nocase
    $jsp2 = "java.lang.Runtime" ascii nocase
    $asp1 = "CreateObject(\"WScript.Shell\")" ascii nocase
    $asp2 = "CreateObject(\"Shell.Application\")" ascii nocase
    $asp3 = "Server.CreateObject(\"WScript.Shell\")" ascii nocase
    $backdoor = "backdoor" ascii nocase
    $cmd = "cmd.exe" ascii nocase
  condition:
    any of ($php*) or any of ($jsp*) or any of ($asp*)
}

rule cobalt_strike_beacon
{
  meta:
    description = "Detect Cobalt Strike beacon artifacts in memory/files"
    author = "cc-toolkit"
    reference = "MITRE ATT&CK S0154"
    date = "2026-06-03"
  strings:
    $m1 = "MZ" fullword
    $ref1 = "ReflectiveLoader"
    $pipe1 = "\msagent_"
    $pipe2 = "\postex_"
    $namedpipe = "\\\\.\\pipe\\"
    $watermark = "x00x00x00x00"     // MZ header watermark offset pattern
    $config1 = "0x2e"               // common config marker
    $beacon = "beacon" ascii nocase
    $x64 = "x64" ascii nocase
  condition:
    ($m1 at 0) and (any of ($ref1,$beacon,$x64))
}

rule mimikatz_detect
{
  meta:
    description = "Detect Mimikatz binary or embedded strings"
    author = "cc-toolkit"
    reference = "MITRE ATT&CK S0002"
    date = "2026-06-03"
  strings:
    $s1 = "mimikatz" ascii nocase
    $s2 = "sekurlsa::" ascii nocase
    $s3 = "kerberos::" ascii nocase
    $s4 = "privilege::debug" ascii nocase
    $s5 = "lsadump::" ascii nocase
    $s6 = "token::" ascii nocase
    $s7 = "crypto::" ascii nocase
    $s8 = "DPAPI::" ascii nocase
    $s9 = "wdigest" ascii nocase
    $s10 = "\\\\.\\minidrv" ascii
  condition:
    3 of ($s*)
}

rule base64_suspicious_strings
{
  meta:
    description = "Detect base64-encoded strings with suspicious keywords"
    author = "cc-toolkit"
    date = "2026-06-03"
  strings:
    $b64 = /[A-Za-z0-9+\/]{40,}={0,2}/
    $cmd_keywords = "cmd" nocase
    $pwsh_keywords = "powershell" nocase
    $exec_keywords = "exec" nocase
    $download_keywords = "download" nocase
  condition:
    #b64 > 3 and (any of ($cmd_keywords, $pwsh_keywords, $exec_keywords, $download_keywords))
}

rule crypto_miner_common
{
  meta:
    description = "Detect common cryptocurrency miner binaries and scripts"
    author = "cc-toolkit"
    reference = "MITRE ATT&CK T1496"
    date = "2026-06-03"
  strings:
    $xmrig = "xmrig" ascii nocase
    $cpuminer = "cpuminer" ascii nocase
    $minerd = "minerd" ascii nocase
    $ethminer = "ethminer" ascii nocase
    $ccminer = "ccminer" ascii nocase
    $stratum = "stratum+tcp" ascii nocase
    $pool_addr = /pool\d*\./ ascii nocase
    $wallet = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
  condition:
    2 of ($xmrig, $cpuminer, $minerd, $ethminer, $ccminer) or
    ($stratum and $pool_addr) or
    ($stratum and $wallet)
}

rule php_backdoor_eval_base64
{
  meta:
    description = "Detect eval(base64_decode(...)) pattern common in PHP backdoors"
    author = "cc-toolkit"
    date = "2026-06-03"
  strings:
    $eval_b64 = "eval(base64_decode(" ascii nocase
    $eval_gz = "eval(gzinflate(base64_decode(" ascii nocase
    $eval_str = "eval(str_rot13(" ascii nocase
    $assert_b64 = "assert(base64_decode(" ascii nocase
    $preg_replace_e = "/e" ascii
  condition:
    any of them
}

rule sus_ip_in_file
{
  meta:
    description = "Detect hardcoded suspicious IP addresses in files"
    author = "cc-toolkit"
    date = "2026-06-03"
  strings:
    $ip_range1 = /10\.\d{1,3}\.\d{1,3}\.\d{1,3}/
    $ip_range2 = /192\.168\.\d{1,3}\.\d{1,3}/
    $ip_range3 = /172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}/
    $c2_port = /:\d{4,5}/
  condition:
    (any of ($ip_range*)) and $c2_port
}
