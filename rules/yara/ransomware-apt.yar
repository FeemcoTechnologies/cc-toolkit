rule lockbit_ransomware
{
  meta:
    description = "Detect LockBit ransomware artifacts"
    author = "cc-toolkit"
    reference = "MITRE ATT&CK S1047"
    date = "2026-06-03"
  strings:
    $mutex = "Global\\LockBit" nocase
    $note1 = "Restore-My-Files" nocase
    $note2 = "lockbit" nocase
    $note3 = "README.txt" nocase
    $ext = ".lockbit" nocase
    $banner = "LockBit" ascii
    $config = "LockBitConfig" nocase
    $stealer = "LockBitStealer" nocase
  condition:
    3 of ($mutex, $note*, $ext, $banner, $config, $stealer)
}

rule blackcat_ransomware
{
  meta:
    description = "Detect BlackCat/ALPHV ransomware artifacts"
    author = "cc-toolkit"
    reference = "MITRE ATT&CK S1068"
    date = "2026-06-03"
  strings:
    $note1 = "ALPHV" ascii nocase
    $note2 = "BlackCat" ascii nocase
    $ext = ".blackcat" nocase
    $ransom_note = "recove" nocase
    $rust_panic = "panicked at" ascii
    $rust_crate = "cargo:" ascii
    $cli = "clap" ascii
  condition:
    2 of ($note*, $ext, $rust*, $cli) or ($rust_panic and $ransom_note)
}

rule ryuk_ransomware
{
  meta:
    description = "Detect Ryuk ransomware artifacts"
    author = "cc-toolkit"
    reference = "MITRE ATT&CK S0446"
    date = "2026-06-03"
  strings:
    $note1 = "Ryuk" ascii nocase
    $note2 = "RyukReadMe" ascii nocase
    $note3 = "RyukRansomware" ascii nocase
    $ext = ".ryk" nocase
    $shadow = "vssadmin" ascii nocase
    $bcdedit = "bcdedit" ascii nocase
    $wmic_del = "wmic" ascii
    $scheduled = "schtasks" ascii
  condition:
    2 of ($note*, $ext, $bcdedit, $scheduled) or ($shadow and $wmic_del)
}

rule apt29_nobellium
{
  meta:
    description = "Detect APT29 / Cozy Bear / NOBELIUM artifacts"
    author = "cc-toolkit"
    reference = "MITRE ATT&CK G0016"
    date = "2026-06-03"
  strings:
    $solarwinds = "SolarWinds" ascii nocase
    $teardrop = "Teardrop" ascii nocase
    $goldmax = "GoldMax" ascii nocase
    $sibot = "Sibot" ascii nocase
    $envy = "ENVYSCOUT" ascii nocase
    $boom = "BOOMBOX" ascii nocase
    $vapor = "VAPORSTEAM" ascii nocase
    $native = "NativeZone" ascii
    $dll_sideload = "DLL load from" ascii
  condition:
    any of ($solarwinds, $teardrop, $goldmax, $sibot) or
    2 of ($envy, $boom, $vapor, $native, $dll_sideload)
}

rule apt28_fancybear
{
  meta:
    description = "Detect APT28 / Fancy Bear / Sofacy artifacts"
    author = "cc-toolkit"
    reference = "MITRE ATT&CK G0007"
    date = "2026-06-03"
  strings:
    $xagent = "XAgent" ascii nocase
    $xagent_config = "XAgentConfig" ascii
    $usb_stealer = "USBStealer" ascii nocase
    $sednit = "Sednit" ascii nocase
    $zebrocy = "Zebrocy" ascii nocase
    $grizzly = "Grizzly" ascii
    $dsquery = "dsquery" ascii
    $adfind = "AdFind" ascii nocase
  condition:
    2 of them
}

rule lazarus_ransomware
{
  meta:
    description = "Detect Lazarus Group / HIDDEN COBRA artifacts"
    author = "cc-toolkit"
    reference = "MITRE ATT&CK G0032"
    date = "2026-06-03"
  strings:
    $wanna = "WannaCry" ascii nocase
    $hoplight = "HopLight" ascii nocase
    $bankshot = "Bankshot" ascii nocase
    $manuscrypt = "Manuscrypt" ascii nocase
    $dtrack = "DDTrack" ascii nocase
    $free_lot = "FreeLOT" ascii nocase
    $apple = "AppleJeus" ascii nocase
    $trojan = "TROJAN" ascii
    $mimikatz = "mimikatz" ascii nocase
  condition:
    2 of ($wanna, $hoplight, $bankshot, $manuscrypt, $dtrack, $free_lot,
          $apple, $trojan, $mimikatz)
}

rule conti_ransomware
{
  meta:
    description = "Detect Conti ransomware artifacts"
    author = "cc-toolkit"
    reference = "MITRE ATT&CK S0575"
    date = "2026-06-03"
  strings:
    $note1 = "CONTIt" ascii nocase
    $note2 = "CONTI" ascii
    $note3 = "CONTINOTE" ascii nocase
    $ext = ".conti" nocase
    $config = "ContiConfig" ascii nocase
    $enc_ext = ".enc" ascii
  condition:
    2 of ($note*, $ext, $config, $enc_ext)
}

rule revil_ransomware
{
  meta:
    description = "Detect REvil / Sodinokibi ransomware artifacts"
    author = "cc-toolkit"
    reference = "MITRE ATT&CK S0496"
    date = "2026-06-03"
  strings:
    $note1 = "REvil" ascii nocase
    $note2 = "Sodin" ascii nocase
    $note3 = "Sodinokibi" ascii nocase
    $ext = ".revil" nocase
    $ext2 = ".sodin" nocase
    $note_file = "readme" ascii nocase
    $tor_site = ".onion" ascii
  condition:
    2 of ($note*, $ext, $ext2, $tor_site, $note_file)
}

rule apt41_group
{
  meta:
    description = "Detect APT41 / Winnti Group artifacts"
    author = "cc-toolkit"
    reference = "MITRE ATT&CK G0096"
    date = "2026-06-03"
  strings:
    $winnti = "Winnti" ascii nocase
    $shadowpad = "ShadowPad" ascii nocase
    $plugx = "PlugX" ascii nocase
    $aclp = "ACLP" ascii
    $bshell = "BSHELL" ascii
    $port_reuse = "PortReuse" ascii nocase
  condition:
    2 of them
}
