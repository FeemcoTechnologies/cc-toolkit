"""Reference data: LDAP filters, Windows Event IDs, CVE lists."""
from typing import List, Dict

# ---------------------------------------------------------------------------
# LDAP Filters reference
# ---------------------------------------------------------------------------
LDAP_FILTERS: List[Dict[str, str]] = [
    {"name": "All users", "filter": "(objectClass=user)", "desc": "Return all user objects"},
    {"name": "All computers", "filter": "(objectClass=computer)", "desc": "Return all computer objects"},
    {"name": "Domain admins", "filter": "(memberOf=CN=Domain Admins,CN=Users,DC=domain,DC=local)", "desc": "Domain Admins group members"},
    {"name": "Enterprise admins", "filter": "(memberOf=CN=Enterprise Admins,CN=Users,DC=domain,DC=local)", "desc": "Enterprise Admins group members"},
    {"name": "Schema admins", "filter": "(memberOf=CN=Schema Admins,CN=Users,DC=domain,DC=local)", "desc": "Schema Admins group members"},
    {"name": "AdminCount=1", "filter": "(adminCount=1)", "desc": "Privileged users/groups (PADA attribute)"},
    {"name": "AS-REP roastable", "filter": "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))", "desc": "Users with DONT_REQ_PREAUTH set — AS-REP roastable"},
    {"name": "Kerberoastable", "filter": "(&(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "desc": "Users with SPNs — kerberoastable"},
    {"name": "PwdLastSet=0", "filter": "(&(objectClass=user)(pwdLastSet=0))", "desc": "Users who never changed password"},
    {"name": "Disabled accounts", "filter": "(userAccountControl:1.2.840.113556.1.4.803:=2)", "desc": "Disabled user accounts"},
    {"name": "Locked out", "filter": "(lockoutTime>=1)", "desc": "Locked out user accounts"},
    {"name": "Password never expires", "filter": "(userAccountControl:1.2.840.113556.1.4.803:=65536)", "desc": "Users with password never expires flag"},
    {"name": "Constrained delegation", "filter": "(msDS-AllowedToDelegateTo=*)", "desc": "Accounts with constrained delegation"},
    {"name": "Unconstrained delegation", "filter": "(userAccountControl:1.2.840.113556.1.4.803:=524288)", "desc": "Accounts with unconstrained delegation"},
    {"name": "Resource-based delegation", "filter": "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)", "desc": "Accounts with RBCD configured"},
    {"name": "Pre-Windows 2000 group", "filter": "(&(objectClass=group)(|(groupType=-2147483643)(groupType=-2147483640)(groupType=-2147483646)))", "desc": "Pre-Windows 2000 compatible access groups"},
    {"name": "SID history present", "filter": "(sidHistory=*)", "desc": "Objects with SID history (possible SID hijacking)"},
    {"name": "Service accounts", "filter": "(&(objectClass=user)(servicePrincipalName=*))", "desc": "All accounts with SPNs"},
    {"name": "GMSA accounts", "filter": "(objectClass=msDS-GroupManagedServiceAccount)", "desc": "Group Managed Service Accounts"},
    {"name": "Domain controllers", "filter": "(userAccountControl:1.2.840.113556.1.4.803:=8192)", "desc": "Domain controller computer accounts"},
    {"name": "Group Policy objects", "filter": "(objectClass=groupPolicyContainer)", "desc": "All GPOs in domain"},
    {"name": "OUs", "filter": "(objectClass=organizationalUnit)", "desc": "All Organizational Units"},
    {"name": "Trusted domains", "filter": "(objectClass=trustedDomain)", "desc": "Domain trusts"},
    {"name": "Foreign security principals", "filter": "(objectClass=foreignSecurityPrincipal)", "desc": "Foreign security principals from trusted domains"},
    {"name": "LAPS passwords", "filter": "(ms-Mcs-AdmPwd=*)", "desc": "Computers with LAPS passwords readable"},
    {"name": "BitLocker recovery", "filter": "(msFVE-RecoveryPassword=*)", "desc": "Objects with BitLocker recovery keys"},
]

# ---------------------------------------------------------------------------
# Windows Event IDs reference (top 100 forensic-relevant)
# ---------------------------------------------------------------------------
EVENT_IDS: List[Dict[str, str]] = [
    {"id": "1102", "log": "Security", "desc": "Security audit log cleared"},
    {"id": "4624", "log": "Security", "desc": "An account was successfully logged on"},
    {"id": "4625", "log": "Security", "desc": "An account failed to log on"},
    {"id": "4634", "log": "Security", "desc": "An account was logged off"},
    {"id": "4647", "log": "Security", "desc": "Initiator logoff notification"},
    {"id": "4648", "log": "Security", "desc": "Logon using explicit credentials (RunAs)"},
    {"id": "4672", "log": "Security", "desc": "Special privileges assigned to new logon (admin logon)"},
    {"id": "4673", "log": "Security", "desc": "A privileged service was called"},
    {"id": "4688", "log": "Security", "desc": "A new process has been created (cmdline included)"},
    {"id": "4689", "log": "Security", "desc": "A process has exited"},
    {"id": "4697", "log": "Security", "desc": "A service was installed in the system"},
    {"id": "4698", "log": "Security", "desc": "A scheduled task was created"},
    {"id": "4699", "log": "Security", "desc": "A scheduled task was deleted"},
    {"id": "4700", "log": "Security", "desc": "A scheduled task was enabled"},
    {"id": "4702", "log": "Security", "desc": "A scheduled task was updated"},
    {"id": "4703", "log": "Security", "desc": "A token right was adjusted (UAC bypass)"},
    {"id": "4704", "log": "Security", "desc": "A user right was assigned"},
    {"id": "4719", "log": "Security", "desc": "System audit policy was changed"},
    {"id": "4720", "log": "Security", "desc": "A user account was created"},
    {"id": "4722", "log": "Security", "desc": "A user account was enabled"},
    {"id": "4723", "log": "Security", "desc": "An attempt was made to change an account's password"},
    {"id": "4724", "log": "Security", "desc": "An attempt was made to reset an account's password"},
    {"id": "4726", "log": "Security", "desc": "A user account was deleted"},
    {"id": "4728", "log": "Security", "desc": "A member was added to a security-enabled global group"},
    {"id": "4732", "log": "Security", "desc": "A member was added to a security-enabled local group"},
    {"id": "4735", "log": "Security", "desc": "A security-enabled local group was changed"},
    {"id": "4738", "log": "Security", "desc": "A user account was changed"},
    {"id": "4740", "log": "Security", "desc": "A user account was locked out"},
    {"id": "4742", "log": "Security", "desc": "A computer account was changed"},
    {"id": "4743", "log": "Security", "desc": "A computer account was deleted"},
    {"id": "4756", "log": "Security", "desc": "A member was added to a security-enabled universal group"},
    {"id": "4768", "log": "Security", "desc": "A Kerberos authentication ticket (TGT) was requested"},
    {"id": "4769", "log": "Security", "desc": "A Kerberos service ticket was requested (potential kerberoast)"},
    {"id": "4771", "log": "Security", "desc": "Kerberos pre-authentication failed"},
    {"id": "4776", "log": "Security", "desc": "The domain controller validated credentials (NTLM)"},
    {"id": "4778", "log": "Security", "desc": "A session was reconnected to a Window Station"},
    {"id": "4779", "log": "Security", "desc": "A session was disconnected from a Window Station"},
    {"id": "4781", "log": "Security", "desc": "The name of an account was changed"},
    {"id": "4782", "log": "Security", "desc": "The password hash an account was accessed"},
    {"id": "4793", "log": "Security", "desc": "The Password Policy Checking API was called"},
    {"id": "4798", "log": "Security", "desc": "A user's local group membership was enumerated"},
    {"id": "4799", "log": "Security", "desc": "A security-enabled local group membership was enumerated"},
    {"id": "4800", "log": "Security", "desc": "The workstation was locked"},
    {"id": "4801", "log": "Security", "desc": "The workstation was unlocked"},
    {"id": "4818", "log": "Security", "desc": "Central Access Policy on an object"},
    {"id": "4825", "log": "Security", "desc": "A user was denied access to a remote desktop"},
    {"id": "4886", "log": "Security", "desc": "Certificate Services received a certificate request"},
    {"id": "4887", "log": "Security", "desc": "Certificate Services approved a certificate request"},
    {"id": "4888", "log": "Security", "desc": "Certificate Services denied a certificate request"},
    {"id": "4898", "log": "Security", "desc": "Certificate Services loaded a template"},
    {"id": "4902", "log": "Security", "desc": "The Per-user audit policy table was created"},
    {"id": "4907", "log": "Security", "desc": "Auditing settings on object were changed"},
    {"id": "4964", "log": "Security", "desc": "Special groups have been assigned to a new logon"},
    {"id": "5038", "log": "Security", "desc": "Code integrity determined invalid image hash"},
    {"id": "5120", "log": "Security", "desc": "OCSP Responder started"},
    {"id": "5136", "log": "Security", "desc": "A directory service object was modified"},
    {"id": "5137", "log": "Security", "desc": "A directory service object was created"},
    {"id": "5140", "log": "Security", "desc": "A network share object was accessed"},
    {"id": "5142", "log": "Security", "desc": "A network share object was added"},
    {"id": "5145", "log": "Security", "desc": "A network share object was checked for access"},
    {"id": "5152", "log": "Security", "desc": "The Windows Filtering Platform blocked a packet"},
    {"id": "5156", "log": "Security", "desc": "The Windows Filtering Platform allowed a connection"},
    {"id": "5157", "log": "Security", "desc": "The Windows Filtering Platform blocked a connection"},
    {"id": "5376", "log": "Security", "desc": "Credential Manager backup"},
    {"id": "5377", "log": "Security", "desc": "Credential Manager restore"},
    {"id": "5381", "log": "Security", "desc": "Vault credentials read (DPAPI)"},
    {"id": "5382", "log": "Security", "desc": "Vault credentials were accessed"},
    {"id": "6416", "log": "Security", "desc": "A new device was recognized (PnP)"},
    {"id": "6419", "log": "Security", "desc": "A request was made to disable a device"},
    {"id": "6420", "log": "Security", "desc": "A device was disabled"},
    {"id": "6421", "log": "Security", "desc": "A request was made to enable a device"},
    {"id": "6422", "log": "Security", "desc": "A device was enabled"},
    {"id": "7045", "log": "System", "desc": "A service was installed in the system"},
    {"id": "7036", "log": "System", "desc": "The service entered the running/stopped state"},
    {"id": "1000", "log": "Application", "desc": "Application Error (crash)"},
    {"id": "1001", "log": "Application", "desc": "Windows Error Reporting (WER) crash"},
    {"id": "1002", "log": "Application", "desc": "Application Hang"},
    {"id": "20001", "log": "PowerShell", "desc": "PowerShell module/script execution (script block)"},
    {"id": "4103", "log": "PowerShell", "desc": "PowerShell pipeline execution details"},
    {"id": "4104", "log": "PowerShell", "desc": "PowerShell script block logging"},
    {"id": "4105", "log": "PowerShell", "desc": "PowerShell command started"},
    {"id": "4106", "log": "PowerShell", "desc": "PowerShell command completed"},
    {"id": "800", "log": "PowerShell", "desc": "PowerShell provider started"},
    {"id": "3", "log": "Network/EventLog", "desc": "Network connection detected (Sysmon)"},
    {"id": "1", "log": "Sysmon", "desc": "Process creation (cmdline, hash, parent)"},
    {"id": "2", "log": "Sysmon", "desc": "File creation time changed"},
    {"id": "3", "log": "Sysmon", "desc": "Network connection detected"},
    {"id": "4", "log": "Sysmon", "desc": "Sysmon service state changed"},
    {"id": "5", "log": "Sysmon", "desc": "Process terminated"},
    {"id": "6", "log": "Sysmon", "desc": "Driver loaded"},
    {"id": "7", "log": "Sysmon", "desc": "Image loaded"},
    {"id": "8", "log": "Sysmon", "desc": "CreateRemoteThread detected"},
    {"id": "9", "log": "Sysmon", "desc": "RawAccessRead (Handle) detected"},
    {"id": "10", "log": "Sysmon", "desc": "Process access (LSASS dump detection)"},
    {"id": "11", "log": "Sysmon", "desc": "File creation"},
    {"id": "12", "log": "Sysmon", "desc": "Registry object added/deleted"},
    {"id": "13", "log": "Sysmon", "desc": "Registry value set"},
    {"id": "14", "log": "Sysmon", "desc": "Registry object renamed"},
    {"id": "15", "log": "Sysmon", "desc": "File stream created"},
    {"id": "16", "log": "Sysmon", "desc": "Sysmon config state changed"},
    {"id": "17", "log": "Sysmon", "desc": "Pipe created"},
    {"id": "18", "log": "Sysmon", "desc": "Pipe connected"},
    {"id": "19", "log": "Sysmon", "desc": "WMI event filter"},
    {"id": "20", "log": "Sysmon", "desc": "WMI consumer"},
    {"id": "21", "log": "Sysmon", "desc": "WMI consumer filter binding"},
    {"id": "22", "log": "Sysmon", "desc": "DNS query (high value for C2 detection)"},
    {"id": "23", "log": "Sysmon", "desc": "File delete logged"},
    {"id": "24", "log": "Sysmon", "desc": "Clipboard change"},
]

# ---------------------------------------------------------------------------
# CVE References (curated high-value exploits from toolset notes)
# ---------------------------------------------------------------------------
CVE_LIST: List[Dict[str, str]] = [
    {"id": "CVE-2021-1675", "name": "PrintNightmare", "desc": "RCE in Windows Print Spooler — LPE/RCE via RpcAddPrinterDriver", "category": "exploitation"},
    {"id": "CVE-2021-34527", "name": "PrintNightmare (variant)", "desc": "Print Spooler RCE — patched but still exploitable with Point and Print", "category": "exploitation"},
    {"id": "CVE-2021-42278", "name": "NoPac (sAMAccountName Spoofing)", "desc": "AD privilege escalation by spoofing sAMAccountName to match a DC", "category": "ad"},
    {"id": "CVE-2021-42287", "name": "NoPac (DC spoofing)", "desc": "Pair with CVE-2021-42278 to impersonate DC and request tickets", "category": "ad"},
    {"id": "CVE-2020-1472", "name": "Zerologon", "desc": "Netlogon crypto flaw — DC compromise via empty session", "category": "ad"},
    {"id": "CVE-2019-1040", "name": "Drop the MIC", "desc": "NTLM MIC bypass — relay SMB signing  enforcement", "category": "ad"},
    {"id": "CVE-2019-1388", "name": "UAC Bypass", "desc": "Windows Certificate Dialog UAC bypass via HH.exe", "category": "privilege-escalation"},
    {"id": "CVE-2021-36934", "name": "HiveNightmare", "desc": "Volume Shadow Copy readable SAM/SYSTEM by normal users", "category": "privilege-escalation"},
    {"id": "CVE-2019-1938", "name": "Ghostcat", "desc": "Apache Tomcat AJP file read/RCE on port 8009", "category": "web"},
    {"id": "CVE-2017-5638", "name": "Struts2 RCE", "desc": "Apache Struts2 OGNL injection via Content-Type header", "category": "web"},
    {"id": "CVE-2021-40444", "name": "MSHTML RCE", "desc": "Office RCE via ActiveX control in HTML", "category": "phishing"},
    {"id": "CVE-2021-26855", "name": "ProxyLogon (SSRF)", "desc": "Exchange SSRF leading to auth bypass", "category": "exchange"},
    {"id": "CVE-2021-27065", "name": "ProxyLogon (Write)", "desc": "Exchange arbitrary file write via OABVirtualDirectory", "category": "exchange"},
    {"id": "CVE-2021-34473", "name": "ProxyShell (ACL bypass)", "desc": "Exchange ACL bypass for PowerShell backend", "category": "exchange"},
    {"id": "CVE-2022-22947", "name": "Spring4Shell", "desc": "Spring Cloud Gateway RCE via SpEL injection", "category": "web"},
    {"id": "CVE-2021-44228", "name": "Log4Shell", "desc": "Log4j JNDI injection leading to RCE", "category": "web"},
    {"id": "CVE-2021-45046", "name": "Log4Shell (variant)", "desc": "Log4j mitigation bypass — still exploitable in non-default configs", "category": "web"},
    {"id": "CVE-2022-30190", "name": "Follina", "desc": "MSDT RCE via Word doc calling ms-msdt protocol", "category": "phishing"},
    {"id": "CVE-2022-26923", "name": "AD CS ESC4", "desc": "Certified Pre-Owned — AD CS misconfig allowing privilege escalation", "category": "ad"},
    {"id": "CVE-2022-33679", "name": "AS-REP Roasting (improved)", "desc": "Domain user enumeration via Kerberos AS-REP without pre-auth even if set to required", "category": "ad"},
    {"id": "CVE-2023-23397", "name": "Outlook NTLM leak", "desc": "Microsoft Outlook arbitrary NTLM hash leak via calendar invite", "category": "phishing"},
    {"id": "CVE-2023-28252", "name": "CLFS LPE", "desc": "Windows Common Log File System driver LPE", "category": "privilege-escalation"},
    {"id": "CVE-2024-21413", "name": "MonikerLink", "desc": "Microsoft Outlook link-click NTLM hash leak via file:// link", "category": "phishing"},
]


def search_ldap(keyword: str = "") -> List[Dict]:
    if keyword:
        kw = keyword.lower()
        return [f for f in LDAP_FILTERS if kw in f["name"].lower() or kw in f["desc"].lower()]
    return LDAP_FILTERS


def search_event_ids(keyword: str = "") -> List[Dict]:
    if keyword:
        kw = keyword.lower()
        return [e for e in EVENT_IDS if kw in e["desc"].lower() or kw in e["id"] or kw in e["log"].lower()]
    return EVENT_IDS


def search_cves(keyword: str = "") -> List[Dict]:
    if keyword:
        kw = keyword.lower()
        return [c for c in CVE_LIST if kw in c["id"].lower() or kw in c["name"].lower() or kw in c["desc"].lower() or kw in c["category"]]
    return CVE_LIST
