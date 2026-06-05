import yaml

cards = [
  {
    "question": "Which Windows Event ID logs process creation, and how do you enable command-line logging?",
    "answer": "Event ID 4688 logs process creation; enable command-line logging via GPO or registry key 'ProcessCreationIncludeCmdLine_Enabled' under Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit."
  },
  {
    "question": "What Windows Event ID indicates a successful logon, and what fields should you examine?",
    "answer": "Event ID 4624 indicates a successful logon. Key fields include LogonType (2=interactive, 3=network, 10=remote interactive), TargetUserName, WorkstationName, Source Network Address, and Authentication Package."
  },
  {
    "question": "Which Windows Event ID tracks failed logon attempts, and what is a typical brute-force indicator?",
    "answer": "Event ID 4625 logs failed logon attempts. A large volume of 4625 events from the same source IP with different usernames or multiple LogonType 3 failures indicates a brute-force attack."
  },
  {
    "question": "What Windows Event ID logs new service installation, and why is it critical for persistence detection?",
    "answer": "Event ID 7045 logs new service installation. Attackers often install malicious services for persistence, so any 7045 event from a non-admin installer should be investigated."
  },
  {
    "question": "Which Event ID records the Windows event log being cleared, and what does it suggest?",
    "answer": "Event ID 1102 logs the security event log being cleared. It is a strong indicator of defense evasion \u2014 attackers clear logs to hide their tracks after gaining access."
  },
  {
    "question": "What Sysmon Event ID logs process creation, and how does it differ from Windows 4688?",
    "answer": "Sysmon Event ID 1 logs process creation with richer detail including ProcessID, ParentProcessID, command-line arguments, and hash of the executable (SHA1/SHA256/MD5), unlike basic 4688."
  },
  {
    "question": "Which Sysmon Event ID logs network connections, and what data does it capture?",
    "answer": "Sysmon Event ID 3 logs network connections, capturing source/destination IP, ports, protocol, process GUID, and the process that initiated the connection \u2014 essential for beaconing detection."
  },
  {
    "question": "What Sysmon Event ID detects image loading, and when is it useful?",
    "answer": "Sysmon Event ID 7 logs DLL/image loading. It is useful for detecting DLL injection, sideloading, or when a suspicious DLL is loaded by a known process like notepad.exe or svchost.exe."
  },
  {
    "question": "Which Sysmon Event ID monitors CreateRemoteThread, and what technique does it detect?",
    "answer": "Sysmon Event ID 8 monitors CreateRemoteThread calls, which detects code injection. A known process injecting into lsass.exe or svchost.exe is highly suspicious."
  },
  {
    "question": "What Sysmon Event ID logs file creation, and how does it help detect malware drops?",
    "answer": "Sysmon Event ID 11 logs file creation events. It detects malware dropping executables, scripts, or payloads into suspicious directories like AppData, Temp, or Startup folders."
  },
  {
    "question": "Which Sysmon Event ID logs registry modifications, and what key events should you monitor?",
    "answer": "Sysmon Event ID 13 logs registry value changes. Monitor Run keys (HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run), services, and autoconfiguration settings for persistence."
  },
  {
    "question": "What Sysmon Event ID detects file creation timestamp modification, and what technique does it reveal?",
    "answer": "Sysmon Event ID 15 detects when a file's creation timestamps are modified \u2014 revealing timestamping (timestomping), a defense evasion technique used to hide malware age."
  },
  {
    "question": "Which Sysmon Event ID logs DNS queries, and why is it critical for threat hunting?",
    "answer": "Sysmon Event ID 22 logs DNS queries and responses. It is critical for detecting DNS tunneling, C2 callbacks to known bad domains, and DGAs (domain generation algorithms)."
  },
  {
    "question": "What are the six phases of the NIST 800-61 incident response lifecycle?",
    "answer": "Preparation, Detection & Analysis, Containment Eradication & Recovery, and Post-Incident Activity (Lessons Learned). Some models separate Containment, Eradication, and Recovery as distinct phases."
  },
  {
    "question": "What is the most important step to take before an incident occurs, according to NIST 800-61?",
    "answer": "Preparation \u2014 establishing incident response policies, assembling a CSIRT team, provisioning tools (SIEM, EDR, forensics kits), and conducting tabletop exercises before any incident happens."
  },
  {
    "question": "What is the primary goal of the containment phase in incident response?",
    "answer": "To limit the scope and impact of the incident by preventing further damage \u2014 isolating affected hosts, blocking C2 traffic, disabling compromised accounts, and segmenting network access."
  },
  {
    "question": "What distinguishes eradication from containment in incident response?",
    "answer": "Containment stops the bleeding by isolating systems and blocking malicious activity. Eradication removes the root cause \u2014 deleting malware, revoking certificates, closing backdoors, and removing persistence mechanisms."
  },
  {
    "question": "What is the purpose of the recovery phase after an attack?",
    "answer": "To restore affected systems to normal operations safely \u2014 rebuilding hosts from clean images, restoring data from verified backups, patching vulnerabilities, and monitoring for re-infection."
  },
  {
    "question": "What should a Lessons Learned report after an incident typically include?",
    "answer": "A timeline of events, root cause analysis, what worked and what did not, detection gaps, recommended tooling or process improvements, and a follow-up action plan with ownership."
  },
  {
    "question": "In Splunk SPL, what does the index parameter filter, and how do you search across multiple indexes?",
    "answer": "The index parameter specifies which data source to search. To search multiple, use 'index=*' or 'index=(main OR security OR windows)' \u2014 narrowing early improves performance."
  },
  {
    "question": "Write a Splunk query to find the top 10 source IPs generating the most failed logon events in the last hour.",
    "answer": "'index=windows EventCode=4625 | stats count by src_ip | sort - count | head 10' \u2014 this counts failed logins by source IP and returns the top 10."
  },
  {
    "question": "Write a Splunk query to detect a process launching powershell.exe from an Office application.",
    "answer": "'index=windows EventCode=4688 ParentImage=*\\\\winword.exe OR ParentImage=*\\\\excel.exe Image=*\\\\powershell.exe' \u2014 this catches malicious macros launching PowerShell."
  },
  {
    "question": "How would you use Splunk to find outbound connections to a known malicious IP over the last 24 hours?",
    "answer": "'index=* dest_ip=203.0.113.5 src_ip=10.* | table _time, src_ip, dest_ip, dest_port, process_name' \u2014 search all indexes for traffic to the known-bad IP."
  },
  {
    "question": "What Splunk command calculates the average count of events per minute, and how is it used for baseline detection?",
    "answer": "'timechart' with 'per_second' or 'timechart count | stats avg(count)' \u2014 used to establish normal baselines; deviations beyond 3 standard deviations may indicate an anomaly."
  },
  {
    "question": "What is the Splunk lookup command used for in a SOC context?",
    "answer": "'lookup' enriches events with external data like threat intel feeds, asset inventories, or watchlists \u2014 e.g., 'lookup threat_intel.csv dest_ip OUTPUT malicious' tags matches for triage."
  },
  {
    "question": "How do you detect beaconing in Splunk using network connection logs?",
    "answer": "'index=* EventCode=3 | stats min(_time) as first, max(_time) as last, count by src_ip, dest_ip | eval duration=last-first | eval avg_gap=duration/count | where avg_gap < 300 AND count > 50' \u2014 finds regular connections to the same IP."
  },
  {
    "question": "In the ELK stack, what is a detection rule in Elastic Security?",
    "answer": "A detection rule is a query or machine learning job that triggers alerts when a specific threat pattern is matched. Rules can be query-based, threshold, ML, or event correlation across data sources."
  },
  {
    "question": "How do you create a query-based detection rule in Elastic Security for PowerShell downloading a file?",
    "answer": "Use the rule type 'Query' with 'event.code: 4688 and process.name: powershell.exe and process.command_line: (*DownloadFile* or *Invoke-WebRequest* or *wget*)' on Windows index."
  },
  {
    "question": "What is the difference between Kibana Query Language (KQL) and Lucene syntax in the ELK stack?",
    "answer": "KQL uses field: value without special escaping and does not require wildcards for partial matches. Lucene uses field:value* and supports regex, proximity searches, and more complex Boolean grouping."
  },
  {
    "question": "How would you detect a brute-force attack in QRadar using rules?",
    "answer": "Create a rule that triggers when 'Login Failed' events from the same source IP exceed a threshold (e.g., 10 in 5 minutes) against multiple destination users, then maps the source IP to a offense."
  },
  {
    "question": "What is a QRadar Offense, and how is severity calculated?",
    "answer": "An Offense is a grouping of correlated network and log events that indicate a security incident. Magnitude (0-10) is calculated from severity, credibility, and relevance of the contributing events."
  },
  {
    "question": "How does Azure Sentinel correlate events across multiple data sources differently from on-prem SIEMs?",
    "answer": "Sentinel uses KQL and Analytics Rules to correlate events across Microsoft 365, Azure AD, Windows, and third-party data in a single workspace. Built-in UEBA and fusion ML models surface complex multi-stage attacks."
  },
  {
    "question": "Write a KQL query to list all Azure AD accounts that signed in from an anonymous proxy IP.",
    "answer": "'SigninLogs | where RiskLevelDuringSignIn has_any (\"anonymous\", \"proxy\") | summarize by UserPrincipalName, IPAddress, RiskLevelDuringSignIn' \u2014 detects risky sign-ins via anonymizers."
  },
  {
    "question": "What SIEM correlation technique detects a user logging in from two geographically impossible locations in a short time?",
    "answer": "Velocity/geo-anomaly correlation \u2014 a rule calculates the distance between two login locations and the time delta; if impossible (e.g., NYC to London in 10 minutes), it triggers a possible credential theft alert."
  },
  {
    "question": "What does the MITRE ATT&CK ID T1059.001 refer to, and what is its sub-technique?",
    "answer": "T1059.001 is Command and Scripting Interpreter: PowerShell. It covers adversaries using PowerShell for execution, often to run encoded commands, download payloads, or perform lateral movement."
  },
  {
    "question": "What MITRE technique describes adversaries using rundll32.exe to execute malicious DLLs?",
    "answer": "T1218.011 \u2014 Signed Binary Proxy Execution: Rundll32. Attackers abuse rundll32.exe to load and execute arbitrary DLLs, bypassing application allowlists via a Microsoft-signed binary."
  },
  {
    "question": "What is the difference between a MITRE ATT&CK technique and sub-technique?",
    "answer": "A technique is a broad adversary behavior goal (e.g., T1059 \u2014 Command and Scripting Interpreter). Sub-techniques are specific methods to achieve that goal (e.g., T1059.001 \u2014 PowerShell)."
  },
  {
    "question": "What MITRE tactic corresponds to Credential Access, and name three common techniques within it.",
    "answer": "TA0006 \u2014 Credential Access. Common techniques: T1555 (Credentials from Password Stores), T1003 (OS Credential Dumping), T1056 (Input Capture / keylogging)."
  },
  {
    "question": "How can you use MITRE ATT&CK to map detections and identify coverage gaps?",
    "answer": "Map existing SIEM rules and alerts to MITRE technique IDs. The MITRE ATT&CK Navigator visualizes coverage \u2014 techniques with no detection rules represent gaps that need new analytics."
  },
  {
    "question": "What is T1566.001 \u2014 Spearphishing Attachment, and what are common indicators?",
    "answer": "T1566.001 is a phishing technique where a malicious file is attached to a targeted email. Indicators include suspicious attachments (.docm, .js, .lnk), unusual sender domains, and urgent subject lines."
  },
  {
    "question": "What MITRE technique ID covers Pass-the-Hash, and what sub-technique does it fall under?",
    "answer": "T1550.002 \u2014 Use Alternate Authentication Material: Pass the Hash. Adversaries use harvested NTLM hashes to authenticate as a user without knowing the plaintext password."
  },
  {
    "question": "What is the MITRE ATT&CK tactic for Persistence, and list three common sub-techniques.",
    "answer": "TA0003 \u2014 Persistence. Common sub-techniques: T1547.001 (Registry Run Keys), T1053.005 (Scheduled Task), T1543.003 (Windows Service)."
  },
  {
    "question": "What is T1087.001 and how does it relate to Active Directory reconnaissance?",
    "answer": "T1087.001 \u2014 Account Discovery: Local Account. Adversaries enumerate local user accounts via net user, Get-LocalUser, or wmic useraccount for privilege escalation and lateral movement."
  },
  {
    "question": "Which MITRE technique covers Data Exfiltration Over C2 Channel, and what is its ID?",
    "answer": "T1041 \u2014 Exfiltration Over C2 Channel. Adversaries exfiltrate data through the same command-and-control channel used for communication, often encrypted to blend in with normal traffic."
  },
  {
    "question": "What are the five types of IOCs commonly shared in threat intelligence?",
    "answer": "IP addresses, domain names, file hashes (MD5/SHA1/SHA256), registry keys/paths, and YARA rules. Some sources also include mutex names, SSL/TLS fingerprints, and email addresses."
  },
  {
    "question": "Why is an IP address alone considered a weak IOC compared to a file hash?",
    "answer": "IP addresses are transient \u2014 attackers change IPs frequently, and IPs can be shared by multiple benign services (CDNs, cloud). File hashes are cryptographically unique to a specific malware sample."
  },
  {
    "question": "What is a mutex, and why is it useful as an IOC?",
    "answer": "A mutex (mutual exclusion object) is a synchronization primitive malware creates to prevent multiple instances from running. Known malware strains use predictable mutex names that can be detected by EDR."
  },
  {
    "question": "What is a YARA rule, and what is its typical structure?",
    "answer": "A YARA rule is a pattern-matching tool for identifying malware. Structure: rule name { meta: description strings: condition: } \u2014 it matches on byte sequences, regex, or file metadata."
  },
  {
    "question": "Write a simple YARA rule that detects a specific string in a PE file.",
    "answer": "Rule SuspiciousString { meta: description = \"Detects X\" strings: $s1 = \"malicious\" ascii wide condition: $s1 and pe } \u2014 matches files containing the string and having a PE header."
  },
  {
    "question": "What is the difference between atomic, computed, and behavioral IOCs?",
    "answer": "Atomic IOCs are immutable and cannot be derived (e.g., an IP address). Computed IOCs are derived from data (e.g., file hash). Behavioral IOCs describe patterns of activity (e.g., beaconing every 60s)."
  },
  {
    "question": "What does SPF (Sender Policy Framework) check to prevent email spoofing?",
    "answer": "SPF checks if the sending mail server IP is authorized by the domain owner DNS TXT record. The receiving server queries the sender domain for an SPF record listing approved IPs."
  },
  {
    "question": "How does DKIM verify email authenticity?",
    "answer": "DKIM uses a cryptographic signature in the email header. The sending domain publishes a public key in DNS TXT; the receiver decrypts the signature to verify the email was not tampered with during transit."
  },
  {
    "question": "What does DMARC do, and how does it use SPF and DKIM results?",
    "answer": "DMARC tells receiving servers how to handle emails that fail SPF or DKIM checks (none/quarantine/reject). It also enables reporting so domain owners see unauthorized usage."
  },
  {
    "question": "What email header field contains the actual sender IP, and how do you find it in a phishing investigation?",
    "answer": "The Received: from header chain reveals the true originating IP. Start from the bottommost Received header (closest to the source) and trace upward through each relay hop."
  },
  {
    "question": "What is a common method to detect phishing URLs without clicking them?",
    "answer": "Use URL scanning services or sandboxes (VirusTotal, URLScan.io) to fetch and render the page. Check for typosquatted domains, excessive subdirectories, URL shorteners, and non-standard ports."
  },
  {
    "question": "How would you analyze a suspicious email attachment in a sandbox?",
    "answer": "Submit the attachment to an automated sandbox (AnyRun, Joe Sandbox, Cuckoo). Observe execution behavior \u2014 process creation, registry changes, network connections, and any dropped files."
  },
  {
    "question": "What are common red flags in an email header for a phishing email?",
    "answer": "Mismatch between the From domain and Reply-To domain, failure of SPF/DKIM/DMARC, unusual Message-ID format, forged Received headers, and an envelope sender different from the header From."
  },
  {
    "question": "What is the difference between URLScan.io and VirusTotal for phishing URL analysis?",
    "answer": "URLScan.io captures a screenshot and DOM of the rendered page, showing redirect chains and resources loaded. VirusTotal checks the URL against multiple threat intel feeds and antivirus engines."
  },
  {
    "question": "What information can you extract from a PCAP file to identify malicious traffic?",
    "answer": "Extract source/destination IPs, ports, protocols, DNS queries, HTTP requests/User-Agent strings, TLS certificate details, payload content, and timing patterns for beaconing analysis."
  },
  {
    "question": "How do you detect DNS tunneling in network traffic?",
    "answer": "Look for DNS queries with unusually long subdomains (e.g., base64-encoded), high query volumes to a single domain, TXT record queries of abnormal size, or queries to domains with no MX records."
  },
  {
    "question": "What is a NetFlow record, and how does it differ from full packet capture?",
    "answer": "NetFlow is metadata about network flows \u2014 source/dest IP, ports, protocol, packet/byte counts. It is lightweight but lacks payload content. Full PCAP captures everything including application data."
  },
  {
    "question": "How would you identify beaconing in NetFlow data?",
    "answer": "Beaconing shows periodic, consistent connections at regular intervals. Analyze flow timing \u2014 look for connections to the same dest IP every X seconds with similar packet sizes, especially outside business hours."
  },
  {
    "question": "What are common DNS anomalies that indicate compromise?",
    "answer": "NXDOMAIN floods (DGA probing), responses from known malicious domains, excessive TXT record queries, DNS queries to unregistered TLDs, and encoded data in subdomains (DNS tunneling)."
  },
  {
    "question": "What is static malware analysis, and what tools are commonly used?",
    "answer": "Static analysis examines the file without executing it \u2014 inspecting strings, imports, exports, PE headers, and entropy. Tools: pestudio, Detect It Easy, BinText, HxD, and FLOSS for obfuscated strings."
  },
  {
    "question": "What is dynamic malware analysis, and what is its main advantage over static?",
    "answer": "Dynamic analysis executes the malware in a controlled sandbox to observe behavior in real time \u2014 process creation, network connections, file system changes. It captures actions static analysis cannot see."
  },
  {
    "question": "How does VirusTotal aggregate malware scan results?",
    "answer": "VirusTotal submits files to 70+ antivirus engines and sandboxes. Results show detection ratios, behavior reports, community comments, and related samples. A file detected by less than 5 engines may be a false positive."
  },
  {
    "question": "What is AnyRun used for in malware analysis?",
    "answer": "AnyRun is an interactive online sandbox that lets analysts execute malware and see a live stream of screen captures, process trees, network requests, and file operations in real time."
  },
  {
    "question": "What is OSINT in the context of threat intelligence?",
    "answer": "OSINT (Open Source Intelligence) is threat data collected from publicly available sources \u2014 blogs, social media, paste sites, public threat feeds, security reports, Shodan, and VirusTotal."
  },
  {
    "question": "What is TAXII and STIX, and how do they relate?",
    "answer": "STIX (Structured Threat Information Expression) is a standardized language for describing threat data. TAXII (Trusted Automated Exchange of Intelligence) is the protocol for transporting STIX data between systems."
  },
  {
    "question": "What is the difference between strategic, operational, and tactical threat intelligence?",
    "answer": "Strategic (high-level trends for executives), operational (details of specific campaigns and TTPs for defenders), tactical (IOCs \u2014 hashes, IPs, domains \u2014 for automated detection systems)."
  },
  {
    "question": "Name three closed-source threat intelligence feeds commonly used in SOCs.",
    "answer": "VirusTotal Premium, Recorded Future, Mandiant Advantage (formerly FireEye iSIGHT). Others include CrowdStrike Falcon Intel and Anomali ThreatStream."
  },
  {
    "question": "What is a TTP in threat intelligence, and why is it more valuable than an IOC?",
    "answer": "TTP (Tactics, Techniques, Procedures) describes how an adversary operates. TTPs are more durable than IOCs because attackers change infrastructure but change their methods less frequently."
  },
  {
    "question": "How would you implement an ACL to block C2 traffic at the network perimeter?",
    "answer": "Create an ACL on the firewall or router denying outbound traffic from internal hosts to known C2 IPs and domains. Apply it to the egress interface with a deny-all rule for those destinations."
  },
  {
    "question": "What is sinkholing in incident response?",
    "answer": "Sinkholing redirects malicious traffic (e.g., malware C2 callbacks) to a server under analyst control, allowing the SOC to enumerate compromised hosts without the attacker receiving data."
  },
  {
    "question": "When should you isolate a host versus block it at the network level?",
    "answer": "Isolate the host (disable NIC, pull cable) when rapid spread is suspected (ransomware). Block at the network level (ACL) when you want to preserve connectivity for forensics while stopping C2."
  },
  {
    "question": "How do you disable a compromised Active Directory account without deleting it?",
    "answer": "Disable the account in ADUC or via PowerShell: 'Disable-ADAccount -Identity \"username\"'. This prevents authentication while preserving the object for investigation."
  },
  {
    "question": "What is the difference between host isolation and network segmentation during containment?",
    "answer": "Host isolation removes a single machine from all network access (disconnect cable). Network segmentation uses VLANs or firewall rules to restrict traffic between zones while allowing monitored access."
  },
  {
    "question": "When eradicating malware from a compromised endpoint, why is reimaging preferred over cleaning?",
    "answer": "Reimaging (format and reinstall OS) is trusted because you cannot guarantee all malware artifacts \u2014 rootkits, registry modifications, persistence hooks \u2014 are fully removed by cleaning tools."
  },
  {
    "question": "What is the purpose of credential rotation during the eradication phase?",
    "answer": "Attackers often capture plaintext passwords, hashes, or Kerberos tickets. Rotating all credentials ensures stolen authentication material is invalidated, preventing re-entry through stolen creds."
  },
  {
    "question": "What does patch deployment during recovery aim to achieve?",
    "answer": "Patch deployment closes the vulnerabilities that were exploited to gain initial access. Without patching, the same attack vector remains open and the system can be recompromised."
  },
  {
    "question": "How do you verify system integrity after restoring from backups during recovery?",
    "answer": "Scan the restored system with EDR and antivirus, verify security patches are current, check for anomalous processes and registry entries, and monitor logs for 48-72 hours before returning to production."
  },
  {
    "question": "What criteria determine whether an alert is a true positive versus a false positive?",
    "answer": "True positive: confirmed malicious activity matching known TTPs. False positive: benign activity that triggered the rule (e.g., admin running a tool that looks like malware). Investigate context and whitelist if verified benign."
  },
  {
    "question": "What is a severity scoring system, and name a common framework used in SOCs?",
    "answer": "Severity scoring assigns a numeric value (0-10) to alerts based on asset criticality, exploitability, and impact. The Common Vulnerability Scoring System (CVSS) is widely used for vulnerability prioritization."
  },
  {
    "question": "What is a false negative in SOC alerting, and why is it dangerous?",
    "answer": "A false negative occurs when malicious activity happens but no alert fires. It is dangerous because the attack goes undetected, potentially causing significant damage without the SOC's knowledge."
  },
  {
    "question": "How do you handle a high-frequency alert that is a known false positive?",
    "answer": "Document the root cause, adjust the detection rule to exclude the benign pattern (add filter), or create a suppression rule. Ensure the justification is peer-reviewed before tuning."
  },
  {
    "question": "What is the typical triage order for alerts in a SOC?",
    "answer": "Triage by severity and impact: critical alerts (ransomware, lateral movement) first, then high (malware, credential access), medium (reconnaissance), low (policy violations). Re-triage as context emerges."
  },
  {
    "question": "What is a SOAR platform and how does it improve SOC efficiency?",
    "answer": "SOAR (Security Orchestration, Automation, and Response) automates repetitive tasks \u2014 enrichment, alert triage, containment. It integrates SIEM, EDR, email, and ticketing into playbook-driven workflows."
  },
  {
    "question": "What is an automation playbook in a SOAR context?",
    "answer": "A playbook is a documented workflow of automated actions triggered by an alert \u2014 e.g., enrich IP via VirusTotal, block on firewall, create ticket, notify analyst \u2014 often built in drag-and-drop interfaces."
  },
  {
    "question": "Name three SOAR platforms commonly used in enterprise SOCs.",
    "answer": "Palo Alto Cortex XSOAR (formerly Demisto), Splunk Phantom, and Shuffle (open-source). Others include ServiceNow Security Operations and IBM Resilient."
  },
  {
    "question": "What is a playbook trigger in XSOAR (Demisto) and give an example?",
    "answer": "A trigger defines when a playbook runs \u2014 based on incident type, severity, or specific field value. Example: trigger a phishing playbook when an incident of type 'Phishing' with severity 'High' is created."
  },
  {
    "question": "In Splunk Phantom, what is an action and how is it used in automation?",
    "answer": "An action is a single automated task (e.g., 'Get reputation of IP from VirusTotal'). Actions are chained in a playbook with conditional logic to automate multi-step response workflows."
  },
  {
    "question": "What is the escalation procedure when a SOC analyst confirms a critical incident?",
    "answer": "The analyst notifies the SOC lead or incident commander, opens a bridge call, documents initial findings in the case management system, and follows the organization's critical incident response plan."
  },
  {
    "question": "What information should be communicated in an initial incident notification to management?",
    "answer": "Brief description of the incident, current scope/impact, actions taken so far, confidence level, criticality assessment, and whether external stakeholders or law enforcement need involvement."
  },
  {
    "question": "What is the purpose of a war room during a major security incident?",
    "answer": "A war room is a dedicated virtual or physical meeting space where incident responders, IT, legal, and management collaborate in real time to coordinate response decisions."
  },
  {
    "question": "What is the recommended communication channel during an active incident and why?",
    "answer": "Out-of-band communication (e.g., Microsoft Teams/Slack dedicated channel, phone bridge) \u2014 not email, as attackers may have compromised email accounts and can monitor response communications."
  },
  {
    "question": "When would a SOC analyst escalate an incident to law enforcement?",
    "answer": "When the incident involves criminal activity (ransomware payment demands, PII theft, financial fraud), has legal reporting requirements (GDPR, HIPAA breach notification), or targets critical infrastructure."
  },
  {
    "question": "What is kernel memory dump analysis, and how does Volatility help?",
    "answer": "Kernel memory dump analysis examines the contents of RAM (physical memory) to find running processes, loaded drivers, open network connections, and injected code."
  },
  {
    "question": "Name three Volatility plugins commonly used in incident response.",
    "answer": "pslist/psscan (list processes), netscan (network connections in Windows 7+), hivelist (list registry hives). Others: malfind (detect injected code), cmdline (process command lines)."
  },
  {
    "question": "What does Volatility malfind plugin detect?",
    "answer": "malfind identifies processes with suspicious memory protections (PAGE_EXECUTE_READWRITE) \u2014 often indicating code injection or shellcode. It dumps the injected memory region for further analysis."
  },
  {
    "question": "How can you find hidden processes using Volatility?",
    "answer": "Compare pslist (uses the process list) with psscan (scans memory pool tags). Hidden rootkit processes appear in psscan but not in pslist because they are unlinked from the active list."
  },
  {
    "question": "What Volatility command lists all active network connections from a memory dump?",
    "answer": "'volatility -f mem.dump netscan' \u2014 lists TCP and UDP endpoints with process PID, local/remote IPs, and port numbers. Equivalent to 'netstat -ano' but from memory."
  },
  {
    "question": "What is the first step in responding to a ransomware incident?",
    "answer": "Immediately isolate affected systems from the network to prevent lateral encryption. Disconnect network cables, disable Wi-Fi, and quarantine the host. Do not power off \u2014 preserve memory for forensics."
  },
  {
    "question": "How do you identify the ransomware strain during an incident?",
    "answer": "Check the ransom note filename and content, file extension appended to encrypted files, the ransom email/URL, or submit a sample to ID Ransomware or NoMoreRansom. Each strain has unique artifacts."
  },
  {
    "question": "What is the difference between disk-level and file-level encryption in a ransomware attack?",
    "answer": "Disk-level ransomware encrypts the entire disk or partition (e.g., Petya/NotPetya modifies the MBR). File-level encrypts individual files (e.g., Ryuk, Sodinokibi) leaving the OS functional."
  },
  {
    "question": "How do you assess the scope of encryption in a ransomware incident?",
    "answer": "Map network shares and determine which file servers, databases, and endpoints are affected. Check event logs for the ransomware execution time and track lateral movement using EDR telemetry."
  },
  {
    "question": "What recovery options exist for ransomware when backups are available?",
    "answer": "Wipe and reimage affected systems, restore data from offline/immutable backups, rotate all credentials, patch the initial access vector, and verify restoration integrity before returning to production."
  },
  {
    "question": "What indicators suggest data exfiltration is occurring on a network?",
    "answer": "Large outbound data transfers to external IPs (especially during off-hours), spikes in DNS TXT query sizes (DNS tunneling), unusual SMB traffic to cloud storage, and data compression activity on file servers."
  },
  {
    "question": "How do you detect DNS tunneling for data exfiltration?",
    "answer": "Monitor DNS query length \u2014 queries longer than 52 characters are suspicious. Look for high query volume to a single domain, excessive NXDOMAIN responses, or base64-encoded subdomain patterns."
  },
  {
    "question": "What is a common signature of a data exfiltration attempt using HTTP POST?",
    "answer": "Large post bodies to a single external domain, abnormal Content-Type headers, unusual User-Agent strings, and requests sent outside business hours with consistent timing."
  },
  {
    "question": "How does detecting unusual outbound SMB traffic help identify data theft?",
    "answer": "SMB traffic to the internet is abnormal since SMB/CIFS is designed for local networks. Outbound SMB to external IPs (port 445) often indicates data exfiltration or malware propagation."
  },
  {
    "question": "What is the significance of a sudden increase in RDP outbound connections from a single host?",
    "answer": "It may indicate an attacker using RDP for lateral movement or data exfiltration. Each unique destination suggests the compromised host is being used to pivot to other internal systems."
  },
  {
    "question": "How does pass-the-hash (PtH) work, and how do you detect it?",
    "answer": "PtH uses NTLM password hashes extracted from lsass.exe to authenticate without the plaintext password. Detect via Event ID 4624 with LogonType 3 or 9 where the authentication package is NTLM and the source is a known admin workstation."
  },
  {
    "question": "What Event ID logs incoming RDP connections, and what fields indicate lateral movement?",
    "answer": "Event ID 4624 with LogonType 10 (RemoteInteractive) logs RDP logins. Lateral movement indicators include a non-admin user connecting to multiple servers in rapid succession."
  },
  {
    "question": "How do you detect lateral movement via SMB/WMI using Windows event logs?",
    "answer": "Event ID 4688 for wmic.exe or powershell.exe with target host references. Sysmon Event ID 3 with destination port 445 (SMB) or 135 (WMI) from administrative workstations to multiple servers."
  },
  {
    "question": "What is PSExec, and why is it commonly abused for lateral movement?",
    "answer": "PSExec is a Sysinternals tool that executes processes remotely via SMB. Attackers abuse it because it is signed by Microsoft and often whitelisted \u2014 it creates a service on the remote host (Event ID 7045)."
  },
  {
    "question": "How does WMI differ from PSExec for lateral movement, and how are both detected?",
    "answer": "WMI uses DCOM (port 135) and WinRM (5985/5986) without writing files to disk. Both trigger Event ID 4688 with wmic.exe, winrm.cmd, or powershell.exe with -EncodedCommand and remote host references."
  },
  {
    "question": "What Windows Event IDs indicate UAC bypass attempts?",
    "answer": "Event ID 4688 with parent process consent.exe (standard UAC prompt bypass). Sysmon Event ID 1 showing an auto-elevating executable (trusted installer) launched from a non-standard location."
  },
  {
    "question": "What is token manipulation, and how is it used for privilege escalation?",
    "answer": "Token manipulation duplicates or impersonates access tokens of higher-privileged processes. Detect via Event ID 4688 and abnormal parent-child relationships \u2014 e.g., cmd.exe spawning as child of winlogon.exe."
  },
  {
    "question": "How do attackers perform service exploitation for privilege escalation?",
    "answer": "Abuse misconfigured services running as SYSTEM where low-privileged users can modify the service binary path or restart it. Detect via Event ID 4697 (service install) or registry changes to service keys (Event ID 13)."
  },
  {
    "question": "What common kernel vulnerabilities are exploited for privilege escalation on Windows?",
    "answer": "CVE-2021-1732 (Win32k), CVE-2022-21882 (Win32k), and CVE-2023-21768 (AFD.sys). Exploitation creates processes with SYSTEM integrity \u2014 visible in processes running as SYSTEM with unusual parent chains."
  },
  {
    "question": "How do you detect LSASS dumping using Windows event logs?",
    "answer": "Event ID 4688 with process lsass.exe being accessed by an unusual process (e.g., procdump.exe, comsvcs.dll via rundll32). Sysmon Event ID 10 (ProcessAccess) with lsass.exe as TargetImage and suspicious SourceImage."
  },
  {
    "question": "What is Mimikatz, and what does it extract from lsass.exe?",
    "answer": "Mimikatz extracts plaintext passwords, NTLM hashes, Kerberos tickets, and PINs from LSASS process memory. It uses techniques like sekurlsa::logonpasswords to dump credentials in cleartext."
  },
  {
    "question": "What Sysmon Event ID detects credential dumping via LSASS process access?",
    "answer": "Sysmon Event ID 10 (Process Access) when TargetImage is lsass.exe and CallTrace includes suspicious modules. GrantAccess calls with PROCESS_VM_READ from non-standard tools."
  },
  {
    "question": "What Event ID logs keylogger installation, and where do keyloggers typically persist?",
    "answer": "Keyloggers are often installed as hooks \u2014 Event ID 8 (CreateRemoteThread) injecting into winlogon.exe or explorer.exe. They persist via registry Run keys (Event ID 13), services, or AppInit_DLLs."
  },
  {
    "question": "What process should you investigate if you see svchost.exe making unusual outbound connections?",
    "answer": "Investigate immediately \u2014 svchost.exe should not make direct outbound connections except for Windows Update and a few specific services. Check the -k parameter to identify the service group and compare with baselines."
  },
  {
    "question": "What Event ID tracks scheduled task creation, and what is a common persistence abuse?",
    "answer": "Event ID 4698 logs scheduled task creation. Attackers create tasks to run malicious binaries at logon or at specific intervals. Detection: look for tasks created by non-admin users or with suspicious trigger times."
  },
  {
    "question": "How are registry Run keys used for persistence, and what Sysmon Event ID detects changes?",
    "answer": "Run keys under HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run let programs start at every boot. Sysmon Event ID 13 detects registry value modification \u2014 monitor for new entries pointing to Temp, AppData, or non-standard paths."
  },
  {
    "question": "What is process hollowing, and how is it detected?",
    "answer": "Process hollowing replaces the memory of a legitimate process (e.g., svchost.exe, explorer.exe) with malicious code. Detection: Sysmon Event ID 8 showing CreateRemoteThread, or Event ID 1 showing a legitimate binary starting from a suspicious path."
  },
  {
    "question": "How does DLL injection work, and what Sysmon Event IDs can detect it?",
    "answer": "DLL injection writes a malicious DLL path into a target process and forces it to load via CreateRemoteThread or SetWindowsHookEx. Detect via Sysmon Event ID 7 (Image Loaded) \u2014 a known process loading an unsigned DLL from a user-writable path."
  },
  {
    "question": "What is masquerading, and how do you detect it with Sysmon?",
    "answer": "Masquerading names malware as a legitimate file (e.g., svchost.exe in AppData). Detect via Sysmon Event ID 1: a process named svchost.exe running from a non-system32 directory has a different OriginalFilename."
  },
  {
    "question": "What is obfuscation, and how does it evade signature-based detection?",
    "answer": "Obfuscation transforms code (e.g., base64 encoding, XOR, compression) to hide its true intent. Signatures fail because the byte pattern changes, but behavioral detection catches the decoded execution."
  },
  {
    "question": "How do you detect net user /domain and net group /domain enumeration commands?",
    "answer": "Monitor Event ID 4688 for net.exe or net1.exe with command-line arguments containing user /domain, group /domain, localgroup, or accounts. Multiple queries in sequence suggests Active Directory reconnaissance."
  },
  {
    "question": "What is BloodHound, and what does it do in an Active Directory attack?",
    "answer": "BloodHound is an AD enumeration tool that maps relationships between users, groups, computers, and permissions. Attackers use it to find privilege escalation paths \u2014 e.g., user can admin a server that has a session with a domain admin."
  },
  {
    "question": "How do you detect BloodHound (Sharphound) execution on an endpoint?",
    "answer": "Detection: Event ID 4688 with common Sharphound arguments (--CollectionMethod, -c, All), high-volume LDAP queries from a single host (Event ID 5156)."
  },
  {
    "question": "What is ad-hoc AD exploration, and what commands should you monitor?",
    "answer": "Ad-hoc exploration uses built-in Windows commands: net group Domain Admins /domain, net user /domain, dsquery * -filter, nltest /domain_trusts. Multiple distinct queries in minutes indicate reconnaissance."
  },
  {
    "question": "What Event IDs track LDAP queries for AD reconnaissance?",
    "answer": "Event ID 4662 (Operation on an AD object) and 5156 (WFP connection) to the DC on port 389. High query rates from a single non-DC host indicate enumeration."
  },
  {
    "question": "What is beaconing behavior in C2 traffic?",
    "answer": "Beaconing is regular, periodic communication between compromised host and C2 server. Characteristics: connections at fixed intervals (every 30/60/300s), similar packet sizes, predictable jitter, and during off-hours."
  },
  {
    "question": "How do you detect C2 traffic using HTTPS (encrypted) when you cannot inspect payload?",
    "answer": "Analyze metadata \u2014 TLS handshake parameters (JA3/S certificates), beacon timing patterns, destination IP reputation, and domain age. JA3 fingerprinting identifies malicious TLS clients even with valid certificates."
  },
  {
    "question": "What is domain fronting, and how does it evade detection?",
    "answer": "Domain fronting uses a legitimate CDN (CloudFront, Akamai) as a proxy. The TLS SNI field shows the CDN domain (allowed), while the HTTP Host header points to the C2 server \u2014 the firewall sees only the CDN domain."
  },
  {
    "question": "How does DNS over HTTPS (DoH) affect C2 detection?",
    "answer": "DoH encrypts DNS queries within HTTPS traffic, hiding DNS tunneling or malicious domain lookups from traditional DNS monitoring. SOCs must inspect HTTPS metadata or use TLS inspection to detect DoH-based C2."
  },
  {
    "question": "What is a C2 redirector, and how does it complicate IP-based blocking?",
    "answer": "A redirector is a relay server (often a rented VPS or compromised site) between the beacon and the actual C2. Blocking the redirector IP is temporary \u2014 attackers rotate them frequently, making IP-based blocklists ineffective."
  },
  {
    "question": "What indicators suggest a web shell has been uploaded to a web server?",
    "answer": "Unusually named files in web-accessible directories, anomalous HTTP requests to those files, spike in POST requests, and process execution via w3wp.exe or httpd.exe spawning cmd.exe or powershell.exe."
  },
  {
    "question": "How do you detect web shell activity in IIS web server logs?",
    "answer": "Look for HTTP POST requests to .aspx or .ashx files in upload directories, suspicious URL parameters (cmd, exec, command), User-Agent strings like Java or empty UA, and requests from non-standard source IPs."
  },
  {
    "question": "What Event ID captures process creation by IIS worker process (w3wp.exe), and why is it important?",
    "answer": "Event ID 4688 with ParentImage containing w3wp.exe is critical. w3wp.exe should never spawn cmd.exe, powershell.exe, or reg.exe \u2014 any such event strongly indicates web shell or code execution."
  },
  {
    "question": "What is a common web shell detection method using file integrity monitoring?",
    "answer": "Monitor the web directory for new or modified files with extensions .aspx, .ashx, .php, .jsp. Use Sysmon Event ID 11 (FileCreate) or a FIM tool to alert on any file creation in wwwroot or equivalent directories."
  },
  {
    "question": "What is the difference between a one-liner web shell and a full-featured web shell?",
    "answer": "A one-liner web shell (e.g., <?php system($_GET[cmd]);?>) executes a single command via URL parameter. Full-featured webshells (e.g., China Chopper, WSO, b374k) provide file browser, database access, and privilege escalation."
  },
  {
    "question": "What are the first three questions a SOC analyst should ask when investigating an alert?",
    "answer": "Is it a true or false positive? What is the scope \u2014 how many hosts/users are affected? What is the impact \u2014 data loss, credential compromise, ransomware, or recon?"
  },
  {
    "question": "How do you differentiate between a compromised account and a misconfigured service account?",
    "answer": "Compromised accounts show anomalous geolocation, off-hours activity, multiple failed logons before success, and unusual lateral movement. Service accounts follow predictable patterns from known source IPs."
  },
  {
    "question": "What is a diamond model in intrusion analysis?",
    "answer": "The diamond model maps four elements: Adversary, Capability, Infrastructure, and Victim. It helps SOC analysts understand the attack relationship \u2014 who attacked, with what tool, from where, and who was targeted."
  },
  {
    "question": "What is the Pyramid of Pain, and how does it relate to IOCs?",
    "answer": "The Pyramid of Pain (by David Bianco) ranks IOCs by difficulty for attackers to change: hash (easiest), IP, domain, network artifacts, tools, TTPs (hardest). Focus detection on TTPs to maximize attacker cost."
  },
  {
    "question": "What are the stages of the Cyber Kill Chain framework?",
    "answer": "Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command & Control, Actions on Objectives. Developed by Lockheed Martin to describe stages of a cyber intrusion."
  },
  {
    "question": "How do you prioritize patching vulnerabilities based on threat intelligence?",
    "answer": "Use CVSS score combined with active exploit data: prioritize CVSS 9-10 + known exploited in the wild + internet-facing assets. CISA's Known Exploited Vulnerabilities (KEV) catalog is a primary source."
  },
  {
    "question": "What is the difference between IOC and IOA (Indicator of Attack)?",
    "answer": "IOC is a forensic artifact left behind (hash, IP, registry key) \u2014 evidence of a past compromise. IOA focuses on real-time behavior and intent \u2014 what the attacker is trying to do, detected during the attack."
  },
  {
    "question": "What is a false positive avalanche, and how do you handle it?",
    "answer": "A false positive avalanche is a massive surge of alerts from a single misconfigured rule, often triggered by a routine change or scan. Investigate the rule, suppress with targeted exclusion, and re-enable when resolved."
  },
  {
    "question": "What information should be included in a SOC shift handoff report?",
    "answer": "Active incidents with status, escalated cases, new alerts that require follow-up, scheduled maintenance impacting detection, intelligence briefs, and any degraded tooling or data source issues."
  },
  {
    "question": "How do you detect the use of living-off-the-land binaries (LOLBins)?",
    "answer": "Monitor for normal Windows binaries used in abnormal ways \u2014 certutil.exe downloading files, mshta.exe executing scripts, regsvr32.exe running remote code, bitsadmin.exe transferring data. Baseline normal usage first."
  },
  {
    "question": "What is the significance of an encoded PowerShell command from the command line?",
    "answer": "PowerShell -EncodedCommand with base64 strings is heavily used by attackers to obfuscate code. Decode the base64 in the command line to reveal the actual script \u2014 often contains download cradles and payload execution."
  },
  {
    "question": "How do you detect suspicious child processes of Microsoft Office applications?",
    "answer": "Monitor Event ID 4688 where the parent is winword.exe, excel.exe, pptview.exe, or outlook.exe, and the child is cmd.exe, powershell.exe, wscript.exe, or mshta.exe \u2014 typical of macro-driven malware."
  },
  {
    "question": "What is the purpose of a canary token or honey token in detection?",
    "answer": "Canary tokens are fake credentials, files, or database records placed to alert when accessed. Any access is unauthorized \u2014 they detect data exfiltration, credential theft, or insider threats."
  },
  {
    "question": "How do you validate a suspicious file hash against multiple threat intelligence sources?",
    "answer": "Submit the hash to VirusTotal, AlienVault OTX, and AbuseIPDB. Check for any positive detections, community comments, related samples, and the first-seen date to assess how recent and prevalent the threat is."
  },
  {
    "question": "What is a pre-authentication brute force detection, and how do you tune it to reduce false positives?",
    "answer": "Pre-auth brute force triggers when Event ID 4625 (failed logon) occurs from a single IP across multiple users. Tune by excluding known admin scanning tools, VPN health checks, and setting a threshold."
  },
  {
    "question": "How do you detect scheduled task creation for persistence using Sysmon?",
    "answer": "Sysmon Event ID 1 with Image = schtasks.exe and command-line containing /create, /sc, /tn, /tr. Persistence tasks often run at user logon or system startup."
  },
  {
    "question": "What is a common technique to detect mimikatz via Windows event logs?",
    "answer": "Event ID 4688 with a process accessing lsass.exe (procdump.exe, comsvcs.dll). Also Event ID 4656 (handle to object requested) for lsass.exe from a non-standard process. Sysmon Event ID 10 is more reliable."
  },
  {
    "question": "How do you detect LSASS dumping via comsvcs.dll and rundll32.exe?",
    "answer": "Event ID 4688 with ParentImage = rundll32.exe and command line containing comsvcs.dll,MiniDump or #24 \u2014 the MiniDump export. The dump file is written to C:\\Windows\\Temp."
  },
  {
    "question": "What is the MITRE ATT&CK technique for service stop (used to disable AV or EDR)?",
    "answer": "T1562.001 \u2014 Impair Defenses: Disable or Modify Tools. Adversaries stop security services via net stop, sc stop, or Set-Service. Detect via Event ID 4688 with net stop or service control manager events."
  },
  {
    "question": "What is the difference between a Sigma rule and a YARA rule?",
    "answer": "Sigma is a generic signature format for log events \u2014 translates to SIEM queries (Splunk, KQL, QRadar). YARA is a pattern-matching format for files \u2014 used to identify malware binaries by byte sequences or strings."
  },
  {
    "question": "How do you detect the use of a remote access tool (RAT) on a network?",
    "answer": "RATs show persistent outbound connections over common ports (443, 80, 8080), beaconing patterns, unusual process names, and DNS queries to dynamic DNS or newly registered domains."
  },
  {
    "question": "How do you detect certificate services abuse for privilege escalation?",
    "answer": "Monitor Event ID 4886 (Certificate Services request) and 4887 (Certificate Services approval). ESC1/ESC2/ESC3 attacks modify certificate templates or issue certificates for authentication."
  },
  {
    "question": "How do you detect Log4Shell (CVE-2021-44228) exploitation attempts?",
    "answer": "Monitor for ${jndi:ldap://} or ${jndi:rmi://} patterns in HTTP headers (User-Agent, X-Forwarded-For), URL parameters, or POST bodies. WAF logs and application logs are primary detection sources."
  },
  {
    "question": "What is the MITRE ATT&CK technique for Remote System Discovery?",
    "answer": "T1018 \u2014 Remote System Discovery. Adversaries probe network segments using ping, net view, nltest /dclist, arp -a, or LDAP queries to find other hosts for lateral movement."
  },
  {
    "question": "What is the difference between Kerberoasting and AS-REP roasting?",
    "answer": "Kerberoasting targets service accounts requesting TGS tickets (any authenticated user). AS-REP roasting targets accounts without Kerberos pre-authentication by requesting AS-REP responses."
  },
  {
    "question": "How do you detect DCSync attacks?",
    "answer": "Event ID 4662 for replica-related GUIDs, or Event ID 5136 from a non-DC host. Also monitor Event ID 4624 with LogonType 9 (logon for replication)."
  },
  {
    "question": "What is the MITRE ATT&CK technique for DLL Side-Loading?",
    "answer": "T1574.002 \u2014 Hijack Execution Flow: DLL Side-Loading. Adversaries place a malicious DLL in the search order of a legitimate application so it loads the attacker's DLL instead."
  },
  {
    "question": "What is a common detection for Regsvr32.exe executing remote code?",
    "answer": "Monitor Event ID 4688 where Image = regsvr32.exe and command line contains -s and a URL. This is a Squiblydoo technique (T1218.010)."
  },
  {
    "question": "What is the MITRE ATT&CK technique for Ingress Tool Transfer?",
    "answer": "T1105 \u2014 Ingress Tool Transfer. Adversaries transfer tools to the compromised environment using protocols like SMB, HTTP, FTP, or file-sharing services."
  },
  {
    "question": "How do you detect an adversary using netsh to create a port forward?",
    "answer": "Event ID 4688 with netsh.exe and command line containing 'interface portproxy add v4tov4' or 'firewall add allowedprogram'. Indicates tunnelling activity."
  },
  {
    "question": "How do you detect a process running from a Temp directory with a random name?",
    "answer": "Sysmon Event ID 1 with Image path containing \\Temp\\, \\AppData\\Local\\Temp\\, or \\Users\\*\\AppData\\Roaming\\ and a random 8-character executable name."
  },
  {
    "question": "What is the MITRE ATT&CK technique for Group Policy Modification?",
    "answer": "T1484.001 \u2014 Domain Policy Modification: Group Policy Modification. Adversaries modify GPOs to deploy malware, add local admin accounts, disable security controls, or push scheduled tasks across the domain."
  },
  {
    "question": "How do you detect anomalous service creation on a domain controller?",
    "answer": "Event ID 7045 for new services on a DC is highly suspicious. DCs should rarely have new services installed outside of authorized changes."
  },
  {
    "question": "What is PowerShell downgrade attack, and how do you detect it?",
    "answer": "PowerShell downgrade uses -Version 2 to execute without Enhanced Logging or constrained language mode. Detect via Event ID 4688 with -Version 2 in the command line."
  },
  {
    "question": "What is WMI persistence, and what should you monitor?",
    "answer": "WMI persistence uses __EventFilter and CommandLineEventConsumer to run commands on triggers. Detect via Sysmon Event ID 11 for mofcomp.exe or Event ID 5861 for WMI consumer changes."
  },
  {
    "question": "What is a common evasion technique against AMSI?",
    "answer": "AMSI patching \u2014 attackers modify AMSI.dll in memory to always return AMSI_RESULT_CLEAN. Detection: Sysmon Event ID 12 for AMSI provider key changes or Event ID 10 for AMSI.dll access."
  },
  {
    "question": "How do you detect suspicious use of BITSAdmin?",
    "answer": "Monitor bitsadmin.exe command lines containing /transfer, /addfile, /setnotifycmdline. BITSAdmin is a LOLBin for file download."
  },
  {
    "question": "How do you detect DLL side-loading using Sysmon?",
    "answer": "Sysmon Event ID 7 (Image Loaded) \u2014 look for a legitimate process loading an unsigned DLL from a user-writable path like AppData or Temp."
  },
  {
    "question": "What is a golden ticket attack?",
    "answer": "A golden ticket forges a Kerberos TGT using the KRBTGT account hash, granting domain admin access. Detection: anomalous TGT durations or forged PAC validation failures."
  },
  {
    "question": "What is the MITRE ATT&CK technique for Kerberoasting?",
    "answer": "T1558.003 \u2014 Steal or Forge Kerberos Tickets: Kerberoasting. Attackers request TGS tickets for service accounts and crack them offline."
  },
  {
    "question": "What is the MITRE ATT&CK technique for DCSync?",
    "answer": "T1003.006 \u2014 OS Credential Dumping: DCSync. Adversaries use Mimikatz lsadump::dcsync to impersonate a DC and replicate AD credentials."
  },
  {
    "question": "How do you detect account takeover through impossible travel?",
    "answer": "Correlate Event ID 4624 with geographic data. Same user logging in from distant locations within impossible travel time indicates credential theft."
  },
  {
    "question": "What is the MITRE ATT&CK technique for Forced Authentication (NTLM relay)?",
    "answer": "T1187 \u2014 Forced Authentication. Adversaries force authentication via SMB trap or lnk file, capture the NTLM hash, and relay it to authenticate elsewhere."
  },
  {
    "question": "What is the MITRE ATT&CK technique for Compiled HTML File (CHM) execution?",
    "answer": "T1218.001 \u2014 Signed Binary Proxy Execution: Compiled HTML File. CHM files execute code via hh.exe with embedded JavaScript or VBScript."
  },
  {
    "question": "What is a common detection for Cobalt Strike beacon on an endpoint?",
    "answer": "Cobalt Strike beacons use named pipes (e.g., \\\\.\\pipe\\msagent_*), inject into legitimate processes, and show periodic HTTPS beaconing."
  },
  {
    "question": "How do you detect anomalous NTDS.dit file access?",
    "answer": "Monitor Event ID 4663 for NTDS.dit access. Any process accessing this file from a non-DC host is credential dumping (T1003.003)."
  },
  {
    "question": "How do you detect PsExec execution with Event IDs?",
    "answer": "Event ID 4688 with psexec.exe or PSEXESVC.exe. Event ID 7045 for service creation named PSEXESVC. Event ID 5145 for ADMIN$ share access over SMB."
  },
  {
    "question": "How do you detect ZeroLogon (CVE-2020-1472) exploitation?",
    "answer": "Event ID 5827/5828 for Netlogon secure channel failures, or anomalous RPC traffic to the DC on port 445."
  },
  {
    "question": "What are the key differences between EDR and antivirus?",
    "answer": "AV relies on signatures and file scans. EDR monitors behavior in real time and correlates events across endpoints, detecting fileless and in-memory attacks."
  },
  {
    "question": "What is a common technique to detect data staging before exfiltration?",
    "answer": "Monitor for compression tools (RAR, 7z, WinRAR) on file servers. Event ID 4688 with rar a, 7z a, or zip -r targeting non-standard directories."
  },
  {
    "question": "What is the MITRE ATT&CK technique for Browser Bookmark Discovery?",
    "answer": "T1217 \u2014 Browser Bookmark Discovery. Adversaries enumerate bookmarks to find internal resources, SaaS apps, or cloud consoles."
  },
  {
    "question": "How do you detect a user account being added to a privileged group?",
    "answer": "Event ID 4728 (global group) and Event ID 4732 (local group). Check for unexpected additions to Domain Admins or local Administrators."
  },
  {
    "question": "How do you detect an adversary abusing Windows Error Reporting?",
    "answer": "Monitor Event ID 4688 for WerFault.exe -k -r with command line pointing to lsass.exe \u2014 this dumps LSASS memory."
  },
  {
    "question": "What is the MITRE ATT&CK technique for PowerSploit Invoke-Mimikatz?",
    "answer": "T1003.001 \u2014 OS Credential Dumping: LSASS Memory. Detected via Event ID 4104 (PowerShell ScriptBlock logging) with mimikatz function signatures."
  },
]

deck = {
    "title": "CSIRT / SOC Analyst",
    "description": "Incident response, detection engineering, SIEM, threat intel, and malware analysis",
    "cards": cards
}

with open(r"C:\Users\no_ne\Desktop\git-repo\Scripts\ai-combined-tools\flashcards\csirt-soc-analyst.yaml", "w", encoding="utf-8") as f:
    yaml.dump(deck, f, default_flow_style=False, allow_unicode=True, sort_keys=False, width=4096)

with open(r"C:\Users\no_ne\Desktop\git-repo\Scripts\ai-combined-tools\flashcards\csirt-soc-analyst.yaml", "r", encoding="utf-8") as f:
    loaded = yaml.safe_load(f)
    print(f"Title: {loaded['title']}")
    print(f"Description: {loaded['description']}")
    print(f"Cards: {len(loaded['cards'])}")
