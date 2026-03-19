# Threat-Hunting-Port-of-Entry

<img width="740" height="1110" alt="519130689-f6352076-3a19-4fc9-abdb-a2a3060c1ca7" src="https://github.com/user-attachments/assets/ed82b033-8528-4122-ab72-d9a29c05333b" />

🕵️‍♂️ Threat Hunt: "Port of Entry"
Scenario
INCIDENT BRIEF — Azuki Import/Export — 梓貿易株式会社

Competitor undercut our 6-year shipping contract by exactly 3%. Our supplier contracts and pricing data appeared on underground forums.

FieldDetailsCompanyAzuki Import/Export Trading Co. — 23 employees, shipping logistics Japan/SE AsiaCompromised SystemAZUKI-SL (IT admin workstation)Available EvidenceMicrosoft Defender for Endpoint logs
Log Query Scope:
kqlDeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
This report includes:

📅 Timeline reconstruction of auditing, reconnaissance, and attempted exfiltration on azuki-sl
📜 Detailed queries using Microsoft Defender Advanced Hunting (KQL)
🎯 MITRE ATT&CK mapping to understand TTP alignment
🧪 Evidence-based summaries supporting each flag and behavior discovered


🧰 Platforms and Tools
Analysis Environment: Microsoft Defender for Endpoint · Log Analytics Workspace · Azure
Techniques Used: Kusto Query Language (KQL) · Behavioral analysis of endpoint logs (DeviceProcessEvents, DeviceNetworkEvents, DeviceRegistryEvents)

📔 Summary of Findings (Flags)
FlagObjectiveFindingTimestamp1Source IP of RDP connection88.97.178.122025-11-19T00:57:18Z2Compromised user accountkenji.sato2025-11-19T00:57:18Z3Network enumeration commandARP.EXE -a2025-11-19T19:04:01Z4Primary malware staging directoryC:\ProgramData\WindowsCache2025-11-19T19:05:33Z5File extensions excluded from Defender32025-11-19T18:49:27Z6Temp folder excluded from DefenderC:\Users\KENJI~1.SAT\AppData\Local\Temp2025-11-19T18:49:27Z7Windows binary abused to download filescertutil.exe2025-11-19T19:06:58Z8Scheduled task name for persistenceWindows Update Check2025-11-19T19:07:46Z9Scheduled task executable pathC:\ProgramData\WindowsCache\svchost.exe2025-11-19T19:07:46Z10C2 server IP address78.141.196.62025-11-19T18:37:26Z11C2 communication port4432025-11-19T19:11:04Z12Credential dumping tool filenamemm.exe2025-11-19T19:07:22Z13Memory extraction modulesekurlsa::logonpasswords2025-11-19T19:08:26Z14Data staging archive filenameexport-data.zip2025-11-19T19:08:58Z15Cloud exfiltration channelDiscord2025-11-19T19:09:21Z16First event log clearedSecurity2025-11-19T19:11:39Z17Backdoor account usernamesupport2025-11-19T19:09:53Z18Malicious PowerShell scriptwupdate.ps12025-11-19T18:49:48Z19Lateral movement target IP10.1.0.1882025-11-19T19:10:42Z20Lateral movement remote access toolmstsc.exe2025-11-19T19:10:41Z

🚩 Flag Details
Flag 1 — INITIAL ACCESS: Remote Access Source
Flag Value: 88.97.178.12 — 2025-11-19T00:57:18Z
Detection Strategy: Query logon events for interactive sessions from external sources. Filter DeviceLogonEvents by LogonType indicating remote access.
kqlDeviceLogonEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where LogonType == "RemoteInteractive"
| project Timestamp, AccountName, RemoteIP, AdditionalFields
| sort by AccountName

Why This Matters: RDP connections leave network traces identifying the source of unauthorized access. Determining the origin helps with threat actor attribution and blocking ongoing attacks.


Flag 2 — INITIAL ACCESS: Compromised User Account
Flag Value: kenji.sato — 2025-11-19T00:57:18Z
Detection Strategy: The RemoteIP was shown to have accessed the compromised account through RDP. Same query as Flag 1.
kqlDeviceLogonEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where LogonType == "RemoteInteractive"
| project Timestamp, AccountName, RemoteIP, AdditionalFields
| sort by AccountName

Why This Matters: Identifying which credentials were compromised determines the scope of unauthorized access and guides remediation including password resets and privilege reviews.


Flag 3 — DISCOVERY: Network Reconnaissance
Flag Value: ARP.EXE -a — 2025-11-19T19:04:01Z
Detection Strategy: Look for commands that reveal local network devices and hardware addresses. Check DeviceProcessEvents for network enumeration utilities executed post-access.
kqlDeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("whoami", "hostname", "systeminfo", "ipconfig", "net user",
    "net localgroup", "query user", "quser", "qwinsta", "wmic", "Get-ComputerInfo",
    "Get-CimInstance", "Get-WmiObject", "Get-NetIPConfiguration", "Get-NetAdapter",
    "Get-NetIPAddress", "Get-Process", "tasklist", "netstat -ano", "reg query",
    "Get-Service", "Get-LocalUser", "Get-ChildItem Env:")
    or FileName in~ ("netsh.exe", "ipconfig.exe", "systeminfo.exe", "whoami.exe", "dsquery.exe",
    "dsget.exe", "nltest.exe", "nbtstat.exe", "arp.exe", "tracert.exe", "quser.exe", "qwinsta.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by Timestamp asc

Why This Matters: Attackers enumerate network topology to identify lateral movement opportunities and high-value targets — a key indicator of advanced persistent threats.


Flag 4 — DEFENSE EVASION: Malware Staging Directory
Flag Value: C:\ProgramData\WindowsCache — 2025-11-19T19:05:33Z
Detection Strategy: Search for newly created directories in system folders. Look for mkdir or New-Item commands followed by attrib commands that modify folder attributes.
kqlDeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("mkdir", "New-Item", "attrib")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
    FolderCreated=ProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp asc

Why This Matters: Attackers establish staging locations to organize tools and stolen data. Identifying these directories reveals the scope of compromise and helps locate additional malicious artifacts.


Flag 5 — DEFENSE EVASION: File Extension Exclusions
Flag Value: 3 extensions — 2025-11-19T18:49:27Z
Detection Strategy: Search DeviceRegistryEvents for modifications to Windows Defender's exclusion settings. Count unique extensions added to the Exclusions\Extensions registry key.
kqlDeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType == "RegistryValueSet"
| where RegistryKey startswith "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions"
| project Timestamp, DeviceName, RegistryKey, RegistryValueData, RegistryValueName

Why This Matters: File extension exclusions prevent Defender from scanning malicious files, revealing the scope of the attacker's defense evasion strategy.


Flag 6 — DEFENSE EVASION: Temporary Folder Exclusion
Flag Value: C:\Users\KENJI~1.SAT\AppData\Local\Temp — 2025-11-19T18:49:27Z
Detection Strategy: Search DeviceRegistryEvents for folder path exclusions added to Defender configuration. Focus on RegistryValueName for temp folder paths.
kqlDeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType == "RegistryValueSet"
| where RegistryKey startswith "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths"
| project Timestamp, DeviceName, RegistryKey, RegistryValueData,
    RegistryValueName, InitiatingProcessFolderPath, InitiatingProcessFileName

Why This Matters: Folder exclusions allow malware to be downloaded and executed in temp directories without triggering Defender scans.


Flag 7 — DEFENSE EVASION: Download Utility Abuse
Flag Value: certutil.exe — 2025-11-19T19:06:58Z
Detection Strategy: Look for built-in Windows tools with network download capabilities. Search DeviceProcessEvents for command lines containing URLs and output file paths.
kqlDeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("http://", "https://")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine,
    InitiatingProcessFolderPath, AdditionalFields, InitiatingProcessCommandLine
| order by Timestamp asc

Why This Matters: Legitimate system utilities weaponized to download malware bypass many detection controls. Identifying these LOLBin techniques helps improve defensive coverage.


Flag 8 — PERSISTENCE: Scheduled Task Name
Flag Value: Windows Update Check — 2025-11-19T19:07:46Z
Detection Strategy: Search for scheduled task creation commands. Look for schtasks.exe with the /create parameter in DeviceProcessEvents.
kqlDeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("create", "task")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine,
    InitiatingProcessFolderPath, AdditionalFields, InitiatingProcessCommandLine
| order by Timestamp asc

Why This Matters: Scheduled tasks provide reliable persistence across reboots. The name attempts to blend with legitimate Windows maintenance routines.


Flag 9 — PERSISTENCE: Scheduled Task Target
Flag Value: C:\ProgramData\WindowsCache\svchost.exe — 2025-11-19T19:07:46Z
Detection Strategy: Extract the task action from the scheduled task creation command line. Look for the /tr parameter value in the schtasks command. Same query as Flag 8.

Why This Matters: The scheduled task action defines what executes at runtime, revealing the exact persistence mechanism and malware location.


Flag 10 — COMMAND & CONTROL: C2 Server Address
Flag Value: 78.141.196.6 — 2025-11-19T18:37:26Z
Detection Strategy: Analyze network connections from the suspicious executable after download. Use DeviceNetworkEvents to find outbound connections to external IPs, excluding known browsers.
kqlDeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RemoteIPType == "Public"
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe", "teams.exe", "outlook.exe")
| project Timestamp, LocalIP, RemoteIP, RemotePort, Protocol, ActionType,
    InitiatingProcessAccountName, InitiatingProcessCommandLine,
    InitiatingProcessRemoteSessionDeviceName
| order by Timestamp asc

Why This Matters: Identifying C2 servers enables network blocking and infrastructure tracking to disrupt ongoing attacker operations.


Flag 11 — COMMAND & CONTROL: C2 Communication Port
Flag Value: 443 — 2025-11-19T19:11:04Z
Detection Strategy: Examine the RemotePort field for outbound connections to the confirmed C2 IP.
kqlDeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RemoteIP == "78.141.196.6"
| project Timestamp, LocalIP, RemoteIP, RemotePort, Protocol, ActionType,
    InitiatingProcessAccountName, InitiatingProcessCommandLine,
    InitiatingProcessRemoteSessionDeviceName
| order by Timestamp asc

Why This Matters: Use of port 443 allows C2 traffic to blend with normal HTTPS traffic, making it harder to detect at the network perimeter.


Flag 12 — CREDENTIAL ACCESS: Credential Theft Tool
Flag Value: mm.exe — 2025-11-19T19:07:22Z
Detection Strategy: Look for executables downloaded to the staging directory with short filenames, created shortly before LSASS memory access events.
kqlDeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName endswith ".exe"
| project Timestamp, DeviceName, FileName, ActionType, InitiatingProcessFileName, FolderPath
| order by Timestamp desc

Why This Matters: Credential dumping tools extract authentication secrets from memory and are typically renamed to avoid signature-based detection.


Flag 13 — CREDENTIAL ACCESS: Memory Extraction Module
Flag Value: sekurlsa::logonpasswords — 2025-11-19T19:08:26Z
Detection Strategy: Examine command line arguments passed to the credential dumping tool. Look for module::command syntax in process command lines.
kqlDeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("cls", "exit")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine,
    InitiatingProcessFolderPath, AdditionalFields, InitiatingProcessCommandLine
| order by Timestamp asc

Why This Matters: Documenting the exact module used in credential dumping aids detection engineering and confirms LSASS-based extraction.


Flag 14 — COLLECTION: Data Staging Archive
Flag Value: export-data.zip — 2025-11-19T19:08:58Z
Detection Strategy: Search for ZIP file creations in the staging directory. Look for Compress-Archive commands or ZIP files created before exfiltration activity.
kqlDeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName endswith ".zip"
| project Timestamp, DeviceName, FileName, ActionType, InitiatingProcessFileName, FolderPath
| order by Timestamp desc

Why This Matters: Compressing stolen data enables efficient exfiltration. Archive filenames can reveal attacker organization and intent.


Flag 15 — EXFILTRATION: Exfiltration Channel
Flag Value: Discord — 2025-11-19T19:09:21Z
Detection Strategy: Analyze outbound HTTPS connections during the exfiltration phase. Check DeviceNetworkEvents for connections to file sharing or communication platforms.
kqlDeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessCommandLine has_any ("https")
| project Timestamp, LocalIP, RemoteIP, RemotePort, Protocol, ActionType,
    InitiatingProcessAccountName, InitiatingProcessCommandLine,
    InitiatingProcessRemoteSessionDeviceName, AdditionalFields
| order by Timestamp asc

Why This Matters: Widely-used cloud platforms are frequently abused for data theft as they blend with legitimate traffic and are rarely blocked at the perimeter.


Flag 16 — ANTI-FORENSICS: Log Tampering
Flag Value: Security (first log cleared) — 2025-11-19T19:11:39Z
Detection Strategy: Search for event log clearing commands near the end of the attack timeline. Look for wevtutil.exe executions.
kqlDeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName =~ "wevtutil.exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine,
    InitiatingProcessFolderPath, AdditionalFields, InitiatingProcessCommandLine
| order by Timestamp asc

Why This Matters: Clearing event logs destroys forensic evidence. The order of clearing can indicate attacker priorities and sophistication.


Flag 17 — IMPACT: Persistence Account
Flag Value: support — 2025-11-19T19:09:53Z
Detection Strategy: Search for account creation commands with the /add parameter followed by administrator group additions.
kqlDeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("net user", "/add", "useradd", "username")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine,
    InitiatingProcessFolderPath, AdditionalFields, InitiatingProcessCommandLine
| order by Timestamp asc

Why This Matters: Hidden admin accounts provide alternative re-entry for future operations and are often configured to avoid appearing in normal user interfaces.


Flag 18 — EXECUTION: Malicious Script
Flag Value: wupdate.ps1 — 2025-11-19T18:49:48Z
Detection Strategy: Search DeviceFileEvents for script files created in temporary directories during the initial compromise phase.
kqlDeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName endswith ".ps1" or FileName endswith ".bat"
| project Timestamp, DeviceName, FileName, ActionType, InitiatingProcessFileName, FolderPath
| order by Timestamp desc

Why This Matters: Identifying the initial attack script reveals the entry point and automation method used throughout the compromise.


Flag 19 — LATERAL MOVEMENT: Secondary Target
Flag Value: 10.1.0.188 — 2025-11-19T19:10:42Z
Detection Strategy: Examine target system arguments in remote access commands. Look for IP addresses used with cmdkey or mstsc commands near the end of the timeline.
kqlDeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessCommandLine has_any ("cmdkey", "mstsc")
| project Timestamp, LocalIP, RemoteIP, RemotePort, Protocol, ActionType,
    InitiatingProcessAccountName, InitiatingProcessCommandLine,
    InitiatingProcessRemoteSessionDeviceName, AdditionalFields
| order by Timestamp asc

Why This Matters: Lateral movement targets are selected for their access to sensitive data or elevated network privileges, revealing attacker objectives.


Flag 20 — LATERAL MOVEMENT: Remote Access Tool
Flag Value: mstsc.exe — 2025-11-19T19:10:41Z
Detection Strategy: Search for RDP connection utilities executed with remote IP addresses as arguments.
kqlDeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine matches regex @"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine,
    InitiatingProcessFolderPath, AdditionalFields, InitiatingProcessCommandLine
| order by Timestamp asc

Why This Matters: Built-in remote access tools are preferred for lateral movement as they blend with legitimate administrative activity and are harder to detect than custom tools.


🎯 MITRE ATT&CK Technique Mapping
FlagDescriptionMITRE ATT&CK Technique(s)1Remote Desktop / external connection as entry pointT1078.004 Valid Accounts: RDP · T1190 Exploit Public-Facing Application2Compromised credentials used to access hostT1078 Valid Accounts3Enumerate network neighbours, IPs, ARP tableT1016 System Network Configuration Discovery · T1087.002 Account Discovery4Create hidden staging directory for payloadsT1221 Template Injection · T1564.001 Hide Artifacts: Hidden Files and Directories5Exclude file extensions from AV scanningT1562.004 Impair Defenses: Disable or Modify Tools6Exclude Temp folder from AV scanningT1562.004 Impair Defenses7Native Windows binary used to download payloadsT1218 System Binary Proxy Execution · T1105 Ingress Tool Transfer8Create scheduled task for persistenceT1053.005 Scheduled Task / Job9Configure scheduled task to run attacker payloadT1053.005 Scheduled Task / Job10Outbound connection to C2 serverT1071.001 Application Layer Protocol: Web · T1043 Commonly Used Port11Port 443 used for C2 communicationT1043 Commonly Used Port12Credential dumping tool deployedT1003 OS Credential Dumping13LSASS memory-based extraction moduleT1003.001 OS Credential Dumping: LSASS Memory14Data archived for exfiltrationT1560.001 Archive Collected Data: Zip15Data exfiltrated via cloud platformT1041 Exfiltration Over C2 Channel · T1071.001 Application Layer Protocol16Windows event logs clearedT1070.001 Indicator Removal: Clear Windows Event Logs17Backdoor local account createdT1136.001 Create Account: Local Account18PowerShell script automates attack chainT1059.001 Command and Scripting Interpreter: PowerShell19Lateral movement to secondary hostT1021.001 Remote Services: Remote Desktop Protocol20Native RDP tool used for lateral spreadT1021 Remote Services

🧾 Conclusion
The threat hunt revealed a structured, multi-stage intrusion relying heavily on living-off-the-land techniques, stealthy persistence, system reconnaissance, and staged data exfiltration. The adversary leveraged legitimate remote access points, blended malicious activity with normal Windows processes, and created deceptive artifacts to obscure intent.
Attack progression:

Initial Access — compromised credentials via exposed RDP
Reconnaissance — scoped user environment, network posture
Defense Evasion — AV exclusions, trusted system binary abuse
Persistence — scheduled tasks and registry Run keys
Data Staging & Exfiltration — archived and exfiltrated via Discord
Anti-Forensics — event logs cleared to impede investigation

The hunt demonstrated how even lightweight attacker activity leaves detectable footprints across Windows telemetry. By correlating anomalies—unexpected file creations, scheduled task artifacts, unusual connections—the full attack chain became visible.

🎓 Lessons Learned
1. Simple tradecraft still leaves multi-telemetry footprints.
Built-in tools (PowerShell, schtasks.exe, explorer.exe) were used throughout, yet the chain remained traceable via timestamps, registry artifacts, and process execution logs.
2. Persistence often has redundancy.
Scheduled tasks were supplemented by a Run key fallback — typical real-world behavior.
3. Staging and exfiltration prep precedes actual exfil.
Early connectivity checks and port validation occurred before real exfiltration — strong early-warning signals.
4. Endpoint visibility is critical. Without file creation telemetry, PowerShell logging, registry monitoring, scheduled task recording, and Defender config change alerts, identifying the attacker's sequence would be significantly harder.

🛠️ Recommendations for Remediation
1. Harden Remote Access

Enforce MFA on all RDP, VPN, and Remote Assistance
Restrict inbound RDP to VPN-only networks
Monitor RDP logins for anomalies (impossible travel, off-hours access)

2. Strengthen Credential Protection

Rotate all credentials observed during the compromise
Deploy LAPS / LAPS NG for local admin password randomization
Reduce unnecessary user privileges

3. Increase Logging Coverage

Enable PowerShell Module, Script Block, and Transcription logging
Enable Defender tamper protection
Alert on scheduled task creation, Run key additions, and archive creation in sensitive directories

4. Block LOLBin Misuse
BinaryRiskcertutil.exeFile download abusepowershell.exe / pwsh.exeScript executionbitsadmin.exeBackground transfer abuserundll32.exeDLL execution proxywscript.exe / cscript.exeScript host abuse
Apply WDAC / AppLocker to control script execution paths.
5. Monitor for Staging & Exfil Indicators

Alert on large archives (*.zip, *.7z, *.rar) in temp or profile directories
Monitor abnormal outbound HTTPS to unknown IPs/domains
Flag DNS lookups to newly registered or unclassified domains

6. Improve Behavioral Detection

Detect AV exclusion modifications and first-time outbound connections
Hunt for high-volume PowerShell execution by non-IT users
Implement continuous threat-hunting cycles, not just reactive investigations

7. Incident Response Hardening

Develop playbooks for credential resets, lateral movement containment, and persistence removal
Conduct tabletop exercises simulating this exact intrusion pattern
