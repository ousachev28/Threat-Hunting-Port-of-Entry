# Threat Hunting: Port of Entry

<img width="740" height="1110" alt="519130689-f6352076-3a19-4fc9-abdb-a2a3060c1ca7" src="https://github.com/user-attachments/assets/25894e34-0352-4c46-a393-937751e0cc37" />

# Table of Contents

- [Threat Hunt: "Port of Entry"](#threat-hunt-port-of-entry)
- [Platforms and Tools](#platforms-and-tools)
- [Summary of Findings (Flags)](#summary-of-findings-flags)
  - [Flag 1: INITIAL ACCESS - Remote Access Source](#flag-1--initial-access-remote-access-source)
  - [Flag 2: INITIAL ACCESS - Compromised User Account](#flag-2--initial-access-compromised-user-account)
  - [Flag 3: DISCOVERY - Network Reconnaissance](#flag-3--discovery-network-reconnaissance)
  - [Flag 4: DEFENSE EVASION - Malware Staging Directory](#flag-4--defense-evasion-malware-staging-directory)
  - [Flag 5: DEFENSE EVASION - File Extension Exclusions](#flag-5--defense-evasion-file-extension-exclusions)
  - [Flag 6: DEFENSE EVASION - Temporary Folder Exclusion](#flag-6--defense-evasion-temporary-folder-exclusion)
  - [Flag 7: DEFENSE EVASION - Download Utility Abuse](#flag-7--defense-evasion-download-utility-abuse)
  - [Flag 8: PERSISTENCE - Scheduled Task Name](#flag-8--persistence-scheduled-task-name)
  - [Flag 9: PERSISTENCE - Scheduled Task Target](#flag-9--persistence-scheduled-task-target)
  - [Flag 10: COMMAND & CONTROL - C2 Server Address](#flag-10--command--control-c2-server-address)
  - [Flag 11: COMMAND & CONTROL - C2 Communication Port](#flag-11--command--control-c2-communication-port)
  - [Flag 12: CREDENTIAL ACCESS - Credential Theft Tool](#flag-12--credential-access-credential-theft-tool)
  - [Flag 13: CREDENTIAL ACCESS - Memory Extraction Module](#flag-13--credential-access-memory-extraction-module)
  - [Flag 14: COLLECTION - Data Staging Archive](#flag-14--collection-data-staging-archive)
  - [Flag 15: EXFILTRATION - Exfiltration Channel](#flag-15--exfiltration-exfiltration-channel)
  - [Flag 16: ANTI-FORENSICS - Log Tampering](#flag-16--anti-forensics-log-tampering)
  - [Flag 17: IMPACT - Persistence Account](#flag-17--impact-persistence-account)
  - [Flag 18: EXECUTION - Malicious Script](#flag-18--execution-malicious-script)
  - [Flag 19: LATERAL MOVEMENT - Secondary Target](#flag-19--lateral-movement-secondary-target)
  - [Flag 20: LATERAL MOVEMENT - Remote Access Tool](#flag-20--lateral-movement-remote-access-tool)
- [MITRE ATT&CK Technique Mapping](#mitre-attck-technique-mapping)
- [Conclusion](#conclusion)
- [Lessons Learned](#lessons-learned)
- [Recommendations for Remediation](#recommendations-for-remediation)

# Threat Hunt: "Port of Entry"
## Scenario

**INCIDENT BRIEF — Azuki Import/Export **

Competitor undercut our 6-year shipping contract by exactly 3%. Our supplier contracts and pricing data appeared on underground forums.

| Field | Details |
|---|---|
| **Company** | Azuki Import/Export Trading Co. — 23 employees, shipping logistics Japan/SE Asia |
| **Compromised System** | `AZUKI-SL` (IT admin workstation) |
| **Available Evidence** | Microsoft Defender for Endpoint logs |

**Log Query Scope:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
```

This report includes:

- Timeline reconstruction of auditing, reconnaissance, and attempted exfiltration of data on the device `azuki-sl`
- Detailed queries using Microsoft Defender Advanced Hunting (KQL)
- MITRE ATT&CK mapping to understand TTP alignment
- Evidence-based summaries supporting each flag and behavior discovered

---

## Platforms and Tools

**Analysis Environment:**
- Microsoft Defender for Endpoint
- Log Analytics Workspace
- Azure

**Techniques Used:**
- Kusto Query Language (KQL)
- Behavioral analysis of endpoint logs (`DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceRegistryEvents`)

---

## Summary of Findings (Flags)

| Flag | Objective | Finding | Timestamp |
|---|---|---|---|
| 1 | Identify the source IP address of the RDP connection | `88.97.178.12` was the IP address accessing the compromised account | `2025-11-19T00:57:18Z` |
| 2 | Identify the user account that was compromised for initial access | The account `kenji.sato` has been compromised | `2025-11-19T00:57:18Z` |
| 3 | Identify the command and argument used to enumerate network neighbours | `ARP.EXE -a` was executed for enumeration | `2025-11-19T19:04:01Z` |
| 4 | Identify the PRIMARY staging directory where malware was stored | `C:\ProgramData\WindowsCache` was found to be the primary staging directory | `2025-11-19T19:05:33Z` |
| 5 | How many file extensions were excluded from Windows Defender scanning? | 3 file extensions were excluded | `2025-11-19T18:49:27Z` |
| 6 | What temporary folder path was excluded from Windows Defender scanning? | `C:\Users\KENJI~1.SAT\AppData\Local\Temp` was excluded | `2025-11-19T18:49:27Z` |
| 7 | Identify the Windows-native binary the attacker abused to download files | `certutil.exe` was used to download malware | `2025-11-19T19:06:58Z` |
| 8 | Identify the name of the scheduled task created for persistence | `Windows Update Check` was found to be a disguised scheduled task | `2025-11-19T19:07:46Z` |
| 9 | Identify the executable path configured in the scheduled task | `C:\ProgramData\WindowsCache\svchost.exe` | `2025-11-19T19:07:46Z` |
| 10 | Identify the IP address of the command and control server | `78.141.196.6` was found to be the C2 server | `2025-11-19T18:37:26Z` |
| 11 | Identify the destination port used for C2 communications | Port `443` was the destination port used | `2025-11-19T19:11:04Z` |
| 12 | Identify the filename of the credential dumping tool | `mm.exe` was identified as the credential dumping tool | `2025-11-19T19:07:22Z` |
| 13 | Identify the module used to extract logon passwords from memory | `sekurlsa::logonpasswords` module was utilized | `2025-11-19T19:08:26Z` |
| 14 | Identify the compressed archive filename used for data exfiltration | `export-data.zip` was created for data exfiltration | `2025-11-19T19:08:58Z` |
| 15 | Identify the cloud service used to exfiltrate stolen data | Discord was used to exfiltrate the data | `2025-11-19T19:09:21Z` |
| 16 | Identify the first Windows event log cleared by the attacker | `Security` was the first event log cleared | `2025-11-19T19:11:39Z` |
| 17 | Identify the backdoor account username created by the attacker | `support` was the name of account created | `2025-11-19T19:09:53Z` |
| 18 | Identify the PowerShell script file used to automate the attack chain | `wupdate.ps1` was the automated script | `2025-11-19T18:49:48Z` |
| 19 | What IP address was targeted for lateral movement? | `10.1.0.188` | `2025-11-19T19:10:42Z` |
| 20 | Identify the remote access tool used for lateral movement | `mstsc.exe` was identified as the RAT | `2025-11-19T19:10:41Z` |

---

## Flag Details

### Flag 1 — INITIAL ACCESS: Remote Access Source

**Objective:** Identify the source IP address of the Remote Desktop Protocol connection.

**Flag Value:** `88.97.178.12` — `2025-11-19T00:57:18Z`

**Detection Strategy:** Query logon events for interactive sessions from external sources during the incident timeframe. Use `DeviceLogonEvents` and filter by `LogonType` values indicating remote access.

**KQL Query:**
```
DeviceLogonEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where isnotempty(RemoteIP) and RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| project TimeGenerated, AccountName, DeviceName, ActionType, RemoteIP, RemoteIPType
```
**Evidence**

<img width="1015" height="95" alt="image" src="https://github.com/user-attachments/assets/9d38f243-7678-486f-b386-8e018bdc8313" />


**Why This Matters:** RDP connections leave network traces that identify the source of unauthorized access. Determining the origin helps with threat actor attribution and blocking ongoing attacks.

---

### Flag 2 — INITIAL ACCESS: Compromised User Account

**Objective:** Identify the user account that was compromised for initial access.

**Flag Value:** `kenji.sato` — `2025-11-19T00:57:18Z`

**Detection Strategy:** The `RemoteIP` was shown to have accessed the compromised account through RDP.

```kql
DeviceLogonEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where LogonType == "RemoteInteractive"
| project Timestamp, AccountName, RemoteIP, AdditionalFields
| sort by AccountName
```

> **Why This Matters:** Identifying which credentials were compromised determines the scope of unauthorized access and guides remediation efforts including password resets and privilege reviews.

---

### Flag 3 — DISCOVERY: Network Reconnaissance

**Objective:** Identify the command and argument used to enumerate network neighbours.

**Flag Value:** `ARP.EXE -a` — `2025-11-19T19:04:01Z`

**Detection Strategy:** Look for commands that reveal local network devices and hardware addresses. Check `DeviceProcessEvents` for network enumeration utilities executed after initial access.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("whoami", "hostname", "systeminfo", "ipconfig", "ipconfig /all",
    "net user", "net localgroup", "query user", "quser", "qwinsta", "wmic", "Get-ComputerInfo",
    "Get-CimInstance", "Get-WmiObject", "Get-NetIPConfiguration", "Get-NetAdapter",
    "Get-NetIPAddress", "Get-Process", "tasklist", "netstat -ano", "reg query",
    "Get-Service", "Get-LocalUser", "Get-ChildItem Env:")
    or FileName in~ ("netsh.exe", "ipconfig.exe", "systeminfo.exe", "whoami.exe", "dsquery.exe",
    "dsget.exe", "nltest.exe", "nbtstat.exe", "arp.exe", "tracert.exe", "quser.exe", "qwinsta.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by Timestamp asc
```

> **Why This Matters:** Attackers enumerate network topology to identify lateral movement opportunities and high-value targets. This reconnaissance activity is a key indicator of advanced persistent threats.

---

### Flag 4 — DEFENSE EVASION: Malware Staging Directory

**Objective:** Find the primary staging directory where malware was stored.

**Flag Value:** `C:\ProgramData\WindowsCache` — `2025-11-19T19:05:33Z`

**Detection Strategy:** Search for newly created directories in system folders that were subsequently hidden. Look for `mkdir` or `New-Item` commands followed by `attrib` commands that modify folder attributes.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("mkdir", "New-Item", "attrib")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderCreated=ProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp asc
```

> **Why This Matters:** Attackers establish staging locations to organize tools and stolen data. Identifying these directories reveals the scope of compromise and helps locate additional malicious artifacts.

---

### Flag 5 — DEFENSE EVASION: File Extension Exclusions

**Objective:** Find how many file extensions were excluded from Windows Defender scanning.

**Flag Value:** `3` — `2025-11-19T18:49:27Z`

**Detection Strategy:** Search `DeviceRegistryEvents` for registry modifications to Windows Defender's exclusion settings. Count the unique file extensions added to the `Exclusions\Extensions` registry key.

```kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType == "RegistryValueSet"
| where RegistryKey startswith "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions"
| project Timestamp, DeviceName, RegistryKey, RegistryValueData, RegistryValueName
```

> **Why This Matters:** Attackers add file extension exclusions to Windows Defender to prevent scanning of malicious files. Counting these exclusions reveals the scope of the attacker's defense evasion strategy.

---

### Flag 6 — DEFENSE EVASION: Temporary Folder Exclusion

**Objective:** What temporary folder path was excluded from Windows Defender scanning?

**Flag Value:** `C:\Users\KENJI~1.SAT\AppData\Local\Temp` — `2025-11-19T18:49:27Z`

**Detection Strategy:** Search `DeviceRegistryEvents` for folder path exclusions added to Windows Defender configuration. Focus on the `RegistryValueName` field for temporary folder paths.

```kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType == "RegistryValueSet"
| where RegistryKey startswith "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths"
| project Timestamp, DeviceName, RegistryKey, RegistryValueData, RegistryValueName, InitiatingProcessFolderPath, InitiatingProcessFileName
```

> **Why This Matters:** Attackers add folder path exclusions to Windows Defender to prevent scanning of directories used for downloading and executing malicious tools. These exclusions allow malware to run undetected.

---

### Flag 7 — DEFENSE EVASION: Download Utility Abuse

**Objective:** Identify the Windows-native binary the attacker abused to download files.

**Flag Value:** `certutil.exe` — `2025-11-19T19:06:58Z`

**Detection Strategy:** Look for built-in Windows tools with network download capabilities. Search `DeviceProcessEvents` for processes with command lines containing URLs and output file paths.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("http://", "https://")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine,
    InitiatingProcessFolderPath, AdditionalFields, InitiatingProcessCommandLine
| order by Timestamp asc
```

> **Why This Matters:** Legitimate system utilities are often weaponized to download malware while evading detection. Identifying these techniques helps improve defensive controls.

---

### Flag 8 — PERSISTENCE: Scheduled Task Name

**Objective:** Identify the name of the scheduled task created for persistence.

**Flag Value:** `Windows Update Check` — `2025-11-19T19:07:46Z`

**Detection Strategy:** Search for scheduled task creation commands. Look for `schtasks.exe` with the `/create` parameter in `DeviceProcessEvents`.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("create", "task")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine,
    InitiatingProcessFolderPath, AdditionalFields, InitiatingProcessCommandLine
| order by Timestamp asc
```

> **Why This Matters:** Scheduled tasks provide reliable persistence across system reboots. The task name often attempts to blend with legitimate Windows maintenance routines.

---

### Flag 9 — PERSISTENCE: Scheduled Task Target

**Objective:** Identify the executable path configured in the scheduled task.

**Flag Value:** `C:\ProgramData\WindowsCache\svchost.exe` — `2025-11-19T19:07:46Z`

**Detection Strategy:** Extract the task action from the scheduled task creation command line. Look for the `/tr` parameter value in the `schtasks` command.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("create", "task")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine,
    InitiatingProcessFolderPath, AdditionalFields, InitiatingProcessCommandLine
| order by Timestamp asc
```

> **Why This Matters:** The scheduled task action defines what executes at runtime. This reveals the exact persistence mechanism and the malware location.

---

### Flag 10 — COMMAND & CONTROL: C2 Server Address

**Objective:** Identify the IP address of the command and control server.

**Flag Value:** `78.141.196.6` — `2025-11-19T18:37:26Z`

**Detection Strategy:** Analyze network connections initiated by the suspicious executable shortly after it was downloaded. Use `DeviceNetworkEvents` to find outbound connections to external IP addresses.

```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RemoteIPType == "Public"
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe", "teams.exe", "outlook.exe")
| project Timestamp, LocalIP, RemoteIP, RemotePort, Protocol, ActionType,
    InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessRemoteSessionDeviceName
| order by Timestamp asc
```

> **Why This Matters:** Command and control infrastructure allows attackers to remotely control compromised systems. Identifying C2 servers enables network blocking and infrastructure tracking.

---

### Flag 11 — COMMAND & CONTROL: C2 Communication Port

**Objective:** Identify the destination port used for command and control communications.

**Flag Value:** `443` — `2025-11-19T19:11:04Z`

**Detection Strategy:** Examine the destination port for outbound connections from the malicious executable. Check `DeviceNetworkEvents` for the `RemotePort` field associated with C2 traffic.

```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RemoteIP == "78.141.196.6"
| project Timestamp, LocalIP, RemoteIP, RemotePort, Protocol, ActionType,
    InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessRemoteSessionDeviceName
| order by Timestamp asc
```

> **Why This Matters:** C2 communication ports can indicate the framework or protocol used. This supports network detection rules and threat intelligence correlation.

---

### Flag 12 — CREDENTIAL ACCESS: Credential Theft Tool

**Objective:** Identify the filename of the credential dumping tool.

**Flag Value:** `mm.exe` — `2025-11-19T19:07:22Z`

**Detection Strategy:** Look for executables downloaded to the staging directory with short filenames. Search for files created shortly before LSASS memory access events.

```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName endswith ".exe"
| project Timestamp, DeviceName, FileName, ActionType, InitiatingProcessFileName, FolderPath
| order by Timestamp desc
```

> **Why This Matters:** Credential dumping tools extract authentication secrets from system memory. These tools are typically renamed to avoid signature-based detection.

---

### Flag 13 — CREDENTIAL ACCESS: Memory Extraction Module

**Objective:** Identify the module used to extract logon passwords from memory.

**Flag Value:** `sekurlsa::logonpasswords` — `2025-11-19T19:08:26Z`

**Detection Strategy:** Examine command line arguments passed to the credential dumping tool. Look for `module::command` syntax in the process command line or output redirection.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("cls", "exit")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine,
    InitiatingProcessFolderPath, AdditionalFields, InitiatingProcessCommandLine
| order by Timestamp asc
```

> **Why This Matters:** Credential dumping tools use specific modules to extract passwords from security subsystems. Documenting the exact technique used aids in detection engineering.

---

### Flag 14 — COLLECTION: Data Staging Archive

**Objective:** Identify the compressed archive filename used for data exfiltration.

**Flag Value:** `export-data.zip` — `2025-11-19T19:08:58Z`

**Detection Strategy:** Search for ZIP file creations in the staging directory during the collection phase. Look for `Compress-Archive` commands or examine files created before exfiltration activity.

```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName endswith ".zip"
| project Timestamp, DeviceName, FileName, ActionType, InitiatingProcessFileName, FolderPath
| order by Timestamp desc
```

> **Why This Matters:** Attackers compress stolen data for efficient exfiltration. The archive filename often includes dates or descriptive names for the attacker's organization.

---

### Flag 15 — EXFILTRATION: Exfiltration Channel

**Objective:** Identify the cloud service used to exfiltrate stolen data.

**Flag Value:** `Discord` — `2025-11-19T19:09:21Z`

**Detection Strategy:** Analyze outbound HTTPS connections and file upload operations during the exfiltration phase. Check `DeviceNetworkEvents` for connections to common file sharing or communication platforms.

```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessCommandLine has_any ("https")
| project Timestamp, LocalIP, RemoteIP, RemotePort, Protocol, ActionType,
    InitiatingProcessAccountName, InitiatingProcessCommandLine,
    InitiatingProcessRemoteSessionDeviceName, AdditionalFields
| order by Timestamp asc
```

> **Why This Matters:** Cloud services with upload capabilities are frequently abused for data theft. Identifying the service helps with incident scope determination and potential data recovery.

---

### Flag 16 — ANTI-FORENSICS: Log Tampering

**Objective:** Identify the first Windows event log cleared by the attacker.

**Flag Value:** `Security` — `2025-11-19T19:11:39Z`

**Detection Strategy:** Search for event log clearing commands near the end of the attack timeline. Look for `wevtutil.exe` executions and identify which log was cleared first.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName =~ "wevtutil.exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine,
    InitiatingProcessFolderPath, AdditionalFields, InitiatingProcessCommandLine
| order by Timestamp asc
```

> **Why This Matters:** Clearing event logs destroys forensic evidence and impedes investigation efforts. The order of log clearing can indicate attacker priorities and sophistication.

---

### Flag 17 — IMPACT: Persistence Account

**Objective:** Identify the backdoor account username created by the attacker.

**Flag Value:** `support` — `2025-11-19T19:09:53Z`

**Detection Strategy:** Search for account creation commands during the impact phase. Look for commands with the `/add` parameter followed by administrator group additions.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("net user", "/add", "useradd", "username")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine,
    InitiatingProcessFolderPath, AdditionalFields, InitiatingProcessCommandLine
| order by Timestamp asc
```

> **Why This Matters:** Hidden administrator accounts provide alternative access for future operations. These accounts are often configured to avoid appearing in normal user interfaces.

---

### Flag 18 — EXECUTION: Malicious Script

**Objective:** Identify the PowerShell script file used to automate the attack chain.

**Flag Value:** `wupdate.ps1` — `2025-11-19T18:49:48Z`

**Detection Strategy:** Search `DeviceFileEvents` for script files created in temporary directories during the initial compromise phase. Look for PowerShell or batch script files downloaded from external sources shortly after initial access.

```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName endswith ".ps1" or FileName endswith ".bat"
| project Timestamp, DeviceName, FileName, ActionType, InitiatingProcessFileName, FolderPath
| order by Timestamp desc
```

> **Why This Matters:** Attackers often use scripting languages to automate their attack chain. Identifying the initial attack script reveals the entry point and automation method used in the compromise.

---

### Flag 19 — LATERAL MOVEMENT: Secondary Target

**Objective:** What IP address was targeted for lateral movement?

**Flag Value:** `10.1.0.188` — `2025-11-19T19:10:42Z`

**Detection Strategy:** Examine the target system specified in remote access commands during lateral movement. Look for IP addresses used with `cmdkey` or `mstsc` commands near the end of the attack timeline.

```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessCommandLine has_any ("cmdkey", "mstsc")
| project Timestamp, LocalIP, RemoteIP, RemotePort, Protocol, ActionType,
    InitiatingProcessAccountName, InitiatingProcessCommandLine,
    InitiatingProcessRemoteSessionDeviceName, AdditionalFields
| order by Timestamp asc
```

> **Why This Matters:** Lateral movement targets are selected based on their access to sensitive data or network privileges. Identifying these targets reveals attacker objectives.

---

### Flag 20 — LATERAL MOVEMENT: Remote Access Tool

**Objective:** Identify the remote access tool used for lateral movement.

**Flag Value:** `mstsc.exe` — `2025-11-19T19:10:41Z`

**Detection Strategy:** Search for remote desktop connection utilities executed near the end of the attack timeline. Look for processes launched with remote system names or IP addresses as arguments.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine matches regex @"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine,
    InitiatingProcessFolderPath, AdditionalFields, InitiatingProcessCommandLine
| order by Timestamp asc
```

> **Why This Matters:** Built-in remote access tools are preferred for lateral movement as they blend with legitimate administrative activity. This technique is harder to detect than custom tools.

---

## MITRE ATT&CK Technique Mapping

| Flag | Description | MITRE ATT&CK Technique(s) |
|---|---|---|
| 1 | Remote Desktop / external connection as entry point | `T1078.004` – Valid Accounts: Remote Desktop Protocol<br>`T1190` – Exploit Public-Facing Application |
| 2 | Compromised credentials used to access host | `T1078` – Valid Accounts |
| 3 | Enumerate network neighbours, IPs, ARP table, topology | `T1016` – System Network Configuration Discovery<br>`T1087.002` – Account Discovery: Domain/Local Accounts |
| 4 | Create hidden or unusual staging directory for payloads | `T1221` – Template Injection<br>`T1564.001` – Hide Artifacts: Hidden Files and Directories |
| 5 | Excluding certain extensions from antivirus scanning | `T1562.004` – Impair Defenses: Disable or Modify Tools |
| 6 | Excluding Temp folder from scanning | `T1562.004` – Impair Defenses |
| 7 | Use of native Windows utilities to download payloads | `T1218` – System Binary Proxy Execution<br>`T1105` – Ingress Tool Transfer |
| 8 | Create scheduled task to maintain persistence | `T1053.005` – Scheduled Task / Job |
| 9 | Configure scheduled task to run attacker payload | `T1053.005` – Scheduled Task / Job |
| 10 | Outbound connection to attacker-controlled C2 server | `T1071.001` – Application Layer Protocol: Web Protocol<br>`T1043` – Commonly Used Port |
| 11 | Use of port 443 for C2 communication | `T1043` – Commonly Used Port |
| 12 | Use of credential-dumping tool | `T1003` – OS Credential Dumping |
| 13 | Use of memory-based extraction module | `T1003.001` – OS Credential Dumping: LSASS Memory |
| 14 | Archive of data (zip) for exfiltration | `T1560.001` – Archive Collected Data: Zip |
| 15 | Outbound data movement to external host | `T1041` – Exfiltration Over C2 Channel<br>`T1071.001` – Application Layer Protocol |
| 16 | Clearing Windows event logs | `T1070.001` – Indicator Removal on Host: Clear Windows Event Logs |
| 17 | Creation of a backdoor local account | `T1136.001` – Create Account: Local Account |
| 18 | Execution of script to automate attack chain | `T1059.001` – Command and Scripting Interpreter: PowerShell |
| 19 | Using remote access tools to move to another host | `T1021.001` – Remote Services: Remote Desktop Protocol |
| 20 | Use of native remote access tool for lateral spread | `T1021` – Remote Services |

---

## Conclusion

The threat hunt revealed a structured, multi-stage intrusion that relied heavily on **living-off-the-land techniques**, stealthy persistence mechanisms, system reconnaissance, and staged data exfiltration. The adversary leveraged legitimate remote access points, blended malicious activity with normal Windows processes, and created deceptive artifacts to obscure intent.

Each flag represented a distinct phase of the intrusion, showing a clear progression:

1. **Initial access** via compromised credentials or exposed services
2. **Reconnaissance** to scope the user environment, system configuration, and network posture
3. **Defense evasion**, including AV exclusions and the use of trusted system binaries
4. **Persistence**, via scheduled tasks and registry Run keys
5. **Data staging and exfiltration testing**, preparing outbound transfer channels
6. **Covering tracks**, by planting narrative artifacts to mislead an investigation

The hunt demonstrated how even lightweight attacker activity leaves detectable footprints across Windows telemetry. By correlating small anomalies—unexpected file creations, scheduled task artifacts, unusual connections, and deceptive files—the full attack chain became visible.

---

## Lessons Learned

**1. Even simple attacker tradecraft leaves multi-telemetry footprints.**
The operator used mostly built-in Windows tools (`PowerShell`, `explorer.exe`, `schtasks.exe`). Despite the low profile, the attack chain was still traceable through correlated timestamps, directory activity, registry artifacts, and process execution logs.

**2. Persistence often has redundancy.**
Attackers rarely rely on a single persistence channel. Scheduled tasks were supplemented by a fallback Run key—demonstrating typical real-world behavior.

**3. Staging and exfiltration prep occurs before real exfiltration.**
Early outbound connectivity checks, DNS lookups, and port validation occurred before actual exfil attempts. These pre-checks provide strong early-warning signals.

**4. Narrative artifacts are common in insider or MFA-bypass scenarios.**
Dropping misleading files reflects an attempt to justify abnormal activity. Analysts should correlate intent, timing, and surrounding operations—not the text itself.

**5. Endpoint visibility is critical.**
The hunt emphasized the importance of:
- File creation telemetry
- PowerShell logging
- Registry modifications
- Scheduled task recording
- Defender configuration changes

Without these data sources, identifying the attacker's sequence would be significantly harder.

---

## Recommendations for Remediation

### 1. Harden Remote Access
- Enforce MFA on all remote access tools (RDP, VPN, Remote Assistance)
- Limit inbound RDP to VPN-only networks
- Disable unnecessary remote-access services on endpoints
- Monitor all successful RDP logins for anomalies (impossible travel, time-of-day deviations)

### 2. Strengthen Credential Protection
- Rotate credentials for any accounts observed during compromise
- Enforce strong password length and rotation policies
- Deploy local admin password randomization (LAPS / LAPS NG)
- Reduce user privileges where unnecessary

### 3. Increase Logging Coverage
- Enable PowerShell Module, Script Block, and Transcription logs
- Enable Microsoft Defender tamper protection and prevent policy edits by non-admins
- Ensure Defender AV exclusion events are monitored (high-severity indicator)
- Alert on:
  - Scheduled task creation/modification
  - Run key registry additions
  - Archive creation in sensitive directories

### 4. Block Living-off-the-Land Binary (LOLBin) Misuse

Restrict or monitor the following binaries:

| Binary | Risk |
|---|---|
| `certutil.exe` | File download abuse |
| `powershell.exe` / `pwsh.exe` | Script execution |
| `bitsadmin.exe` | Background transfer abuse |
| `rundll32.exe` | DLL execution proxy |
| `wscript.exe` / `cscript.exe` | Script host abuse |

Apply WDAC / AppLocker to control script execution paths.

### 5. Monitor for Data Staging & Exfil Indicators
- Alert when large archives (`*.zip`, `*.7z`, `*.rar`) appear in temp or user profile directories
- Monitor abnormal outbound HTTP/S connections to unknown IPs/domains
- Flag DNS lookups to newly registered or unclassified domains

### 6. Improve Behavioral Detection & Threat Hunting

Implement detection use cases for:
- Scheduled task creation outside admin channels
- AV exclusion modifications
- Registry Run key persistence
- Unusual `explorer.exe`-initiated file access
- High-volume PowerShell execution by non-IT users
- First-time outbound connections to new destinations

### 7. Incident Response Hardening
- Develop playbooks for credential resets, lateral movement containment, and persistence removal
- Conduct routine tabletop exercises simulating this exact intrusion pattern
- Apply continuous threat-hunting cycles instead of reactive investigations


