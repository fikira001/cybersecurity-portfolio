# INCIDENT REPORT
## Enterprise SOC Detection Lab — Ransomware Attack Chain Simulation & Splunk Cloud Detection Engineering

**Reference:** IR-SPLUNK-2026-001 | **Classification:** LAB SIMULATION | **Severity:** CRITICAL

---

### Incident Metadata

| Field | Details |
| :--- | :--- |
| **Incident Reference** | IR-SPLUNK-2026-001 |
| **Date** | October 5, 2026 |
| **Analyst** | Idris Lawan Mustapha |
| **Classification** | LAB SIMULATION — Threat Emulation & Detection Engineering |
| **Severity Rating** | **CRITICAL** |
| **Affected Host** | `DESKTOP-F95RRHE` (Windows 10 x64, VMware Workstation) |
| **Victim IP** | `192.168.238.129` |
| **Victim MAC** | `00:0C:29:B8:EF:28` |
| **Attacker Host & IP** | `parrot-htb` / `192.168.238.128` (Parrot OS Linux) |
| **SIEM Platform** | Splunk Cloud Platform (`prd-p-o1pgk.splunkcloud.com`) |
| **Forwarder Agent** | Splunk Universal Forwarder v10.4.3 (x64) via mTLS |
| **Endpoint Telemetry** | Microsoft Sysmon v15.21 (SwiftOnSecurity Schema) |

---

### 1. Executive Summary

This formal incident report documents an end-to-end simulated cyberattack and corresponding detection engineering response conducted against an isolated Windows 10 enterprise workstation within a VMware virtual environment. The engagement emulated the tactics, techniques, and procedures (TTPs) of modern ransomware syndicates (e.g., LockBit, BlackCat, Akira), culminating in pre-encryption recovery inhibition and credential theft.

Telemetry was streamed in real-time from kernel-level Microsoft Sysmon and Windows Event Log channels into the **Splunk Cloud Platform** (`prd-p-o1pgk.splunkcloud.com`) utilizing the authenticated Splunk Universal Forwarder with private CA TLS credentials.

While default SIEM search configurations ingested raw system activity, they suffered from significant context gaps—failing to prioritize critical ransomware staging operations such as volume shadow copy destruction (`vssadmin delete shadows`). To eliminate this blind spot, five custom high-fidelity SPL detections were engineered, scheduled, and validated in Splunk Cloud. The custom rules successfully escalated malicious behavior to **High** and **Critical** alerts, validating the defensive posture and automated alerting pipeline.

---

### 2. Lab Architecture & Infrastructure

The simulated operating theater comprised two virtual machines in an isolated VMware virtual network segment paired with an enterprise cloud SIEM tenant:

| Role | Hostname / OS | IP Address | Primary Security / Attack Tools | Function |
| :--- | :--- | :--- | :--- | :--- |
| **Attacker Node** | `parrot-htb` (Parrot OS 2026) | `192.168.238.128` | Metasploit v6.4.136, Nmap 7.95, Python HTTP | Threat actor emulation |
| **Victim Endpoint** | `DESKTOP-F95RRHE` (Win 10 x64) | `192.168.238.129` | Sysmon v15.21, Splunk UF v10.4.3 | Target enterprise node |
| **SIEM Platform** | Splunk Cloud Platform | `prd-p-o1pgk.splunkcloud.com` | Search & Reporting, Alert Manager, Dashboards | Central log aggregation & alerting |

---

### 3. Attack Timeline & Chronology (Verified Evidence)

| Timestamp | Phase / Event Description | Command / Execution Syntax | MITRE ATT&CK | Source Telemetry |
| :--- | :--- | :--- | :--- | :--- |
| **2026-10-04 14:55:20 UTC** | Sysmon kernel minifilter driver installed and baseline verified | `sysmon64.exe -i sysmonconfig-export.xml` | Baseline | Sysmon Event ID 16 |
| **2026-10-04 15:27:16 UTC** | Splunk Universal Forwarder established TLS mTLS connection | `splunkd.exe` $\rightarrow$ `prd-p-o1pgk.splunkcloud.com:9997` | Ingestion | Splunk UF Log |
| **2026-10-04 16:50:02 UTC** | Malicious binary staged in world-writable directory and executed | `C:\Users\Public\payload.exe` | `T1204.002` | Sysmon Event ID 1 |
| **2026-10-04 17:02:00 WAT** | Network service scanning and OS fingerprinting initiated | `sudo nmap -sV -O -p- 192.168.238.129` | `T1046` | Parrot Terminal |
| **2026-10-04 17:03:46 UTC** | Local account enumeration via policy bypass flag | `powershell -ExecutionPolicy Bypass -Command "Get-LocalUser"` | `T1059.001` | Sysmon Event ID 1 |
| **2026-10-04 17:04:10 UTC** | Endpoint defenses impaired via administrative PowerShell | `powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"` | `T1562.001` | Sysmon Event ID 1 |
| **2026-10-04 17:50:05 WAT** | Meterpreter reverse TCP Command & Control (C2) session established | Reverse TCP socket: `192.168.238.129:51329` $\rightarrow$ `192.168.238.128:4444` | `T1571` | Metasploit Console |
| **2026-10-04 18:12:00 WAT** | Privilege escalation to SYSTEM via Named Pipe Impersonation | `getsystem` (Technique 1) | `T1134` | Meterpreter Session |
| **2026-10-04 18:12:30 WAT** | Local SAM database credential extraction | `hashdump` (Extracted NTLM hashes for Administrator, FIKIRA, etc.) | `T1003` | Meterpreter Session |
| **2026-10-05 16:00:41 UTC** | Destruction of Volume Shadow Copies (Recovery Inhibition) | `"C:\Windows\system32\vssadmin.exe" delete shadows /all /quiet` | `T1490` | Sysmon Event ID 1 |
| **2026-10-05 16:01:40 UTC** | Repeated shadow copy deletion attempt | `vssadmin delete shadows /all /quiet` | `T1490` | Sysmon Event ID 1 |
| **2026-10-05 16:38:18 UTC** | Scheduled detection alert rules configured in Splunk Cloud | Deployed 5 scheduled alerts with automated trigger actions | Engineering | Splunk Console |
| **2026-10-05 17:04:59 UTC** | High-severity alert triggered for suspicious location execution | Rule: `Payload from Suspicious Location — T1204.002` | `T1204.002` | Splunk Activity |
| **2026-10-05 17:15:13 UTC** | Critical-severity alert triggered for ransomware staging | Rule: `CRITICAL — Ransomware Staging — T1490` | `T1490` | Splunk Activity |

---

### 4. MITRE ATT&CK Mapping Matrix

| MITRE Technique | Tactic | Description | Emulated Attack Action | Detection Rule |
| :--- | :--- | :--- | :--- | :--- |
| **T1046** | Reconnaissance | Network Service Scanning | Full-port TCP sweep via Nmap (`-sV -O -p-`) | `DET-001` |
| **T1204.002** | Execution | User Execution: Malicious File | Execution of binary dropped in `C:\Users\Public` | `DET-002` |
| **T1059.001** | Execution | Command and Scripting Interpreter: PowerShell | PowerShell execution with `-ExecutionPolicy Bypass` | `DET-003` |
| **T1571** | Command & Control | Non-Standard Port | Reverse TCP connection to attacker port `4444/TCP` | Sysmon Event ID 3 |
| **T1134** | Privilege Escalation | Access Token Manipulation | Meterpreter `getsystem` named pipe impersonation | WinEventLog 4672 |
| **T1003** | Credential Access | OS Credential Dumping | Dumping NTLM password hashes from SAM/LSASS | `DET-004` |
| **T1562.001** | Defense Evasion | Impair Defenses: Disable Tools | PowerShell disabling Defender real-time monitoring | `DET-005` |
| **T1490** | Impact | Inhibit System Recovery | Deleting shadow copies with `vssadmin delete shadows` | `DET-006` |

---

### 5. Indicators of Compromise (IOCs)

#### Network IOCs
- **Attacker IP Address:** `192.168.238.128`
- **Victim IP Address:** `192.168.238.129`
- **Victim Hardware MAC:** `00:0C:29:B8:EF:28`
- **C2 Sockets:** `192.168.238.129:51329` $\rightarrow$ `192.168.238.128:4444` (TCP)
- **Ingress HTTP Tool Transfer:** `http://192.168.238.128:8080/payload.exe`

#### Host IOCs
- **Malicious Executable:** `payload.exe` (7,680 bytes)
- **Staging Directory:** `C:\Users\Public\payload.exe`
- **Target Hostname:** `DESKTOP-F95RRHE`
- **Target User Account:** `DESKTOP-F95RRHE\FIKIRA`
- **Simulated Ransom Artifacts:**
  - `C:\Users\Public\Desktop\README_DECRYPT.txt`
  - `C:\Users\Public\Desktop\FINANCIAL_2026.xlsx.enc`

#### Process Execution Signatures
- `powershell -ExecutionPolicy Bypass -Command "Get-LocalUser"`
- `powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"`
- `vssadmin delete shadows /all /quiet`
- `"C:\Windows\system32\vssadmin.exe" delete shadows /all /quiet`
- `wbadmin delete catalog -quiet`
- `bcdedit /set {default} recoveryenabled No`

---

### 6. Detection Gap Analysis

During baseline threat hunting, a critical operational gap in default SIEM workflows was identified:
- Querying default indexes for `vssadmin` displayed raw command executions, but failed to categorize the event as a security incident or escalate severity.
- In a production SOC receiving thousands of daily events, raw process launches without threat mapping are overlooked by tier-1 analysts.
- **Resolution:** By developing custom SPL rules incorporating PCRE regular expressions on Sysmon telemetry and scheduling persistent alerts, the SOC achieves near-instantaneous notification of ransomware staging attempts.

---

### 7. Strategic Recommendations & Containment

1. **Immediate Host Containment:** Isolate `DESKTOP-F95RRHE` from the network segment to halt active Meterpreter C2 traffic.
2. **Execution Hardening:** Enforce AppLocker / Windows Defender Application Control (WDAC) policies blocking executable execution from `C:\Users\Public` and user `%TEMP%` directories.
3. **Privilege & Policy Enforcement:** Lock down `vssadmin.exe` execution permissions so non-administrative users cannot query or manipulate snapshots.
4. **Tamper Protection:** Enable Windows Defender Tamper Protection via Group Policy or Intune to prevent local administrative scripts from toggling real-time monitoring off.
5. **Credential Rotation:** Immediately revoke and rotate passwords for all accounts present in the SAM database dump (`Administrator`, `FIKIRA`, etc.).

---

**Reporting Analyst:** Idris Lawan Mustapha  
**Role:** Cybersecurity Analyst & Detection Engineer  
**Reference Document:** IR-SPLUNK-2026-001 | Splunk Cloud SOC Lab
