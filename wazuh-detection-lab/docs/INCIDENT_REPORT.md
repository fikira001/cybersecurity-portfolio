# INCIDENT REPORT
## Enterprise SOC Detection Lab — Ransomware Simulation & Detection Engineering

**Reference:** IR-2026-001 | **Classification:** LAB / SIMULATED | **Severity:** CRITICAL

---

### Incident Metadata

| Field | Details |
| :--- | :--- |
| **Incident Reference** | IR-2026-001 |
| **Date** | July 26, 2026 |
| **Analyst** | Idris Lawan Mustapha |
| **Classification** | LAB SIMULATION — Not a live incident |
| **Severity** | **CRITICAL** |
| **Affected Host** | DESKTOP-GFKOI38 (Windows 10 21H1, Build 19043.928) |
| **Victim IP** | `192.168.184.166` |
| **Victim MAC** | `00:0C:29:66:5D:2A` |
| **Attacker IP** | `192.168.184.129` (Kali Linux) |
| **Environment** | Isolated VMware Workstation Lab Network |
| **SIEM Platform** | Wazuh SIEM/XDR v4.14.5 |
| **Endpoint Telemetry** | Microsoft Sysmon v15.21 (SwiftOnSecurity config) |

---

### 1. Executive Summary

This report documents a simulated ransomware attack executed against an isolated Windows 10 endpoint in a controlled VMware lab environment. The objective was twofold: to replicate the tactics, techniques, and procedures (TTPs) used by modern ransomware operators, and to evaluate the detection capability of the Wazuh SIEM platform against these techniques.

The attack chain spanned seven distinct MITRE ATT&CK techniques — from initial reconnaissance through ransomware staging. Wazuh's default detection rules successfully logged process creation events throughout the attack, but critically failed to classify the most dangerous ransomware-staging techniques at appropriate severity levels. The `vssadmin` shadow copy deletion command — a technique used universally by ransomware strains including LockBit, BlackCat, and WannaCry — was classified as a low-level generic event, meaning it would be invisible to a standard SOC analyst monitoring a live dashboard.

Following this gap analysis, three custom XML detection rules were engineered and deployed to the Wazuh Manager. Upon re-execution of the attack chain, all three rules fired immediately — escalating the critical ransomware-staging techniques to Level 12 Critical alerts with MITRE ATT&CK T1490 mapping. This demonstrates the core value of Detection Engineering as a discipline distinct from, and complementary to, standard SOC analysis.

---

### 2. Lab Architecture

The lab consists of three virtual machines operating within an isolated VMware host-only network segment. No external internet traffic is permitted from the victim or attacker nodes during simulation.

| Role | OS | IP Address | Key Tool | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **Attacker** | Kali Linux 2026.1 | `192.168.184.129` | Metasploit v6.4, Nmap 7.99 | Simulate threat actor |
| **Victim** | Windows 10 21H1 | `192.168.184.166` | Sysmon v15.21, Wazuh Agent v4.14.5 | Endpoint under attack |
| **SIEM Server** | Wazuh OVA (Ubuntu) | `192.168.184.130` | Wazuh v4.14.5 | Collect, analyse, alert |

---

### 3. Attack Timeline (Verified Evidence Timestamps)

| Time (EDT/UTC) | Event Description | Tool / Command | MITRE ID |
| :--- | :--- | :--- | :--- |
| **03:54:00 EDT** | Nmap reconnaissance scan launched from Kali against victim endpoint. Open ports identified: 135 (RPC), 139 (NetBIOS), 445 (SMB), 5357 (HTTP). | `nmap -sV -O -p- ...` | `T1595` |
| **04:07:00 EDT** | Msfvenom payload (`windows/x64/meterpreter/reverse_tcp`, 7680 bytes) generated on Kali. Payload hosted via Python HTTP server on port 8080. | `msfvenom` / `python3 -m http.server` | `T1204.002` |
| **04:37:00 EDT** | Multi/handler listener started on Kali (port 4444). | `msfconsole` | `T1571` |
| **04:47:59 EDT** | Meterpreter reverse TCP session 1 opened from `192.168.184.166:60820` to `192.168.184.129:4444`. | `payload.exe` execution | `T1571` |
| **04:50:00 EDT** | Privilege escalation executed via `getsystem` (Named Pipe Impersonation technique). User elevated from `DESKTOP-GFKOI38\win10` to `NT AUTHORITY\SYSTEM`. | `getsystem` | `T1134` |
| **04:50:30 EDT** | Credential dumping via `hashdump`. NTLM hashes extracted for Administrator, DefaultAccount, Guest, WDAGUtilityAccount, and win10 accounts. | `hashdump` | `T1003` |
| **05:00:00 EDT** | Shadow copy deletion executed: `vssadmin delete shadows /all /quiet`. All volume shadow copies destroyed. | `vssadmin` | `T1490` |
| **05:00:15 EDT** | Backup catalog deleted: `wbadmin delete catalog -quiet`. Windows backup catalog successfully deleted. | `wbadmin` | `T1490` |
| **05:00:30 EDT** | Boot recovery disabled attempt: `bcdedit /set {default} recoveryenabled No`. | `bcdedit` | `T1490` |
| **05:01:00 EDT** | Simulated ransomware payload dropped: `README_DECRYPT.txt` and `FINANCIAL_2026.xlsx.enc` created on victim desktop. | Shell file write | `T1486` |
| **09:04:00 EDT** | Defender disabled via `Set-MpPreference -DisableRealtimeMonitoring $true`. | PowerShell | `T1562.001` |
| **09:10:00 EDT** | Web payload download to endpoint at `C:\Users\Public\payload.exe`. | `Invoke-WebRequest` | `T1105` |
| **10:14:00 EDT** | SIEM Detection Gap analysis performed in Wazuh Discover — default rules failed to trigger alerts for `vssadmin`. | Wazuh Discover | Gap Analysis |
| **13:05:59 UTC** | Custom Rule `100001` fired at Level 12 Critical upon re-execution, mapping MITRE T1490. | Wazuh Alert Engine | `T1490` |

---

### 4. MITRE ATT&CK Technique Mapping

| ID | Tactic | Technique | Tool Used |
| :--- | :--- | :--- | :--- |
| **T1595** | Reconnaissance | Active Scanning | Nmap 7.99 |
| **T1204.002** | Execution | User Execution: Malicious File | Msfvenom |
| **T1571** | Command & Control | Non-Standard Port | Metasploit multi/handler |
| **T1134** | Privilege Escalation | Access Token Manipulation | getsystem (Meterpreter) |
| **T1003** | Credential Access | OS Credential Dumping | hashdump (Meterpreter) |
| **T1562.001** | Defense Evasion | Impair Defenses: Disable Tools | Set-MpPreference (PowerShell) |
| **T1490** | Impact | Inhibit System Recovery | vssadmin, wbadmin, bcdedit |
| **T1486** | Impact | Data Encrypted for Impact | Simulated payload |

---

### 5. Indicators of Compromise (IOCs)

#### Network IOCs
- **Attacker IP:** `192.168.184.129`
- **C2 Protocol:** Reverse TCP
- **C2 Port:** `4444/TCP`
- **Payload Delivery Port:** `8080/TCP` (Python HTTP server)

#### Host IOCs
- **Malicious File:** `payload.exe` — Meterpreter reverse shell
- **File Path:** `C:\Users\Public\payload.exe`
- **File Size:** 7,680 bytes
- **Affected Host:** `DESKTOP-GFKOI38`
- **Victim MAC:** `00:0C:29:66:5D:2A`
- **Ransom Note:** `C:\Users\Public\Desktop\README_DECRYPT.txt`
- **Encrypted File:** `C:\Users\Public\Desktop\FINANCIAL_2026.xlsx.enc`

#### Process IOCs
- `vssadmin.exe` with argument: `delete shadows /all /quiet`
- `wbadmin.exe` with argument: `delete catalog -quiet`
- `bcdedit.exe` with argument: `/set {default} recoveryenabled No`
- `powershell.exe` with argument: `Set-MpPreference -DisableRealtimeMonitoring $true`

---

### 6. Detection Gap Analysis & Engineering

Default Wazuh rules failed to raise alerts above level 3 for `vssadmin delete shadows`. Custom rules (100001-100003) were created to target Sysmon Event ID 1 telemetry and generate Level 12 Critical alerts mapped directly to MITRE T1490.

---

### 7. Recommendations

1. **Immediate:** Deploy custom T1490 rules across all production endpoints.
2. **Short-Term:** Implement AppLocker/WDAC application whitelisting and restrict `vssadmin.exe` execution.
3. **Long-Term:** Conduct regular purple team exercises and automate endpoint isolation via Wazuh Active Response.

---

**Analyst:** Idris Lawan Mustapha | **GitHub:** `github.com/fikira001/cybersecurity-portfolio` | **Reference:** IR-2026-001
