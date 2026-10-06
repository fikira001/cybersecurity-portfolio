# Incident Investigation Report: INV-005
## Alert Triggered: PowerShell Abuse & Antivirus Defense Impairment (T1059.001 / T1562.001)

---

### 1. Alert Summary

| Attribute | Details |
|---|---|
| **Incident ID** | `INV-005` |
| **Detection Rule** | `DET-005: Host Defense Tampering via PowerShell — T1562.001` |
| **Correlated Rule** | `DET-003: Suspicious PowerShell Execution Flags — T1059.001` |
| **SIEM Platform** | Splunk Cloud Platform (`prd-p-o1pgk.splunkcloud.com`) |
| **Severity** | **High** |
| **Trigger Timestamp** | 2026-10-04 17:04:10 UTC / 2026-10-05 15:57:00 UTC |
| **Investigating Analyst** | Idris Lawan Mustapha |

---

### 2. Validation & Triage

- **Assessment:** **True Positive — Deliberate Defensive Neutralization.**
- **Rationale:** Execution of administrative PowerShell cmdlets designed to disable Windows Defender Real-Time Monitoring and Script Scanning.
- **Telemetry Sources:**
  - Sysmon Event ID 1 (Process Creation)
  - Windows Event Log Channel `Microsoft-Windows-Sysmon/Operational`

---

### 3. Forensic Scope & Analysis

1. **Observed Execution String:**
   - Host: `DESKTOP-F95RRHE`
   - User: `DESKTOP-F95RRHE\FIKIRA`
   - Parent Process: `C:\Windows\System32\cmd.exe`
   - Executable: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
   - Full Command:
     ```powershell
     powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"
     ```

2. **Splunk SPL Query:**
   ```spl
   index=main EventCode=1 CommandLine="*Set-MpPreference*"
   (CommandLine="*Disable*" OR CommandLine="*false*")
   | table _time, host, User, CommandLine
   ```

---

### 4. Indicators of Compromise (IOCs)

- **Tampered Service:** Windows Defender Antivirus
- **Disabled Preferences:** `DisableRealtimeMonitoring = $true`
- **Parent Process:** `cmd.exe` executing within interactive or spawned shell

---

### 5. Containment & Remediation Actions

1. Re-enable Windows Defender Real-Time Monitoring immediately:
   ```powershell
   Set-MpPreference -DisableRealtimeMonitoring $false
   ```
2. Enable Tamper Protection via Microsoft Defender portal to prevent non-interactive script manipulation.
3. Configure PowerShell Script Block Logging (Event ID 4104) and Transcription for granular script visibility.
