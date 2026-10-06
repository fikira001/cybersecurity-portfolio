# Alert Rules Configuration & Engineering Specification

This document details the configuration parameters, scheduling mechanics, and trigger thresholds for the scheduled detection alerts deployed in the **Splunk Cloud Platform** (`prd-p-o1pgk.splunkcloud.com`).

---

## 📋 Deployed Alerts Summary

As validated in Splunk Cloud (**Searches, Reports, and Alerts** console):

| # | Alert Title | MITRE ATT&CK | Severity | Schedule / Cron | Trigger Condition | Actions | Status |
|---|---|---|---|---|---|---|---|
| **1** | `CRITICAL — Ransomware Staging — T1490` | `T1490` | **Critical** | Hourly / `0 * * * *` | Number of events > 0 | Add to Triggered Alerts | **Enabled** |
| **2** | `Network Scan Detected — T1046` | `T1046` | **Medium** | Scheduled (`*/5 * * * *`) | Number of events > 0 | Add to Triggered Alerts | **Enabled** |
| **3** | `Payload from Suspicious Location — T1204.002` | `T1204.002` | **High** | Scheduled (`*/5 * * * *`) | Number of events > 0 | Add to Triggered Alerts | **Enabled** |
| **4** | `Suspicious LSASS Access — T1003` | `T1003.001` | **High** | Scheduled (`*/5 * * * *`) | Number of events > 0 | Add to Triggered Alerts | **Enabled** |
| **5** | `Suspicious PowerShell Execution — T1059.001` | `T1059.001` | **High** | Scheduled (`*/5 * * * *`) | Number of events > 0 | Add to Triggered Alerts | **Enabled** |

---

## ⚙️ Detailed Alert Specifications

### 1. CRITICAL — Ransomware Staging — T1490
- **Detection Logic:** Flags deletion of Volume Shadow Copies (`vssadmin delete shadows`), backup catalog purge (`wbadmin delete catalog`), or disabling boot recovery (`bcdedit recoveryenabled No`).
- **Search Query:**
  ```spl
  index=main EventCode=1 (CommandLine="*vssadmin*delete*shadows*" OR CommandLine="*wbadmin*delete*catalog*" OR CommandLine="*bcdedit*recoveryenabled*No*")
  ```
- **Alert Type:** Scheduled
- **Cron / Schedule:** `0 * * * *` (or `* * * * *` for real-time SOC escalation)
- **Trigger Condition:** Number of events > 0
- **Severity Level:** **Critical** (Red)
- **Trigger Action:** Add to Triggered Alerts, trigger incident triage workflow.

### 2. Network Scan Detected — T1046
- **Detection Logic:** Evaluates Sysmon Event ID 3 network telemetry for anomalous port fan-out behavior from a single remote IP address.
- **Search Query:**
  ```spl
  index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "<EventID>3</EventID>"
  | rex field=_raw "<Data Name='SourceIp'>(?<src_ip>[^<]+)</Data>"
  | rex field=_raw "<Data Name='DestinationPort'>(?<dest_port>[^<]+)</Data>"
  | stats dc(dest_port) as unique_ports count by src_ip
  | where unique_ports > 1
  ```
- **Alert Type:** Scheduled (every 5 minutes)
- **Trigger Condition:** Number of events > 0
- **Severity Level:** **Medium** (Yellow)
- **Trigger Action:** Add to Triggered Alerts.

### 3. Payload from Suspicious Location — T1204.002
- **Detection Logic:** Captures process execution originating from `C:\Users\Public`, `\Temp\`, or `\AppData\Local\Temp\` directories, excluding legitimate Windows binaries.
- **Search Query:**
  ```spl
  index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "<EventID>1</EventID>"
  | rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
  | rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
  | rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
  | rex field=_raw "<Data Name='User'>(?<User>[^<]+)</Data>"
  | search (Image="*\\Users\\Public\\*" OR Image="*\\Temp\\*" OR Image="*\\AppData\\Local\\Temp\\*") NOT Image="*\\Windows\\*"
  | table _time, host, User, Image, CommandLine, ParentImage
  ```
- **Alert Type:** Scheduled (every 5 minutes)
- **Trigger Condition:** Number of events > 0
- **Severity Level:** **High** (Orange)
- **Trigger Action:** Add to Triggered Alerts.

### 4. Suspicious LSASS Access — T1003
- **Detection Logic:** Identifies non-whitelisted processes requesting read/query memory handles against `lsass.exe` (indicative of Mimikatz or Meterpreter `hashdump`).
- **Search Query:**
  ```spl
  index=main EventCode=10 TargetImage="*lsass.exe*"
  | table _time, host, SourceImage, TargetImage, GrantedAccess, CallTrace
  ```
- **Alert Type:** Scheduled (every 5 minutes)
- **Trigger Condition:** Number of events > 0
- **Severity Level:** **High** (Orange)
- **Trigger Action:** Add to Triggered Alerts.

### 5. Suspicious PowerShell Execution — T1059.001
- **Detection Logic:** Detects command-line flags intended to bypass policy restrictions, hide windows, encode payloads, or disable security sensors.
- **Search Query:**
  ```spl
  index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "<EventID>1</EventID>"
  | rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
  | rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
  | rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
  | rex field=_raw "<Data Name='User'>(?<User>[^<]+)</Data>"
  | search Image="*powershell.exe*" (CommandLine="*-enc*" OR CommandLine="*bypass*" OR CommandLine="*hidden*" OR CommandLine="*DisableRealtimeMonitoring*" OR CommandLine="*-nop*")
  | table _time, host, User, CommandLine, ParentImage
  ```
- **Alert Type:** Scheduled (every 5 minutes)
- **Trigger Condition:** Number of events > 0
- **Severity Level:** **High** (Orange)
- **Trigger Action:** Add to Triggered Alerts.

---

## 🎯 Verification & Evidence

### Active Alerts Inventory
![All Alerts Configured in Splunk Cloud](../assets/screenshots/16-all-alerts-configured.png)
*Figure: Splunk Cloud Alert Management interface displaying all 5 enabled detection rules under the `sc_admin` owner.*

### Triggered Incident Console
![Triggered Alerts in Splunk Cloud](../assets/screenshots/17-alerts-triggered.png)
*Figure: Splunk Cloud Activity → Triggered Alerts showing live alert firings for `CRITICAL — Ransomware Staging — T1490` and `Payload from Suspicious Location — T1204.002`.*
