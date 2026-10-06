# Incident Investigation Report: INV-003
## Alert Triggered: Ransomware Pre-Staging & Recovery Inhibition (T1490)

---

### 1. Alert Summary

| Attribute | Details |
|---|---|
| **Incident ID** | `INV-003` |
| **Detection Rule** | `CRITICAL — Ransomware Staging — T1490` |
| **SIEM Platform** | Splunk Cloud Platform (`prd-p-o1pgk.splunkcloud.com`) |
| **Severity** | **CRITICAL** |
| **Trigger Timestamp** | 2026-10-05 17:15:13 UTC |
| **Investigating Analyst** | Idris Lawan Mustapha |

---

### 2. Validation & Triage

- **Assessment:** **True Positive — Imminent Ransomware Encryption Staging.**
- **Rationale:** High-impact native administrative binaries (`vssadmin.exe`, `wbadmin.exe`, `bcdedit.exe`) were executed sequentially to dismantle Windows snapshot and recovery systems.
- **Telemetry Sources:**
  - Sysmon Event ID 1 (Process Creation)
  - Security Event ID 4688 (Process Tracking)

---

### 3. Forensic Scope & Analysis

1. **Destructive Command Sequence:**
   - Host: `DESKTOP-F95RRHE`
   - User: `DESKTOP-F95RRHE\FIKIRA` (and `NT AUTHORITY\SYSTEM`)
   - Execution 1 (`2026-10-05 16:00:41.830 UTC`):
     `"C:\Windows\system32\vssadmin.exe" delete shadows /all /quiet`
   - Execution 2 (`2026-10-05 16:01:40.650 UTC`):
     `vssadmin delete shadows /all /quiet`
   - Purpose: Permanent destruction of Volume Shadow Copies to prevent restore points from recovering encrypted files.

2. **Detection Evaluation & Splunk Alerting:**
   - Default Splunk view without custom detection rule lacked severity escalation and threat context.
   - Engineered Rule fired in Splunk Cloud Activity Console at **2026-10-05 17:15:13 UTC** with **Critical** severity rating.

3. **Splunk SPL Forensic Query:**
   ```spl
   index=main EventCode=1 CommandLine="*vssadmin*"
   | table _time, host, User, CommandLine
   ```

---

### 4. Indicators of Compromise (IOCs)

- **Target Host:** `DESKTOP-F95RRHE`
- **Execution String 1:** `vssadmin delete shadows /all /quiet`
- **Execution String 2:** `"C:\Windows\system32\vssadmin.exe" delete shadows /all /quiet`
- **Associated Staging Commands:**
  - `wbadmin delete catalog -quiet`
  - `bcdedit /set {default} recoveryenabled No`
- **Simulated Ransom Artifacts:**
  - `C:\Users\Public\Desktop\README_DECRYPT.txt`
  - `C:\Users\Public\Desktop\FINANCIAL_2026.xlsx.enc`

---

### 5. Containment & Remediation Actions

1. **Emergency Isolation:** Immediately isolate `DESKTOP-F95RRHE` from the network segment to halt lateral movement or widespread encryption.
2. **Process Termination:** Kill any parent C2 shells (`cmd.exe`, `powershell.exe`, or Meterpreter processes).
3. **Backup Recovery:** Validate offline/immutable air-gapped backups since local shadow copies were expunged.
4. **Credential Revocation:** Force enterprise-wide password resets for accounts cached on the endpoint.
