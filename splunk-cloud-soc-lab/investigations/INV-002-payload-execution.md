# Incident Investigation Report: INV-002
## Alert Triggered: Malicious Payload Execution & C2 Establishment (T1204.002 / T1571)

---

### 1. Alert Summary

| Attribute | Details |
|---|---|
| **Incident ID** | `INV-002` |
| **Detection Rule** | `DET-002: Payload from Suspicious Location — T1204.002` |
| **SIEM Platform** | Splunk Cloud Platform (`prd-p-o1pgk.splunkcloud.com`) |
| **Severity** | **High** |
| **Trigger Timestamp** | 2026-10-04 16:50:02 UTC |
| **Investigating Analyst** | Idris Lawan Mustapha |

---

### 2. Validation & Triage

- **Assessment:** **True Positive — Active Compromise & C2 Establishment.**
- **Rationale:** An unsigned executable (`payload.exe`) was written to and launched from `C:\Users\Public\`, followed immediately by an outbound TCP session to an external non-standard port (`4444`).
- **Telemetry Sources:** 
  - Sysmon Event ID 1 (Process Creation)
  - Sysmon Event ID 3 (Network Connection)

---

### 3. Forensic Scope & Analysis

1. **Payload Staging & Execution:**
   - Host: `DESKTOP-F95RRHE`
   - User: `DESKTOP-F95RRHE\FIKIRA`
   - Dropped Binary: `C:\Users\Public\payload.exe`
   - Ingress Delivery Vector: Downloaded via PowerShell `Invoke-WebRequest` from `http://192.168.238.128:8080/payload.exe`
   - Execution Command: `"C:\Users\Public\payload.exe"`
   - Execution Time: `2026-10-04 16:50:02.726 UTC`

2. **Command & Control (C2) Sockets:**
   - Connection Established: `192.168.238.129:51329` $\rightarrow$ `192.168.238.128:4444`
   - Protocol: Meterpreter reverse TCP (`windows/x64/meterpreter/reverse_tcp`)
   - Stage Transmission: 248,902 bytes delivered in-memory
   - Session State: Meterpreter Session 1 opened at `2026-10-04 17:50:05 +0100`

3. **Splunk SPL Forensic Query:**
   ```spl
   index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "<EventID>1</EventID>"
   | rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
   | rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
   | rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
   | rex field=_raw "<Data Name='User'>(?<User>[^<]+)</Data>"
   | search (Image="*\\Users\\Public\\*" OR Image="*\\Temp\\*" OR Image="*\\AppData\\Local\\Temp\\*") NOT Image="*\\Windows\\*"
   | table _time, host, User, Image, CommandLine, ParentImage
   ```

---

### 4. Indicators of Compromise (IOCs)

- **Malicious Binary:** `payload.exe` (SHA256 recorded in Sysmon Event ID 1)
- **File Location:** `C:\Users\Public\payload.exe`
- **File Size:** ~7,680 bytes
- **C2 IP Address:** `192.168.238.128`
- **C2 Port:** `4444/TCP`
- **Delivery HTTP Server:** `192.168.238.128:8080`

---

### 5. Containment & Remediation Actions

1. Terminate running process PID associated with `C:\Users\Public\payload.exe`.
2. Quarantine and delete `C:\Users\Public\payload.exe`.
3. Sever active network connection socket to `192.168.238.128:4444`.
4. Restrict execution permissions for non-administrative users on world-writable folders via AppLocker / Software Restriction Policies.
