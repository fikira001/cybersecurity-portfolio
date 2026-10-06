# Incident Investigation Report: INV-004
## Alert Triggered: Privilege Escalation & SAM Database Credential Theft (T1134 / T1003)

---

### 1. Alert Summary

| Attribute | Details |
|---|---|
| **Incident ID** | `INV-004` |
| **Detection Rule** | `DET-004: Suspicious LSASS Process Access — T1003` |
| **Correlated Events** | Event 4672 (Special Privileges Assigned) & Event 4624 (Logon Type 5) |
| **SIEM Platform** | Splunk Cloud Platform (`prd-p-o1pgk.splunkcloud.com`) |
| **Severity** | **High** |
| **Trigger Timestamp** | 2026-10-04 18:12:00 WAT |
| **Investigating Analyst** | Idris Lawan Mustapha |

---

### 2. Validation & Triage

- **Assessment:** **True Positive — In-Memory Privilege Escalation & Credential Harvesting.**
- **Rationale:** Following payload execution, the session escalated from local user `FIKIRA` to `NT AUTHORITY\SYSTEM` using Named Pipe Impersonation (`getsystem`), subsequently accessing LSASS memory to extract local SAM account password hashes.
- **Telemetry Sources:**
  - Sysmon Event ID 10 (ProcessAccess)
  - Security Event ID 4672 (Special privileges assigned to new logon)
  - Security Event ID 4624 (Successful logon)

---

### 3. Forensic Scope & Analysis

1. **In-Memory Privilege Escalation:**
   - Host: `DESKTOP-F95RRHE`
   - Initial Context: `DESKTOP-F95RRHE\FIKIRA`
   - Elevated Context: `NT AUTHORITY\SYSTEM`
   - Mechanism: Meterpreter `getsystem` via Technique 1 (`Named Pipe Impersonation (In Memory/Admin)`).

2. **Credential Extraction:**
   - Tool: Meterpreter `hashdump` extension
   - Compromised Accounts Dumped from SAM:
     - `Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::`
     - `DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::`
     - `FIKIRA:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::`
     - `Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::`
     - `WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:0947a61b28f5af22aba04f74e9bfbf6f:::`

3. **Splunk SPL Correlation Query:**
   ```spl
   index=main (EventCode=4624 OR EventCode=4672)
   | table _time, host, EventCode, Account_Name, Security_ID, Logon_Type, PrivilegeList
   | sort -_time
   | head 30
   ```

---

### 4. Indicators of Compromise (IOCs)

- **Target Image Monitored:** `C:\Windows\System32\lsass.exe`
- **Privilege Token:** `SeDebugPrivilege`, `SeTcbPrivilege` granted to `SYSTEM` (`S-1-5-18`)
- **Compromised Hash Set:** NTLM hashes for local administrator and standard user accounts.

---

### 5. Containment & Remediation Actions

1. Force password reset for all compromised local accounts.
2. Disable local Administrator and Guest accounts where practicable.
3. Enable LSA Protection (`RunAsPPL=1`) in Windows Registry:
   ```cmd
   reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
   ```
4. Deploy Credential Guard on supported Windows 10/11 Enterprise endpoints.
