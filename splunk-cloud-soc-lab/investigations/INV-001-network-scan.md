# Incident Investigation Report: INV-001
## Alert Triggered: Network Service Scanning (T1046)

---

### 1. Alert Summary

| Attribute | Details |
|---|---|
| **Incident ID** | `INV-001` |
| **Detection Rule** | `DET-001: Network Scan Detected — T1046` |
| **SIEM Platform** | Splunk Cloud Platform (`prd-p-o1pgk.splunkcloud.com`) |
| **Severity** | **Medium** |
| **Trigger Timestamp** | 2026-10-04 17:02:00 WAT |
| **Investigating Analyst** | Idris Lawan Mustapha |

---

### 2. Validation & Triage

- **Assessment:** **True Positive — Malicious Reconnaissance.**
- **Rationale:** A single remote host (`192.168.238.128`) initiated full-spectrum port probing against the Windows 10 victim workstation (`192.168.238.129`).
- **Telemetry Source:** `Microsoft-Windows-Sysmon/Operational` (Event ID 3 - Network Connection).

---

### 3. Forensic Scope & Analysis

1. **Attacker Reconnaissance Behavior:**
   - Source IP: `192.168.238.128` (Parrot OS VM `parrot-htb`)
   - Target Host: `DESKTOP-F95RRHE` (`192.168.238.129`)
   - Command Identified on Attacker Terminal:
     ```bash
     sudo nmap -sV -O -p- 192.168.238.129
     ```
   - Target Ports Probed: Full TCP spectrum (65,535 ports). Open ports detected by attacker: `5040/tcp`, `5357/tcp` (Microsoft HTTPAPI httpd 2.0 SSDP/UPnP), `7680/tcp` (pando-pub).
   - Attack Duration: Approximately 511.07 seconds (~8.5 minutes).

2. **Splunk SPL Forensic Query:**
   ```spl
   index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "<EventID>3</EventID>"
   | rex field=_raw "<Data Name='SourceIp'>(?<src_ip>[^<]+)</Data>"
   | rex field=_raw "<Data Name='DestinationPort'>(?<dest_port>[^<]+)</Data>"
   | stats dc(dest_port) as unique_ports count by src_ip
   | where unique_ports > 1
   ```

---

### 4. Indicators of Compromise (IOCs)

- **Source IP (Attacker):** `192.168.238.128`
- **Destination IP (Victim):** `192.168.238.129`
- **Tool Fingerprint:** Nmap 7.95 (SYN Stealth Scan + OS Detection probe)

---

### 5. Containment & Remediation Actions

1. Apply immediate host-level firewall block on `192.168.238.128`:
   ```powershell
   New-NetFirewallRule -DisplayName "Block Attacker 192.168.238.128" -Direction Inbound -RemoteAddress 192.168.238.128 -Action Block
   ```
2. Escalate monitoring scope on `DESKTOP-F95RRHE` to monitor subsequent weaponization or exploitation phases.
