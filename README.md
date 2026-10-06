# Cybersecurity Portfolio

[![Security Operations](https://img.shields.io/badge/Domain-SOC%20%7C%20Detection%20Engineering%20%7C%20Blue%20Team-blue)](#)
[![SIEM Platforms](https://img.shields.io/badge/SIEM-Splunk%20Cloud%20%7C%20Wazuh%20XDR-orange)](#)
[![Telemetry](https://img.shields.io/badge/Telemetry-Microsoft%20Sysmon%20v15-brightgreen)](#)
[![Framework](https://img.shields.io/badge/Standards-MITRE%20ATT%26CK%20%7C%20NIST%20CSF-red)](#)
[![Author](https://img.shields.io/badge/Author-Idris%20Lawan%20Mustapha-purple)](#author)

A professional collection of hands-on cybersecurity projects, threat emulation labs, and technical detection engineering documentation demonstrating real-world experience across Security Operations (SOC), Threat Hunting, Detection Engineering, Incident Response, and Enterprise SIEM architectures (Splunk Cloud & Wazuh XDR).

---

## 📂 Featured Enterprise Projects & Labs

### ☁️ [Enterprise Splunk Cloud SOC & Detection Engineering Lab](./splunk-cloud-soc-lab/)
- **Domain:** Cloud SIEM Engineering, Blue Team Operations, Threat Hunting, SOC Dashboard Architecture
- **Tech Stack:** Splunk Cloud Platform, Splunk Universal Forwarder v10.4.3, Microsoft Sysmon v15.21, Parrot OS (Metasploit v6.4, Nmap 7.95), Windows 10 Enterprise
- **Key Deliverables:** 
  - Ingested encrypted kernel telemetry over mTLS to an enterprise Splunk Cloud tenant (`prd-p-o1pgk.splunkcloud.com`).
  - Executed end-to-end multi-stage adversary simulation: Nmap port sweep, dropped executable execution, reverse TCP C2 session, PowerShell defense evasion, in-memory SYSTEM privilege escalation, and Volume Shadow Copy destruction.
  - Engineered 6 custom SPL detection queries with false positive tuning and regular expression extraction for structured XML telemetry.
  - Deployed 5 automated scheduled alerts with verified firings in Splunk Cloud Activity console.
  - Built production SOC Operations Center Classic XML dashboard and authored formal Incident Report ([IR-SPLUNK-2026-001.pdf](./splunk-cloud-soc-lab/docs/INCIDENT_REPORT.pdf)).

### 🛡️ [Enterprise SOC Detection Lab: Ransomware Simulation & Detection Engineering](./wazuh-detection-lab/)
- **Domain:** Host-Based Intrusion Detection (HIDS), SIEM Engineering, Blue Team Operations, MITRE ATT&CK T1490
- **Tech Stack:** Wazuh SIEM/XDR v4.14.5, Microsoft Sysmon v15.21, Kali Linux (Metasploit, Nmap), Windows 10 Enterprise
- **Key Deliverables:** 
  - Simulated ransomware pre-staging recovery inhibition techniques on an isolated Windows workstation.
  - Conducted SIEM detection gap analysis revealing default rule blind spots for native administrative tools.
  - Engineered 3 custom XML detection rules (`100001`–`100003`) escalating recovery inhibition to **Level 12 Critical** alerts.
  - Authored formal executive Incident Report ([INCIDENT_REPORT.pdf](./wazuh-detection-lab/docs/INCIDENT_REPORT.pdf)).

### 🎓 [Google Cybersecurity Professional Certificates & Labs](./google-cybersecurity/)
- **Domain:** Foundational Cybersecurity, Linux CLI, Python for Automation, SQL Data Analysis, Network Security
- **Tech Stack:** Linux, Python, SQL, Wireshark, Bash, NIST Cybersecurity Framework

---

## 🛠️ Security Tools & Technical Competencies

- **SIEM & Analytics Platforms:** Splunk Cloud Platform (SPL, Classic XML Dashboards, Alert Manager), Wazuh SIEM/XDR v4.14.5 (OSSEC XML Rules, Wazuh Indexer/Dashboard), Elastic Stack (ELK)
- **Endpoint Telemetry & Monitoring:** Microsoft Sysmon v15.21 (SwiftOnSecurity Schema), Windows Event Log Channels (`Security.evtx`, `System.evtx`, `Sysmon/Operational`), Splunk Universal Forwarder (UF v10.4.3)
- **Adversary Emulation & Assessment:** Kali Linux, Parrot OS, Metasploit Framework, Msfvenom, Nmap, PowerShell Empire
- **Detection Engineering & Scripting:** Search Processing Language (SPL), PCRE2 Regular Expressions, XML (Wazuh & Splunk Schemas), Python, PowerShell, SQL, Bash
- **Frameworks & Industry Standards:** MITRE ATT&CK Framework, Cyber Kill Chain, NIST SP 800-61, NIST CSF

---

## 👤 Author

**Idris Lawan Mustapha**  
*Cyber Security Analyst & Detection Engineer*  
- **GitHub:** [github.com/fikira001](https://github.com/fikira001)  
- **Portfolio Repository:** [cybersecurity-portfolio](https://github.com/fikira001/cybersecurity-portfolio)
