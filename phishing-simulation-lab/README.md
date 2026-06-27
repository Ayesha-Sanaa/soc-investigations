# Phishing Unfolding Simulation – SOC Investigation Lab

## Overview

This repository contains my investigation and analysis of security alerts generated during the **Phishing Unfolding Simulation** on the **TryHackMe** platform.

The simulation presents a realistic Security Operations Center (SOC) environment in which analysts investigate alerts generated throughout a phishing attack lifecycle. The objective of this lab was to triage alerts, identify malicious activity, collect evidence, and determine the appropriate response actions.

Rather than documenting every alert generated during the simulation, this repository focuses on the most significant and security-relevant events, including phishing delivery, suspicious PowerShell activity, and potential DNS-based data exfiltration.

---

## Lab Information

| Field              | Value                                 |
| ------------------ | ------------------------------------- |
| Platform           | TryHackMe                             |
| Lab                | Phishing Unfolding Simulation         |
| Environment        | Simulated SOC Environment             |
| SIEM               | Elastic Stack (ELK)                   |
| Data Sources       | Email Logs, Sysmon Logs               |
| Investigation Type | Alert Triage & Incident Investigation |

---

## Investigation Cases

### Case 01 – Malicious Email Attachment Investigation

**Description:** Investigated a suspicious inbound email containing a ZIP attachment that was ultimately identified as malicious after extracting and analyzing its contents.

**Key Skills:**

* Email Analysis
* Attachment Analysis
* Phishing Detection
* IOC Identification
* Alert Triage

📁 Folder: `Case-01-Malicious-Email-Attachment`

---

### Case 02 – Suspicious PowerShell Script Creation Investigation

**Description:** Investigated the creation of `PowerView.ps1` within the user's Downloads directory. The presence of a known offensive reconnaissance tool was identified and escalated for further investigation.

**Key Skills:**

* Sysmon Log Analysis
* PowerShell Investigation
* File Creation Analysis
* Threat Hunting
* Alert Triage

📁 Folder: `Case-02-PowerShell-Script-Creation`

---

### Case 03 – Suspicious DNS Request Investigation

**Description:** Investigated suspicious DNS activity where `powershell.exe` spawned `nslookup.exe` to query a domain containing encoded data, indicating possible DNS-based command-and-control or data exfiltration.

**Key Skills:**

* Process Analysis
* Parent-Child Relationship Analysis
* DNS Investigation
* Command Line Analysis
* Threat Hunting

📁 Folder: `Case-03-Suspicious-DNS-Activity`

---

## Tools Used

* Elastic Stack (ELK)
* Elastic Discover
* Sysmon
* TryHackMe SOC Environment

---

## MITRE ATT&CK Techniques Observed

| Technique                                     | ID        |
| --------------------------------------------- | --------- |
| Phishing                                      | T1566     |
| Spearphishing Attachment                      | T1566.001 |
| User Execution                                | T1204     |
| Command and Scripting Interpreter: PowerShell | T1059.001 |
| Application Layer Protocol: DNS               | T1071.004 |
| Exfiltration Over Alternative Protocol        | T1048     |

---

## Skills Demonstrated

* Security Alert Triage
* Phishing Investigation
* Email Analysis
* Sysmon Log Analysis
* PowerShell Analysis
* DNS Investigation
* IOC Identification
* MITRE ATT&CK Mapping
* Incident Documentation
* Evidence Collection
* SOC Investigation Workflow

---

## Key Takeaways

* Phishing emails frequently leverage social engineering techniques to persuade users to open malicious attachments.
* PowerShell is commonly abused by attackers for reconnaissance and post-exploitation activities.
* Unusual parent-child process relationships can reveal malicious behavior.
* DNS requests containing encoded data may indicate command-and-control or data exfiltration attempts.
* Effective SOC investigations require validating alerts, collecting evidence, and escalating suspicious activity when necessary.

---


```
