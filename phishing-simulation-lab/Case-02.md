# Case 02: Suspicious PowerShell Script Creation Investigation

## Source

**Platform:** TryHackMe

**Room/Simulation:** Phishing Unfolding Simulation

**Environment:** Simulated SOC Investigation Lab

---

## Overview

During the investigation, an alert was triggered after a PowerShell script was created in the user's Downloads directory. Since PowerShell is frequently abused by threat actors for reconnaissance, persistence, and post-exploitation activities, the event required further investigation to determine whether the activity was legitimate or malicious.

The investigation revealed the creation of **PowerView.ps1**, a well-known PowerShell-based reconnaissance tool commonly used by attackers to enumerate Active Directory environments.

---

## Scenario

A security alert identified the creation of a PowerShell script within the Downloads directory on host **win-3450**. The alert indicated that **powershell.exe** created a file named **PowerView.ps1**.


---

## Alert Details

| Field                | Value                                            |
| -------------------- | ------------------------------------------------ |
| Alert ID             | 1020                                             |
| Alert Name           | PowerShell Script in Downloads Folder            |
| Category             | Execution                                        |
| Severity             | Low                                              |
| Data Source          | Sysmon                                           |
| Timestamp            | 27 June 2026, 09:05:53 UTC                       |
| Event Code           | 11                                               |
| Host Name            | `win-3450`                                       |
| Process Name         | `powershell.exe`                                 |
| Process ID           | `9060`                                           |
| Event Action         | `File created (rule: FileCreate)`                |
| File Path            | `C:\Users\michael.ascot\Downloads\PowerView.ps1` |
| Investigation Result | True Positive                                    |
| Final Classification | Suspicious PowerShell Reconnaissance Activity    |





## Investigation Steps

### Step 1: Review the Alert

The investigation began by reviewing the Sysmon alert. The alert indicated that a PowerShell script had been created in the Downloads directory on host **win-3450**.

Key observations:

* Data Source: `Sysmon`
* Event Code: `11` (File Create)
* Process Name: `powershell.exe`
* Host: `win-3450`

### Evidence

<img width="1402" height="424" alt="alert2" src="https://github.com/user-attachments/assets/a2835cbf-765f-4800-995c-fb34114cfde5" />

---

### Step 2: Analyze the Created File

Further analysis of the alert revealed that the file created was **`PowerView.ps1`**, located at:

```text
C:\Users\michael.ascot\Downloads\PowerView.ps1
```

The file creation event was initiated by **`powershell.exe`**.

### Evidence

<img width="576" height="525" alt="alert 2 evidence" src="https://github.com/user-attachments/assets/1e3a01c7-169a-4d68-b435-47e149db3987" />

---

### Step 3: Assess the Suspicious Activity

The file **`PowerView.ps1`** is a well-known PowerShell-based reconnaissance tool commonly used to enumerate Active Directory environments.

Although the alert only confirmed file creation and not script execution, the presence of a known offensive security tool in the user's Downloads directory was considered highly suspicious and warranted further investigation.

### Step 4: Determine the Verdict

Based on the creation of PowerView.ps1, a well-known reconnaissance tool commonly used by attackers, the alert was classified as a True Positive.

Although the available evidence only confirmed file creation and not script execution, the presence of a known offensive security tool on the system was considered suspicious. Therefore, the case was escalated to a senior analyst for further investigation to determine whether the script had been executed and whether additional malicious activity had occurred.
Final Verdict

**True Positive – Suspicious Reconnaissance Tool Detected**

### Key Findings
A PowerShell script named PowerView.ps1 was created in the Downloads folder on host win-3450.
The file creation event was initiated by powershell.exe.
PowerView is a well-known reconnaissance tool frequently used to enumerate Active Directory environments.
The alert confirmed file creation but did not provide evidence of script execution.
The presence of a known offensive security tool on the system was considered suspicious and warranted further investigation.


### Action Taken: Escalated to a Senior Analyst for further investigation.
