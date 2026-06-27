# Case 01: Malicious Email Attachment Investigation

****Source****

**Platform**: TryHackMe

**Room/Simulation**: Phishing Unfolding Simulation

**Environment**: Simulated SOC Investigation Lab

## Overview

During the phishing simulation exercise, a suspicious email containing a malicious attachment was identified. The objective of this investigation was to analyze the email, determine whether the attachment was malicious, and assess the potential risk to the organization.

The investigation confirmed that the email was part of a phishing campaign designed to deliver a malicious attachment to the victim.

## Scenario

A security alert was generated after an inbound email containing a suspicious attachment was detected. The email, titled "FINAL NOTICE: Overdue Payment - Account Suspension Imminent", urged the recipient to immediately review an attached invoice to avoid account suspension and legal action.

The message originated from john@hatmakereurope.xyz and included a ZIP attachment named ImportantInvoice-February.zip. The use of urgent language, financial themes, and pressure tactics indicated a potential phishing attempt designed to trick the recipient into opening a malicious attachment.

The objective of this investigation was to determine whether the email and its attachment were malicious and assess the potential risk to the organization.

## Alert Details

| Field                | Value                                |
| -------------------- | ------------------------------------ |
| Alert ID             | 1005                                 |
| Alert Name           | Suspicious Attachment Found in Email |
| Category             | Phishing                             |
| Severity             | Low                                  |
| Data Source          | Email                                |
| Timestamp            | 27 June 2026, 08:44:23 UTC           |
| Sender               | `john@hatmakereurope.xyz`            |
| Recipient            | `michael.ascot@tryhatme.com`         |
| Attachment           | `ImportantInvoice-February.zip`      |
| Direction            | Inbound                              |
| Investigation Result | True Positive                        |
| Final Classification | Malicious Phishing Email             |





---

## Investigation Process

**Step 1: Access Elastic Discover**

The investigation began by accessing the Elastic Discover dashboard to review email-related events generated during the simulation.

<img width="1427" height="469" alt="alert1" src="https://github.com/user-attachments/assets/7fa6e5cc-1fed-402b-8d96-e236405331d3" />


**Step 2: Identify the Affected Recipient**

To locate suspicious emails delivered to the targeted user, the following query was executed in Elastic:

recipient : "michael.ascot@tryhatme.com"

This search returned multiple inbound email events associated with the recipient.
<img width="1829" height="863" alt="alert1 elastic" src="https://github.com/user-attachments/assets/c311a38b-56c5-4958-948e-c4c293506b2c" />

**Step 3: Analyze the Email and Identify Suspicious Artifacts**

The email event was further examined in Elastic Discover to identify suspicious artifacts associated with the message.

During the analysis, an attachment named ImportantInvoice-February.zip was identified. The presence of a ZIP attachment in an unsolicited email, combined with the urgent payment theme, raised suspicion of a potential phishing attempt.

Additional observations included:

Sender: john@hatmakereurope.xyz
Subject: FINAL NOTICE: Overdue Payment - Account Suspension Imminent
Direction: Inbound

The use of a compressed ZIP file as an attachment is a common technique used by threat actors to deliver malicious payloads while evading email security controls.
<img width="536" height="346" alt="alert1 attach" src="https://github.com/user-attachments/assets/4e7db630-8407-467d-ac44-561383c802ac" />



**Step 4: Attachment Analysis**

To further investigate the email, the attachment ImportantInvoice-February.zip was uploaded to the file analysis tool.

The initial analysis reported that the ZIP archive itself was clean and did not contain any immediately detectable malicious content.

However, this result did not completely eliminate suspicion because attackers frequently use compressed archives to conceal malicious payloads. While reviewing the investigation, it was identified that only the ZIP archive was analyzed and the files contained within the archive were not extracted and inspected individually.

As a result, the attachment remained suspicious despite the initial "clean" verdict, and additional analysis of the extracted files would be required to conclusively determine whether the email contained malicious content.

<img width="939" height="683" alt="alert1 safe attch" src="https://github.com/user-attachments/assets/d8ba25a6-ab13-4740-a73d-2ba5963f3bd3" />



**Step 5: Revisiting the Analysis and Extracting the Archive**

During the investigation, it was identified that only the ZIP archive had been analyzed during the initial review. Since compressed archives can be used to conceal malicious payloads, relying solely on the archive-level analysis was insufficient.

To ensure a thorough investigation, the ZIP file ImportantInvoice-February.zip was extracted, and the files contained within the archive were prepared for further analysis.

This additional step ensured that hidden or embedded malicious files would not be overlooked during the investigation process.

<img width="1097" height="126" alt="alert 1 attch extract" src="https://github.com/user-attachments/assets/a518349e-05ac-4221-af0d-74c204ab0f4d" />



**Step 6: Analysis of the Extracted File**

After extracting the contents of ImportantInvoice-February.zip, the extracted file was analyzed to determine whether it posed a security risk.

The analysis revealed that the extracted file exhibited malicious characteristics and was identified as a malware payload. This confirmed that the original email was part of a phishing campaign designed to deliver malware to the recipient.

The discovery of a malicious file inside the archive validated the initial suspicion and confirmed the alert as a True Positive.

<img width="916" height="673" alt="alert1 malicious" src="https://github.com/user-attachments/assets/6e2e9410-ad8b-433d-ab62-2be7838c1c0c" />



**Step 7 Classification as True Positive**


The alert was classified as a True Positive because the attachment contained a .lnk (shortcut) file instead of a legitimate document format such as .pdf or .docx. Attackers commonly use .lnk files in phishing campaigns to disguise malicious payloads and trick users into executing malicious code.
<img width="916" height="673" alt="alert1 malicious" src="https://github.com/user-attachments/assets/c6f24bee-0621-49d0-8f8a-7c1f823a46f9" />

## Indicators of Compromise (IOCs)

| IOC Type        | Value                                                         |
| --------------- | ------------------------------------------------------------- |
| Sender Email    | `john@hatmakereurope.xyz`                                     |
| Sender Domain   | `hatmakereurope.xyz`                                          |
| Attachment Name | `ImportantInvoice-February.zip`                               |
| Email Subject   | `FINAL NOTICE: Overdue Payment - Account Suspension Imminent` |

---

## MITRE ATT&CK Mapping

| Tactic         | Technique                | ID        |
| -------------- | ------------------------ | --------- |
| Initial Access | Phishing                 | T1566     |
| Initial Access | Spearphishing Attachment | T1566.001 |
| Execution      | User Execution           | T1204     |

---
## Key Findings

* The email used urgent and threatening language to pressure the recipient into immediate action.
* An unsolicited ZIP attachment (`ImportantInvoice-February.zip`) was delivered from a suspicious domain (`hatmakereurope.xyz`).
* Initial analysis of the ZIP archive appeared benign; however, further investigation revealed that only the archive had been analyzed.
* After extracting and analyzing the file contained within the ZIP archive, malicious characteristics were identified.
* The investigation confirmed the email as a phishing attempt designed to deliver malware.
---


## Final Verdict

> **True Positive - Malicious Phishing Email**

The investigation confirmed that the email was a phishing attempt containing a malicious attachment. The email leveraged social engineering tactics, including urgency and threats of account suspension, to persuade the recipient to open the attachment and execute malicious content.


