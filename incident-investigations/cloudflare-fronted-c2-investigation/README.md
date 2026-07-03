
# Background

> On **June 13, 2025**, a Windows computer started making suspicious network connections to external servers. A packet capture (PCAP) and forensic files were collected for analysis. The goal of this investigation was to identify how the system was compromised, what the malware did after execution, and whether it established communication with a command-and-control (C2) server.

---



# Executive Summary

A Windows endpoint was found communicating with suspicious external infrastructure. The investigation revealed that PowerShell downloaded malware from a fake Microsoft-themed domain. The malware established persistence through the Windows Startup folder and communicated with command-and-control (C2) servers hidden behind Cloudflare. The attack was confirmed through network traffic analysis, malware analysis, forensic artifacts, and threat intelligence.


# Objectives

* Identify the compromised host.
* Determine how the malware infected the system.
* Analyze the network traffic and malware behavior.
* Collect and validate Indicators of Compromise (IOCs).
* Map the attack to the MITRE ATT&CK framework.
* Develop detection opportunities for future incidents.

---

# Tools Used

| Tool                    | Purpose                                                                                         |
| ----------------------- | ----------------------------------------------------------------------------------------------- |
| Wireshark               | Analyzed network traffic and followed HTTP/TLS streams.                                         |
| VirusTotal              | Checked the reputation of domains, IP addresses, file hashes, and malware samples.              |                                   |
| **WHOIS (DomainTools)** | Checked domain registration details such as creation date, registrar, and registration history. |
| CyberChef               | Decoded and analyzed encoded data when required.                                                |
| `sha256sum`             | Generated the SHA-256 hash of the malware sample.                                               |
                                               |

---

# Investigation

## Step 1 – Identifying Suspicious Network Activity

I started by opening the PCAP in **Wireshark** and filtering for HTTP traffic.

```text
http
```


<img width="986" height="731" alt="http" src="https://github.com/user-attachments/assets/83edd8be-4b52-4fb4-817d-a95f38e0af2a" />


Several HTTP requests immediately stood out:

* A **GET** request to `/msdownload/update/v3/st`, pretending to be a Windows Update request but communicating with a non-Microsoft IP address.
* Multiple **POST** requests to unusual URIs such as `/NV4RgNEu`, `/YSEpJj/CPZldd`, and `/LIO92KGFa/`.
* All requests originated from the same internal host, **10.6.13.133**.

These patterns are not typical of normal web traffic and suggested that the host was communicating with a command-and-control (C2) server.

---

## Step 2 – Identifying the Initial Infection

Next, I followed the TCP stream of the suspicious GET request to **104.21.24.186**.


<img width="896" height="761" alt="tcp" src="https://github.com/user-attachments/assets/514eddac-5d0b-45ea-b1b1-b5c8239fec48" />


Two indicators confirmed suspicious activity:

* **User-Agent:** `WindowsPowerShell/5.1.26100.4202`
* **Host:** `event-time-microsoft.org`

The request was made through **PowerShell**, not a web browser. The domain also imitated Microsoft's naming but was not an official Microsoft domain.

This indicates that PowerShell was used to download the malware from a fake Microsoft-themed domain, marking the initial infection point.

---

## Step 3 – Investigating Domains and IP Addresses

I validated the suspicious domains and IP addresses using **VirusTotal**, **WHOIS**, and **AbuseIPDB**.

### `event-time-microsoft.org`


VirusTotal detected the domain as malicious, with **15 security vendors** flagging it.

<img width="1568" height="784" alt="virustotalmicrosoft" src="https://github.com/user-attachments/assets/44fa097e-489e-4880-ab04-a511ebc8fb26" />


Using **WHOIS**, I found that the domain was registered on **June 12, 2025**, just **one day before the attack**. Shortly after the campaign, the domain was removed. This short registration period is commonly seen in malicious infrastructure.


<img width="953" height="779" alt="whois" src="https://github.com/user-attachments/assets/d141913c-9c2d-4ff0-8aa4-4aa7fd7f9fb4" />




---

## Step 4 – Analyzing Encrypted Traffic

To examine encrypted communication, I filtered for TLS Client Hello packets.

```text
tls.handshake.type == 1
```

<img width="986" height="711" alt="tls" src="https://github.com/user-attachments/assets/fa98e06f-84a5-42bc-91e4-f84e132cb3f9" />


Most TLS connections were made to legitimate Microsoft services. However, one connection stood out.

* **Destination IP:** `172.67.146.241`
* **SNI:** `dng-microsoftds.com`

<img width="996" height="726" alt="tlssni" src="https://github.com/user-attachments/assets/31993ca0-4407-45ea-96e4-94c02b3ad750" />


Although the domain appeared Microsoft-related, it was fraudulent. The malware used this fake domain over HTTPS to communicate with its command-and-control server, making the traffic appear legitimate.

---

## Step 5 – Malware Analysis

The forensic files contained two suspicious files inside:

```text
AppData\Roaming\afUGkp\
```

* `c2.exe`
* `ycBFVIbLl.lnk`
  

<img width="657" height="519" alt="forensic" src="https://github.com/user-attachments/assets/322bf61c-3cf0-4be3-921b-5e5b19f6e055" />


I generated the SHA-256 hash of **c2.exe** and verified it on VirusTotal.

```bash
sha256sum c2.exe
```

<img width="795" height="562" alt="hash" src="https://github.com/user-attachments/assets/26d42a9d-8454-4020-8972-c36fe6dee29e" />



VirusTotal detected the file as **Trojan.Doina/iaxqm**, with **44 out of 70** security vendors identifying it as malicious.



<img width="1568" height="778" alt="hashvirus" src="https://github.com/user-attachments/assets/e35a1c65-ab40-4ca6-b5c5-f30d139fc338" />



The malware also showed several notable behaviors:

* Delays execution to avoid sandbox detection.
* Detects debugging environments.
* Monitors clipboard activity.
* Has the ability to spread to other systems.
* Compiled as a 64-bit Windows executable.

These behaviors indicate that the malware was designed to evade detection while maintaining long-term access.



---



# Attack Timeline

| **Time (UTC)**          | **Activity**                                                                                              |
| ----------------------- | --------------------------------------------------------------------------------------------------------- |
| **2025-06-12**          | The attacker registered the fake domain **event-time-microsoft.org** one day before launching the attack. |
| **2025-06-13 15:35:20** | PowerShell connected to the fake domain and downloaded the malware.                                       |
| **2025-06-13 15:35:51** | The malware (**c2.exe**) was saved in the **AppData\Roaming\afUGkp** folder.                              |
| **2025-06-13 ~15:36**   | A shortcut (**ycBFVIbLl.lnk**) was created in the Windows Startup folder to maintain persistence.         |
| **2025-06-13 ~15:36**   | The infected host sent a fake Windows Update request to **217.20.51.22**.                                 |
| **2025-06-13 ~15:37**   | The malware established an encrypted TLS connection to **dng-microsoftds.com** through Cloudflare.        |
| **2025-06-13 onwards**  | The infected system continued sending repeated HTTP POST requests to the attacker's C2 infrastructure.    |

---

# Indicators of Compromise (IOCs)

| **Indicator**                                                    | **Type**   | **Description**                                   |
| ---------------------------------------------------------------- | ---------- | ------------------------------------------------- |
| 10.6.13.133                                                      | IP Address | Compromised internal host                         |
| event-time-microsoft.org                                         | Domain     | Fake Microsoft domain used to deliver the malware |
| dng-microsoftds.com                                              | Domain     | Fake Microsoft domain used for C2 communication   |
| 217.20.51.22                                                     | IP Address | Server used to imitate Windows Update traffic     |
| 104.21.112.1                                                     | IP Address | Cloudflare IP used by the C2 infrastructure       |
| 104.21.16.1                                                      | IP Address | Cloudflare IP used by the C2 infrastructure       |
| 172.67.146.241                                                   | IP Address | Cloudflare IP hosting the fake domain             |
| 104.16.230.132                                                   | IP Address | Additional C2-related IP                          |
| c2.exe                                                           | File       | Malware executable                                |
| 1206473a7c5643dc0a1a52c17418aa37fb5194e2395907aefaec976cb4849b4e | SHA-256    | Hash of the malware sample                        |
| ycBFVIbLl.lnk                                                    | File       | Startup shortcut used for persistence             |
| WindowsPowerShell/5.1.26100.4202                                 | User-Agent | PowerShell used to download the malware           |

---

# MITRE ATT&CK Mapping

| **Tactic**          | **Technique**     | **ID**    | **Evidence**                                                         |
| ------------------- | ----------------- | --------- | -------------------------------------------------------------------- |
| Execution           | PowerShell        | T1059.001 | PowerShell downloaded and executed the malware.                      |
| Persistence         | Startup Folder    | T1547.001 | Malware created a shortcut in the Windows Startup folder.            |
| Defense Evasion     | Masquerading      | T1036     | Fake Microsoft-themed domains were used to appear legitimate.        |
| Defense Evasion     | Sandbox Evasion   | T1497     | The malware delayed execution and checked for analysis environments. |
| Defense Evasion     | Domain Fronting   | T1090.004 | Cloudflare infrastructure was used to hide the real C2 server.       |
| Command and Control | Web Protocols     | T1071.001 | HTTP POST requests were used to communicate with the C2 server.      |
| Command and Control | Encrypted Channel | T1573     | TLS encryption was used to hide C2 communication.                    |
| Collection          | Clipboard Data    | T1115     | The malware monitored clipboard activity.                            |
| Lateral Movement    | Internal Spreader | T1534     | Malware showed the capability to spread to other systems.            |





# Findings

The investigation confirmed that **10.6.13.133** (user: **rgaines**) was successfully compromised.

The malware was downloaded using **PowerShell** from a fake Microsoft-themed domain that had been registered only one day before the attack. After execution, it created persistence through the Windows Startup folder and started communicating with command-and-control (C2) servers hidden behind Cloudflare.

The attacker used fake Microsoft domains, Cloudflare infrastructure, and random file names to make the malicious activity appear legitimate and reduce the chances of detection.

**Verdict:** **True Positive — Active compromise confirmed.**

---


## Recommendations

* Isolate **10.6.13.133** from the network immediately to stop further communication with the C2 server.
* Block the domains **event-time-microsoft.org** and **dng-microsoftds.com** across the environment.
* Search all systems for **ycBFVIbLl.lnk** in the Windows Startup folder to identify other affected devices.
* Search for the malware SHA-256 hash across EDR or antivirus logs to check if the malware exists on other endpoints.
* Monitor and alert on **PowerShell** making HTTP requests to suspicious domains, especially those impersonating Microsoft.
* Enable **PowerShell Script Block Logging** to improve visibility into PowerShell activity.
* Review network traffic to the identified Cloudflare IP addresses to determine if additional systems communicated with the same infrastructure.


# Conclusion

 This investigation confirmed a successful malware infection that resulted in command-and-control communication with attacker-controlled infrastructure. The attacker used fake Microsoft-themed domains, Cloudflare services, and persistence techniques to reduce the chance of detection. By combining network traffic analysis, threat intelligence, malware analysis, and domain registration data, the complete attack chain was successfully reconstructed. The collected IOCs and detection rules can help identify similar attacks in the future.

---


**References**


## References

- Malware Traffic Analysis
  
- Wireshark
  
- VirusTotal
  
- DomainTools WHOIS
  
- MITRE ATT&CK
