# Empire C2 Registry Run Key Persistence Investigation

## Detecting Registry Persistence Using Windows Logs & Sysmon

### Scenario

I investigated a Windows workstation after an endpoint alert showed that a **Windows Run registry key** had been modified. While Run keys are commonly used by legitimate software, attackers can also abuse them to maintain persistence by running malware every time a user logs in.

My goal was to identify what changed, which process made the change, whether the persistence worked, and if the activity matched a known attack technique.

**Dataset:** `empire_persistence_registry_modification_run_keys_elevated_user` (OTRF Security Datasets)

## Objectives

* Identify the modified registry value.
* Find the responsible process and user.
* Verify persistence.
* Build the attack timeline.
* Extract IOCs.
* Map to MITRE ATT&CK.
* Recommend detection and remediation.

## Scope

**Included:** Windows Security, Sysmon, PowerShell, and Registry logs.

**Not Included:** Initial access, memory forensics, network traffic, or malware analysis.

## Tools Used

* Python 3
* Kali Linux Terminal
* CyberChef / Python
* MITRE ATT&CK Navigator

  # Investigation Steps

### Step 1 — Download the Dataset

```bash
mkdir empire-investigation && cd empire-investigation
wget "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/persistence/host/empire_persistence_registry_modification_run_keys_elevated_user.zip" -O dataset.zip
unzip dataset.zip
```
<img width="1568" height="687" alt="wget" src="https://github.com/user-attachments/assets/ee2fb242-40a2-4b00-9be5-1daf627c685d" />


Downloaded and extracted the dataset. The main file used for the investigation was:

`empire_persistence_registry_modification_run_keys_elevated_user_2020-07-22001847.json`


---

### Step 2 — Inspect the Dataset

wc -l empire_persistence_registry_modification_run_keys_elevated_user_2020-07-22001847.json
head -1 empire_persistence_registry_modification_run_keys_elevated_user_2020-07-22001847.json | python3 -m json.tool

<img width="1913" height="827" alt="wc" src="https://github.com/user-attachments/assets/72afd7ec-264e-414e-9f64-d5d858cdfeda" />


Checked the total number of events (657) and reviewed the first event to understand the available log fields before filtering.
---

### Step 3 — Find Registry Changes

```python
# Filter Sysmon Event IDs 12 and 13
```

Filtered **Sysmon Event IDs 12 and 13** to find registry activity.

<img width="1913" height="827" alt="wc" src="https://github.com/user-attachments/assets/363c034c-aef3-405e-b2f9-18faaf78f716" />


**Findings**

* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Debug`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater`

Both registry changes were made by **powershell.exe**, making them the main focus of the investigation.

---

### Step 4 — Identify the Process

```python
# Print the full event for the Run key
```

<img width="1870" height="770" alt="04-run-key-full-detail" src="https://github.com/user-attachments/assets/af7220b3-9fd3-4319-8df2-7926b485e6db" />


Examined the complete registry event.

**Key Findings**

* Process: `powershell.exe`
* User: `SYSTEM`
* Registry Key: `Run\Updater`

The Run key launches a hidden PowerShell process that reads another registry value (`Debug`), where the actual payload is stored.

---

### Step 5 — Decode the Payload

```python
# Decode Base64 PowerShell payload
```

Decoded the Base64-encoded PowerShell command stored in the **Debug** registry key.


<img width="1919" height="573" alt="05-decoded-payload" src="https://github.com/user-attachments/assets/2ed51658-af38-4ab4-b396-74de9d2f2535" />


**Findings**

* Empire PowerShell stager
* AMSI bypass
* Script Block Logging disabled
* Fake browser User-Agent
* Encoded C2 information

---

### Step 6 — Extract the C2 Address

```python
# Decode embedded Base64 string
```

Decoded the embedded C2 address.

**C2 Server**

`http://10.10.10.5:80/login/process.php`

---


<img width="1777" height="536" alt="06-c2-address-decoded" src="https://github.com/user-attachments/assets/73b4a223-d690-45e0-9e6d-0216a6421b80" />


### Step 7 — Review the Timeline

# List Event IDs and timeline


Reviewed the available logs and timeline.




**Findings**

* Dataset covers only **49 seconds**.
* No attacker logon events were found for the compromised workstation.
* The logs capture only the **persistence stage**, indicating the attacker already had access before the dataset begins.




## Evidence Summary

| Evidence      | Details                                                                                        |
| ------------- | ---------------------------------------------------------------------------------------------- |
| Host          | `WORKSTATION5.mordor.local`                                                                    |
| Process       | `powershell.exe` (PID 9076)                                                                    |
| User          | `SYSTEM`                                                                                       |
| Registry Keys | `HKLM\...\CurrentVersion\Debug` (payload), `HKLM\...\CurrentVersion\Run\Updater` (persistence) |
| Payload       | Empire stager, AMSI bypass, Script Block Logging disabled                                      |
| C2            | `http://10.10.10.5:80/login/process.php`                                                       |

---

## Timeline

| Time                    | Event                                                        |
| ----------------------- | ------------------------------------------------------------ |
| **00:18:45**            | Log collection starts.                                       |
| **00:18:47 – 00:19:03** | Empire agent is already beaconing.                           |
| **00:19:04**            | PowerShell writes the payload to the **Debug** registry key. |
| **00:19:04**            | Run **Updater** key is created for persistence.              |
| **00:19:34**            | Log collection ends.                                         |

> The dataset only shows the persistence stage. Initial access is not included.

---

## IOCs

* **Host:** `WORKSTATION5.mordor.local`
* **Process:** `powershell.exe`
* **Registry Keys:** `HKLM\...\CurrentVersion\Debug`, `HKLM\...\CurrentVersion\Run\Updater`
* **C2:** `10.10.10.5:80/login/process.php`
* **User-Agent:** `Mozilla/5.0...like Gecko`

---

## MITRE ATT&CK Mapping

| Tactic            | Technique                              |
| ----------------- | -------------------------------------- |
| Persistence       | **T1547.001** – Registry Run Keys      |
| Defense Evasion   | **T1112** – Modify Registry            |
| Defense Evasion   | **T1562.001** – Disable Security Tools |
| Execution         | **T1059.001** – PowerShell             |
| Command & Control | **T1071.001** – Web Protocols          |


## What I Found

An **Empire C2** agent was already running as **SYSTEM** on `WORKSTATION5`. It stored its payload in the **Debug** registry key and created a **Run** key to execute it automatically at logon. The decoded payload confirmed **AMSI bypass**, **PowerShell logging disabled**, and communication with its **C2 server**.

The dataset only covers the **persistence stage**, so it doesn't show how the attacker initially gained access.

---

## Recommendations

**Immediate**

* Isolate the affected machine.
* Stop the malicious `powershell.exe` process.
* Remove the **Debug** and **Run\Updater** registry keys.
* Block traffic to `10.10.10.5:80`.

**Next**

* Review earlier logs to identify the initial access.
* Hunt for the same IOCs on other systems.
* Check for disabled AMSI or PowerShell logging.

**Long Term**

* Enable and protect PowerShell Script Block Logging.
* Deploy detection rules for this technique.
* Restrict PowerShell with security controls such as Constrained Language Mode or Application Control.


## References

* OTRF Security Datasets – *Empire Persistence Registry Modification (Run Keys)*
  https://github.com/OTRF/Security-Datasets

* MITRE ATT&CK – **T1547.001: Registry Run Keys / Startup Folder**
  https://attack.mitre.org/techniques/T1547/001/

* MITRE ATT&CK – **T1112: Modify Registry**
  https://attack.mitre.org/techniques/T1112/

* MITRE ATT&CK – **T1562.001: Disable or Modify Security Tools**
  https://attack.mitre.org/techniques/T1562/001/

* MITRE ATT&CK – **T1059.001: PowerShell**
  https://attack.mitre.org/techniques/T1059/001/

* MITRE ATT&CK – **T1071.001: Web Protocols**
  https://attack.mitre.org/techniques/T1071/001/

* Microsoft Learn – Sysmon Overview
  https://learn.microsoft.com/sysinternals/downloads/sysmon


