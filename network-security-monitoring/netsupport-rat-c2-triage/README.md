# NetSupport RAT C2 Triage — Alert Investigation (45.131.214.85)

## Scenario

A SIEM alert fired on an internal host showing repeated outbound connections to an external IP — `45.131.214.85`. The traffic pattern was flagged as suspicious due to its regularity and destination. My job was to triage the alert, confirm whether this was a genuine compromise, identify the malware family, and document the findings.

This investigation builds on prior analysis documented in NetSupport RAT C2 Triage ,https://github.com/Ayesha-Sanaa/soc-investigations/tree/main/network-traffic-analysis/netsupport-rat-c2-investigation where the same malware family was analyzed at the traffic level. Here the focus is on the full SOC triage workflow — from alert to confirmed threat.

---

## Tools Used

| Tool | Purpose |
|---|---|
| Wireshark | PCAP analysis, beacon pattern identification |
| VirusTotal | IP reputation check |
| AbuseIPDB | ISP/ASN enrichment |
| ThreatFox (abuse.ch) | IOC lookup, malware family confirmation |
| Breakglass Intelligence | Campaign context and threat intel |

---

## Investigation

### Step 1 — IP Triage (OSINT)

First thing I did after the alert fired was look up the destination IP across multiple threat intel platforms to understand what we're dealing with before touching the PCAP.

**VirusTotal**
`45.131.214.85` came back flagged by 11 out of 91 vendors including BitDefender, Fortinet, Sophos, G-Data, and Dr.Web — all labeling it as malware or malicious. Community score was -12. ASN confirmed as MHost LLC (AS200823).

<img width="1834" height="921" alt="virus total" src="https://github.com/user-attachments/assets/6aa1c363-3e7b-424e-af72-fadf1b99694a" />

**AbuseIPDB**
No prior abuse reports, but infrastructure details were telling — ISP: MHost LLC, Usage Type: Data Center/Web Hosting/Transit, Location: Frankfurt am Main, Germany. Data center hosting with no legitimate business association is a common pattern for bulletproof C2 infrastructure.

<img width="1729" height="913" alt="abuseip" src="https://github.com/user-attachments/assets/9d52d464-8962-4c39-b0a1-8862e7e2380b" />

**ThreatFox**
This confirmed it. The IOC `45.131.214.85:443` was reported on 2026-02-28 at 15:00 UTC, tagged as **NetSupportManager RAT**, reported directly by abuse.ch. Port 443 is used to blend C2 traffic with normal HTTPS — a common evasion technique.

<img width="1631" height="820" alt="threatfox" src="https://github.com/user-attachments/assets/ad65407c-251c-4482-8890-4e48edcbfa98" />

---

### Step 2 — Campaign Context


**1. IP Context**
`45.131.214.85` was provisioned on 2026-02-27 under the hostname `VM-3a451985` and is linked to the domain `vadusa[.]xyz`. This VM was specifically deployed as a C2 server for dropper payloads including `us.gov.exe` and `usa.confirm.exe`.

**2. Targets**
This campaign was actively targeting freight brokers, logistics companies, and government organizations. The dropper filenames were deliberately chosen to appear as legitimate freight and business documents — `RateConf.exe`, `Order.exe`, `RateConfirm.exe`.

**3. Delivery Method**
The droppers are wrapped using PyInstaller and register themselves as "Windows Update Assistant by Microsoft Corporation" to avoid suspicion. They establish persistence by dropping a `Client.lnk` shortcut into the Windows Startup folder.

**4. C2 Behavior**
The malware communicates over port 443 but does not use actual HTTPS. NetSupport RAT uses a custom protocol that resets the TLS handshake, meaning standard HTTPS inspection would likely miss this traffic entirely.

**5. Infrastructure Pattern**
MHost LLC (AS200823) is a bulletproof hosting provider. The entire ASN was created only two weeks before this campaign — fresh infrastructure deliberately spun up to avoid reputation-based blocking. When a domain gets burned (e.g. `efsllc.org` was suspended), a replacement domain and VM are ready within 48 hours.

---

### Step 3 — PCAP Analysis

With the IP confirmed malicious, I opened the PCAP in Wireshark to see the actual traffic behavior from the internal network side.

**Filter applied:**
```
http.user_agent contains "NetSupport"
```

This immediately isolated 264 packets — all HTTP POST requests from internal host `10.2.28.88` to `45.131.214.85`, all hitting the endpoint `/fakeurl.htm`.

<img width="1078" height="726" alt="wireshark" src="https://github.com/user-attachments/assets/74af370f-d60f-4507-9e90-b2bb5eca32f8" />

Expanding the HTTP layer on packet 2638 confirmed the User-Agent string:

```
User-Agent: NetSupport Manager/1.3
```
<img width="1070" height="723" alt="extend" src="https://github.com/user-attachments/assets/9a12143e-4c22-45a3-8edb-1e5e64aa1e72" />


This is the known beacon signature for NetSupport RAT C2 communication.


**Beacon Interval Analysis**

Looking at timestamps across the filtered packets:

| Packet | Timestamp (s) | Delta |
|---|---|---|
| 3807 | 105.93 | — |
| 4093 | 166.00 | ~60s |
| 4134 | 226.08 | ~60s |
| 4149 | 286.16 | ~60s |
| 4201 | 346.34 | ~60s |

The infected host was beaconing back to C2 every **~60 seconds** — consistent, automated, no human interaction. This rules out any legitimate NetSupport Manager deployment.

---

## IOCs

| Indicator | Type | Context |
|---|---|---|
| `45.131.214.85` | IP | NetSupport RAT C2 server |
| `45.131.214.85:443` | IP:Port | C2 beacon port |
| `vadusa[.]xyz` | Domain | Associated C2 domain |
| `10.2.28.88` | IP | Infected internal host |
| `/fakeurl.htm` | URI | NetSupport RAT beacon endpoint |
| `NetSupport Manager/1.3` | User-Agent | RAT HTTP beacon signature |
| `AS200823` | ASN | MHost LLC — bulletproof hosting |
| `RateConf.exe`, `Order.exe` | Filename | Known dropper filenames from this campaign |

---

## MITRE ATT&CK Mapping

| Technique | ID | Detail |
|---|---|---|
| Command and Control | T1219 | NetSupport Manager used as RAT for remote access |
| Application Layer Protocol: Web Protocols | T1071.001 | C2 over HTTP POST to `/fakeurl.htm` |
| Non-Standard Port | T1571 | Port 443 used to mimic HTTPS and evade detection |
| Masquerading | T1036 | Dropper filenames themed around freight documents |
| Scheduled/Automated Beaconing | — | ~60 second beacon interval, fully automated |

---

## Findings

The SIEM alert was a **true positive**. Internal host `10.2.28.88` was actively beaconing to a confirmed NetSupport RAT C2 server at `45.131.214.85` every 60 seconds over HTTP. The traffic pattern, User-Agent string, and beacon endpoint `/fakeurl.htm` all match known NetSupport RAT behavior documented in threat intelligence reporting.

The C2 server is hosted on MHost LLC (AS200823) — a bulletproof hosting provider flagged across multiple threat intel feeds. The IP is tied to an active campaign targeting freight and government sectors using lure filenames designed to appear as legitimate business documents.

This is not a false positive. The host needs to be isolated immediately.

---

## Recommendations

- **Isolate** `10.2.28.88` from the network immediately — active C2 channel confirmed
- **Block** `45.131.214.85` and `vadusa[.]xyz` at firewall and DNS level
- **Block** ASN `AS200823` (MHost LLC) if no legitimate business dependency exists
- **Hunt** for other internal hosts communicating with the same ASN or using `NetSupport Manager/1.3` User-Agent
- **Search** endpoint for dropper filenames: `RateConf.exe`, `Order.exe`, `RateConfirm.exe`


---

## References

- [ThreatFox IOC — 45.131.214.85:443](https://threatfox.abuse.ch/browse.php?search=ioc%3A45.131.214.85)
- [VirusTotal — 45.131.214.85](https://www.virustotal.com/gui/ip-address/45.131.214.85)
- [AbuseIPDB — 45.131.214.85](https://www.abuseipdb.com/check/45.131.214.85)
- [Breakglass Intelligence — NetSupport RAT Campaign (Freight/Gov)](https://intel.breakglass.tech/post/open-directory-exposes-active-netsupport-rat-campaign-targeting-freight-and-government-sectors)
- [Malware Traffic Analysis — 2026-02-28 Exercise](https://www.malware-traffic-analysis.net/2026/02/28/index.html)
- Prior investigation: (https://github.com/Ayesha-Sanaa/soc-investigations/tree/main/network-traffic-analysis/netsupport-rat-c2-investigation)
