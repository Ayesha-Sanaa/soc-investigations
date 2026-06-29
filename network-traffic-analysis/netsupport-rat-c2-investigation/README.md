# NetSupport RAT C2 Traffic Investigation

## Background

As dynamic go-getter at a Security Operations Center (SOC), you check the Security Information and Event Management (SIEM) system and find several signature hits for NetSupport Manager RAT from 45.131.214[.]85 over TCP port 443. The activity started on 2026-02-28 at 19:55 UTC.

Using this information, you quickly retrieve a packet capture (pcap) of the traffic from the internal IP address that triggered these alerts. It's all on you now! You're expected to write up an incident report, so someone can track down the infected computer and put a stop to this nonsense!

The characteristics of your environment are:

- LAN segment range: `10.2.28.0/24` (10.2.28.0 through 10.2.28.255)
- Domain: `easyas123.tech`
- AD environment name: `EASYAS123`
- Active Directory (AD) domain controller: `10.2.28.2` - EASYAS123-DC
- LAN segment gateway: `10.2.28.1`
- LAN segment broadcast address: `10.2.28.255`

Armed with the pcap, the job was to find that infected host.

*Scenario and pcap source: [malware-traffic-analysis.net, 2026-02-28 — "Easy As 123"](https://www.malware-traffic-analysis.net/2026/02/28/index.html)*

## What I needed to find

1.  Infected internal IP address

2.  Hostname of the infected machine

3.  MAC address of the infected host

4.  Username of the infected system's user

5.  User's full name

6.  External IP the host was communicating with

7.  Protocol and port used

8.  Whether any additional malware/payload was downloaded

9.  Whether any other suspicious domains were contacted

10.  Indicators of Compromise (IOCs)



## Tools Used

- Wireshark




## Step 1: Don't jump straight to the suspicious IP

My first idea was to just filter on `ip.addr == 45.131.214.85` immediately. But that's tunnel vision — you only see what you already went looking for, you could miss other stuff happening on the host.

So I opened **Statistics > Endpoints** first instead, IPv4 tab, sorted by packets.


<img width="1012" height="747" alt="end" src="https://github.com/user-attachments/assets/34d3f628-f80f-4ae6-8970-2cd99034237b" />

`10.2.28.88` had way more traffic than anything else internal — 14,673 packets, next closest internal host (the DC) only had 5,069. And down in the list I could already see `45.131.214.85` with 550 packets, with way more bytes received than sent. That's already a small clue — looks like a C2 server pushing stuff down, not a normal two-way conversation.

## Step 2: Validate the alert

Filtered on the suspicious IP:

```
ip.addr == 45.131.214.85
```

<img width="1015" height="747" alt="filterip" src="https://github.com/user-attachments/assets/68ab9889-39a1-46ce-945b-81264f0a5027" />

`10.2.28.88` was the only internal host talking to it. First packet was a SYN, so that's where the conversation starts.

Big thing I noticed here: port is 443, which we expect to be HTTPS/TLS, but Protocol column says **HTTP**. Plain HTTP on the HTTPS port. That mismatch turned out to be one of the most useful things in this whole investigation.

## Step 3: Follow the stream

Right-clicked a POST packet, Follow > HTTP Stream.

<img width="1013" height="750" alt="httpstream" src="https://github.com/user-attachments/assets/bd115531-416e-4fe1-86be-806e33bf3166" />


This confirmed the malware — `User-Agent: NetSupport Manager/1.3`, server responding as `NetSupport Gateway/1.92 (Windows NT)`. Exact match to what the alert named.

Pattern in the stream:
- `CMD=POLL` — host asking "anything for me?"
- `CMD=ENCD` + a block of encoded data

Stream count was something like 264 packets from the client, 2 from the server. That ratio is what beaconing looks like — a machine checking in over and over, not a person doing something.

## Step 4: Finding the hostname

I had IP and MAC already from the endpoint stats. For the hostname, I filtered NBNS traffic sourced from the host and looked for the `<00>` suffix — that's the Workstation Service registration, which carries the actual machine name (as opposed to `<1d>`, which is a domain-level Local Master Browser registration).

```
nbns && ip.src == 10.2.28.88
```

<img width="1051" height="692" alt="hostname" src="https://github.com/user-attachments/assets/af46e853-7ee4-491d-9a6c-1da2481740f9" />


Found it: `DESKTOP-TEYQ2NR<00>`. That's the hostname.

## Step 5: Username and full name

Username came from Kerberos. Filtered on `kerberos`, opened a TGS-REQ packet, drilled into `req-body > cname > cname-string`. Got `brolf`.

Kerberos doesn't carry a display name though, only the account name. For the full name I needed something that actually queries the AD user object — that's SAMR.

```
samr
```

<img width="1061" height="705" alt="samrquery" src="https://github.com/user-attachments/assets/ba586fe9-8863-4162-83c1-5de005a3caf1" />


Found a `QueryUserInfo request` followed by a much bigger `QueryUserInfo response` (862 bytes vs 226 for the request — size difference made it obvious which one had the actual data).


Expanded the response, drilled through `Account Name > Full Name`, and there it was:

<img width="1057" height="707" alt="full name found" src="https://github.com/user-attachments/assets/3106fb7a-8728-4525-9ae0-258ba5e74d3f" />


**Full Name: Becka Rolf**

## Step 6: Did it download anything? Any other suspicious domains?

Wanted to rule this out rather than assume it.

**Checked for downloaded files** — File > Export Objects > HTTP.

<img width="1058" height="691" alt="exportobj" src="https://github.com/user-attachments/assets/7d93f4fb-6bf1-4aea-93a2-d8d323760cad" />


Only two things in the list: `connecttest.txt` (this is Microsoft's own built-in connectivity check, normal Windows background traffic, nothing to do with the infection) and a long list of `fakeurl.htm` — same beacon traffic I already saw in the stream. No `.exe`, no binary, nothing downloaded in this capture. So the RAT was already on the machine before this capture started — what I'm looking at is ongoing C2, not the actual infection happening.

**Checked DNS** — any other suspicious domains being contacted?

```
ip.addr == 10.2.28.88 && dns
```

<img width="1055" height="698" alt="dnsqueries" src="https://github.com/user-attachments/assets/32b2ff6d-9f8c-4537-b502-8ec26e2299f3" />


All of it was legitimate Microsoft stuff — `login.microsoftonline.com`, `settings-win.data.microsoft.com`, `v10.events.data.microsoft.com` — plus two WPAD lookups (`wpad.easyas123.tech`, `wpad.mshome.net`) that both came back "No such name," which is just normal Windows behavior, not a sign of a rogue proxy.

Nothing suspicious in DNS at all. Which also tells you something — the C2 channel itself never shows up in DNS, because it connects straight to a hardcoded IP. No domain to block, no domain to flag.


## My Findings

| Category | Detail |
|---|---|
| Infected IP | 10.2.28.88 |
| Hostname | DESKTOP-TEYQ2NR |
| MAC Address | 14:b3:1f:2d:ce:69 |
| Username | brolf |
| Full Name | Becka Rolf |
| C2 Server | 45.131.214.85 |
| Protocol/Port | Plain HTTP over TCP/443 (no TLS) |
| Malware | NetSupport Manager RAT |
| C2 pattern | CMD=POLL / CMD=ENCD beaconing |
| Anything downloaded | No — only beacon traffic, no payload in this capture |
| Other suspicious domains | None — all DNS was legitimate Microsoft traffic |


## IOCs

| Type | Value |
|---|---|
| IP | 45.131.214.85 |
| Port | TCP/443 (HTTP, not TLS) |
| URI | /fakeurl.htm |
| User-Agent | NetSupport Manager/1.3 |
| Server header | NetSupport Gateway/1.92 (Windows NT) |
| C2 strings | CMD=POLL, CMD=ENCD |

## My Recommendations

- Isolate DESKTOP-TEYQ2NR.
- Reset the `brolf` account's credentials.
- Block 45.131.214.85 at the firewall.
- Detect on HTTP traffic over port 443 that never does a TLS handshake — that mismatch was the clearest signal in the whole case.
- Figure out separately how NetSupport Manager got on the machine in the first place — nothing in this capture shows the actual infection happening, only the ongoing C2.



