# 🔍 Network Traffic Analysis — RedLine Stealer Investigation

> **Analyst:** Chukwuemeka Oko  
> **Date:** March 30, 2026  
> **Source:** [Malware-Traffic-Analysis.net](https://malware-traffic-analysis.net) — Exercise 2024-10-23  
> **Tools Used:** Wireshark · Zui (Brim) · VirusTotal  
> **Malware Family:** RedLine Stealer  

---

## 📌 Project Overview

This project documents a full **network traffic forensic investigation** performed on a real-world malware PCAP file sourced from Malware-Traffic-Analysis.net. The goal was to identify the infected victim machine, the attacker's Command-and-Control (C2) infrastructure, the initial infection file, and the full scope of data that was stolen.

This was completed as part of a hands-on cybersecurity learning exercise using industry-standard tools: **Wireshark** for deep packet inspection and **Zui/Brim** for rapid traffic querying.

---

## 🧰 Tools & Environment

| Tool | Purpose |
|------|---------|
| **Wireshark** | Deep packet inspection, TCP stream analysis, HTTP object export |
| **Zui (Brim)** | Fast PCAP querying using Zeek log format |
| **VirusTotal** | Threat intelligence validation of IP addresses |
| **7-Zip / WinRAR** | Extracting password-protected malware archives |

---

## 📁 Files in This Repository

```
📂 redline-stealer-investigation/
├── 📄 README.md                  ← This file
├── 📄 incident-report.md         ← Full written incident summary
├── 📂 screenshots/
│   ├── 01-zui-victim-ip.png      ← Victim IP discovered in Zui
│   ├── 02-zui-dns-queries.png    ← DNS activity in Zui
│   ├── 03-wireshark-http.png     ← HTTP POST traffic to C2
│   ├── 04-tcp-stream-check.png   ← CheckConnect C2 handshake
│   ├── 05-tcp-stream-victim.png  ← MachineName + Public IP in stream
│   ├── 06-tcp-stream-exfil.png   ← SetEnvironment data exfiltration
│   └── 07-virustotal-c2.png      ← VirusTotal C2 IP confirmation
```

---

## 🔎 Investigation Methodology

### Phase 1 — Zui/Brim (Rapid Triage)

Imported the PCAP into Zui and ran structured queries to quickly identify the key players in the traffic before going into deep inspection.

**Query 1 — Find the Victim IP:**
```
_path=="conn" | count() by id.orig_h | sort -r count
```
> Result: `10.10.23.101` had the highest outbound connection count → confirmed victim

**Query 2 — Find DNS Activity:**
```
_path=="dns" | count() by query | sort -r count
```
> Result: Query to `api.ip.sb` detected — used by malware to discover public IP

**Query 3 — Find HTTP Downloads:**
```
_path=="http" | cut ts, id.orig_h, host, uri, resp_mime_types
```
> Result: HTTP POST requests to `188.190.10.10:55123` identified

---

### Phase 2 — Wireshark (Deep Inspection)

Opened the same PCAP in Wireshark and applied display filters to focus on relevant traffic.

**Filter 1 — Isolate HTTP traffic:**
```
http
```

**Filter 2 — Isolate victim traffic:**
```
ip.src == 10.10.23.101
```

**Filter 3 — Follow C2 conversation:**
> Right-click packet to `188.190.10.10` → Follow → TCP Stream

This revealed the full SOAP/XML conversation between the malware and the C2 server, including all three stages: `CheckConnect`, `EnvironmentSettings`, and `SetEnvironment`.

---

## 🧾 Findings Summary

### 🖥️ Victim Machine

| Detail | Value |
|--------|-------|
| Internal IP | `10.10.23.101` |
| Public IP | `173.66.46.112` |
| Machine Name | `user1` |
| MAC Address | `00:08:02:1c:47:ae` |
| Hardware ID | `AB19D0C6238A3F7F9AA2AF4B49C50704` |
| Device Brand | Hewlett-Packard |
| OS Language | English (United States) |
| Country | United States |

---

### 🎯 Attacker Infrastructure

| Detail | Value |
|--------|-------|
| C2 IP Address | `188.190.10.10` |
| C2 Port | `55123` (non-standard) |
| Protocol | HTTP over SOAP/XML |
| Server Software | Microsoft-HTTPAPI/2.0 |
| C2 Domain | None — direct IP communication |

> **Note:** No domain name was used. The malware communicated directly with a hardcoded IP address, which is consistent with some RedLine Stealer variants.

---

### 📁 Infection Vector

| Detail | Value |
|--------|-------|
| Delivery File | `QUOTATION_08670.TAR` |
| Actual Format | RAR archive (file extension mismatch) |
| Payload Inside | `QUOTATION#08670.exe` (915 KB) |
| Disguise Technique | Fake business quotation document |
| Execution Method | Process injection into `RegSvcs.exe` |

---

### ⏱️ Attack Timeline

| Time (UTC) | Event |
|------------|-------|
| Before capture | Victim executed `QUOTATION#08670.exe` |
| **19:15:32** | Malware connects to C2 — `CheckConnect` handshake |
| **19:15:37** | C2 sends steal instructions — `EnvironmentSettings` |
| **19:15:38** | Malware queries `api.ip.sb` for victim's public IP |
| **19:15:48** | ~2.7 MB of stolen data uploaded — `SetEnvironment` |

---

### 🕵️ Data Exfiltrated

The C2 instructed the malware to steal the following — all confirmed in the `EnvironmentSettings` XML response:

- ✅ Browser credentials & cookies (40+ browsers including Chrome, Firefox, Edge, Brave)
- ✅ Discord tokens
- ✅ FTP credentials  
- ✅ Local files matching `*.txt`, `*.doc`, `*wallet*`, `*seed*`
- ✅ Screenshot of victim's screen
- ✅ Steam session data
- ✅ Telegram session data
- ✅ VPN credentials
- ✅ Cryptocurrency wallets and seed phrases

---

## 🔑 Key Technical Observations

### 1. SOAP/XML C2 Protocol
RedLine Stealer used SOAP (Simple Object Access Protocol) over HTTP to communicate with its C2 server. This is a format normally used by legitimate enterprise software, making the traffic harder to flag as suspicious at first glance.

The three SOAP actions observed were:
- `CheckConnect` — initial malware check-in
- `EnvironmentSettings` — receiving steal configuration
- `SetEnvironment` — uploading stolen data

### 2. Process Injection
The malware injected itself into `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe` — a legitimate signed Windows binary — to evade antivirus detection.

### 3. File Extension Mismatch
The delivery archive was named `.TAR` but was actually a RAR file. This tricks both human victims and automated scanners that rely on file extensions for classification.

### 4. Public IP Discovery
The malware reached out to `api.ip.sb` (via HTTPS to `104.26.13.31`) to discover and report the victim's real public IP address to the attacker.

---

## 🌍 Historical Context

> On **October 28, 2024** — just **five days after this infection** — international law enforcement including the **FBI**, **Dutch National Police**, and **Eurojust** dismantled the RedLine Stealer operation in a coordinated global action called **Operation Magnus**. This exercise captures one of the final waves of RedLine activity before the takedown.

---

## 📸 Screenshots

> *Place your 7 screenshots in the `/screenshots/` folder and they will render here.*

### Screenshot 1 — Zui: Victim IP Discovery
![Zui Victim IP](screenshots/01-zui-victim-ip.png)

### Screenshot 2 — Zui: DNS Query Activity  
![Zui DNS](screenshots/02-zui-dns-queries.png)

### Screenshot 3 — Wireshark: HTTP Traffic to C2
![Wireshark HTTP](screenshots/03-wireshark-http.png)

### Screenshot 4 — Wireshark: TCP Stream — CheckConnect
![TCP CheckConnect](screenshots/04-tcp-stream-check.png)

### Screenshot 5 — Wireshark: TCP Stream — Victim Details
![TCP Victim Details](screenshots/05-tcp-stream-victim.png)

### Screenshot 6 — Wireshark: TCP Stream — Data Exfiltration
![TCP Exfil](screenshots/06-tcp-stream-exfil.png)

### Screenshot 7 — VirusTotal: C2 IP Confirmed Malicious
![VirusTotal](screenshots/07-virustotal-c2.png)

---

## ✅ Recommended Response Actions

1. **Isolate** `10.10.23.101` from the network immediately
2. **Block** IP `188.190.10.10` at the firewall
3. **Reset ALL passwords** — all browser-saved credentials are compromised
4. **Revoke** any crypto wallet seed phrases on the machine
5. **Revoke** Discord, Steam, and Telegram sessions
6. **Scan** the full `10.10.23.0/24` subnet for similar indicators
7. **Educate** users about fake invoice/quotation email lures

---

## 📚 What I Learned

- How to perform structured triage on a PCAP file using Zui/Brim
- How to use Wireshark display filters and TCP stream following
- How to identify SOAP/XML-based C2 communication patterns
- How process injection is used by malware to evade detection
- How to validate threat intelligence using VirusTotal
- How to write a professional Incident Summary Report

---

## 🔗 References

- [Malware-Traffic-Analysis.net — Exercise 2024-10-23](https://malware-traffic-analysis.net/2024/10/23/index.html)
- [VirusTotal — 188.190.10.10](https://www.virustotal.com/gui/ip-address/188.190.10.10)
- [Operation Magnus — RedLine Takedown (Oct 2024)](https://www.europol.europa.eu/media-press/newsroom/news/international-operation-takes-down-redline-and-meta-infostealers)
- [Wireshark Official Documentation](https://www.wireshark.org/docs/)
- [Zui (Brim) Documentation](https://zui.brimdata.io/docs/)

---

*This project was completed as part of a self-directed cybersecurity learning path focused on network forensics and malware traffic analysis.*
