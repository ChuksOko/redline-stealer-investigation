# Incident Report — RedLine Stealer Infection
**Analyst:** Chukwuemeka Oko  
**Date:** March 30, 2026  
**Source:** Malware-Traffic-Analysis.net (Exercise: 2024-10-23)  
**Malware Family:** RedLine Stealer  

---

## 1. Overview

This investigation analyzed a packet capture (PCAP) containing malicious network traffic. The analysis revealed a RedLine Stealer infection, where the victim system executed a malicious file disguised as a business quotation and established communication with a Command-and-Control (C2) server, resulting in active data exfiltration of approximately 2.7 MB of sensitive user data.

---

## 2. Victim (Infected Machine)

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

📸 *[Screenshot 1 — Zui: Victim IP Discovery]*

---

## 3. Attacker (C2 Infrastructure)

| Detail | Value |
|--------|-------|
| C2 IP Address | `188.190.10.10` |
| Port | `55123` |
| Protocol | HTTP (SOAP/XML-based communication) |
| Server | Microsoft-HTTPAPI/2.0 |
| Secondary IP | `104.26.13.31` (api.ip.sb — victim IP lookup) |

**Note on C2 Domain:** No C2 domain was identified. The malware communicated directly with the C2 IP address (`188.190.10.10`), which is consistent with some RedLine Stealer variants that hardcode the C2 IP directly into the binary rather than using a resolvable domain name.

📸 *[Screenshot 3 — Wireshark HTTP view showing POST traffic to C2]*  
📸 *[Screenshot 4 — TCP Stream showing CheckConnect handshake]*

---

## 4. Initial Infection Vector

| Detail | Value |
|--------|-------|
| Delivery Archive | `QUOTATION_08670.TAR` |
| Actual Format | RAR archive (deliberate file extension mismatch) |
| Malware Executable | `QUOTATION#08670.exe` (915 KB) |
| Execution Path | `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe` |
| Technique | Process Injection into legitimate Windows process |

The archive used a **file extension mismatch** — named `.TAR` but was actually a RAR file. This is a deliberate technique used to confuse both victims and automated security scanners that rely on file extensions for classification.

---

## 5. Attack Timeline

| Time (UTC) | Event |
|------------|-------|
| Before capture | Victim executed malicious file `QUOTATION#08670.exe` |
| 19:15:32 | Initial C2 connection — `CheckConnect` handshake confirmed |
| 19:15:37 | C2 issued steal instructions — `EnvironmentSettings` received |
| 19:15:38 | Malware queried `api.ip.sb` to discover victim's public IP |
| 19:15:48 | Data exfiltration — ~2.7 MB uploaded via `SetEnvironment` |

📸 *[Screenshot 4 — TCP Stream: CheckConnect]*  
📸 *[Screenshot 5 — TCP Stream: MachineName + IPv4 values]*  
📸 *[Screenshot 6 — TCP Stream: SetEnvironment with Content-Length: 2786973]*

---

## 6. Data Exfiltration

The C2 server instructed the malware to steal the following categories of data, all confirmed via the `EnvironmentSettings` XML response in the TCP stream:

| Category | Stolen |
|----------|--------|
| Browser credentials & cookies (Chrome, Firefox, Edge, Brave + 36 others) | ✅ |
| Discord tokens | ✅ |
| FTP credentials | ✅ |
| Local files matching `*.txt`, `*.doc`, `*wallet*`, `*seed*` | ✅ |
| Screenshot of victim's screen | ✅ |
| Steam session data | ✅ |
| Telegram session data | ✅ |
| VPN credentials | ✅ |
| Cryptocurrency wallets and seed phrases | ✅ |

Total data exfiltrated: **~2.7 MB** (`Content-Length: 2786973`)

📸 *[Screenshot 6 — SetEnvironment payload upload evidence]*

---

## 7. Supporting Evidence

### DNS Activity
- Query to `api.ip.sb` observed — used by the malware to discover and report the victim's public IP address to the C2. This is a documented RedLine Stealer behaviour pattern.

📸 *[Screenshot 2 — Zui DNS queries]*

### Threat Intelligence Validation
- IP `188.190.10.10` confirmed malicious via VirusTotal external threat intelligence.

📸 *[Screenshot 7 — VirusTotal result for 188.190.10.10]*

---

## 8. Conclusion

The investigation confirms that host `10.10.23.101` (machine name: `user1`) was infected with **RedLine Stealer** via execution of a malicious file disguised as a business quotation archive. The malware injected itself into the legitimate Windows process `RegSvcs.exe` to evade detection, established communication with a remote C2 server at `188.190.10.10:55123` using SOAP/XML protocol, and successfully exfiltrated approximately **2.7 MB of sensitive user data** including browser credentials, cryptocurrency wallets, and session tokens.

The communication pattern, payload structure, and SOAP-based C2 protocol observed are fully consistent with documented RedLine Stealer behaviour as confirmed by multiple threat intelligence sources.

**Historical Note:** The RedLine Stealer operation was dismantled by international law enforcement — including the FBI, Dutch National Police, and Eurojust — on **October 28, 2024**, just **five days after this infection occurred**, in a global operation named **Operation Magnus**.

---

## 9. Recommended Response Actions

1. Isolate `10.10.23.101` from the network immediately
2. Block IP `188.190.10.10` at the firewall on all ports
3. Reset ALL passwords for user `user1` — all browser-saved credentials are compromised
4. Revoke any cryptocurrency wallet seed phrases stored on the machine
5. Revoke Discord, Steam, and Telegram sessions
6. Scan all machines on the `10.10.23.0/24` subnet for similar indicators
7. Educate users about fake invoice/quotation email lures
