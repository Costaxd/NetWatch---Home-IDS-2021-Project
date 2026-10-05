# What is "normal", and what is not

NetWatch works on two ideas: **signatures** (behaviour that is almost never legitimate) and **baselines** (behaviour that is only suspicious *for this network*). ✅ = implemented, 🗺️ = roadmap.

## 1. What normal looks like

A healthy home or office network has a stable fingerprint:

| Property | Typical normal behaviour |
|---|---|
| Volume | Pkt/s and bytes/s follow a daily rhythm (quiet at night, busy during work) with moderate random variation |
| Connections | Many short TCP flows to well-known ports (443, 80), mostly to a small, repeating set of CDNs and cloud services |
| Fan-out | A host talks to a handful of LAN peers, mainly the gateway, DNS server and printers/NAS |
| DNS | Mostly A/AAAA queries for readable names; a few unique subdomains per domain; low-entropy labels (`www`, `mail`, `api`) |
| ARP | A few requests per host, one stable IP-to-MAC mapping per device |
| DHCP | One server (usually the router) |
| Devices | Same set of MACs, new ones appear rarely (guests, new phone) |
| Timing | Human-driven, irregular. Machine traffic (NTP, updates) is periodic but well-known |
| Direction | Downloads far exceed uploads from LAN hosts |

NetWatch learns the numeric part of this with an EWMA mean/variance per metric (pps, bytes/s, SYN, DNS, ICMP, ARP per 10 s window). Windows flagged as anomalous are **not** fed back into the baseline, so an attack can't teach the detector that it is normal.

## 2. Anomaly catalogue

### Reconnaissance
| Anomaly | What it looks like | Status | Notes / false positives |
|---|---|---|---|
| Port scan (vertical) | One source sends SYN/UDP to ≥20 different ports of one host in seconds | ✅ `PORT_SCAN` | Vulnerability scanners, your own nmap |
| Host sweep (horizontal) | One source contacts ≥15 different LAN hosts | ✅ `HOST_SWEEP` | Network discovery tools, printers' discovery |
| Stealth scans | NULL / FIN / Xmas flags, SYN with unusual options | 🗺️ | Invalid flag combos never occur in normal TCP |
| ARP scan | One host ARPs for every address in the subnet | ✅ via `ARP_FLOOD` / `SPIKE_ARP` | |

### Denial of service
| Anomaly | What it looks like | Status |
|---|---|---|
| SYN flood | Hundreds of SYNs per window to one destination, few completions, often spoofed sources | ✅ `SYN_FLOOD` (grouped by *destination*, so spoofed sources don't hide it) |
| ICMP flood / smurf | Hundreds of echo requests per window | ✅ `ICMP_FLOOD` |
| UDP flood / amplification | Huge UDP volume, responses far larger than requests (DNS, NTP, memcached) | ✅ partly via `SPIKE_PPS`/`SPIKE_BPS`; 🗺️ ratio check |
| Volume spike | pps or bytes/s far above baseline | ✅ `SPIKE_PPS`, `SPIKE_BPS` |
| Traffic collapse | Traffic drops to <10 % of baseline (outage, link attack, dead sensor) | ✅ `TRAFFIC_DROP` |

### Layer 2 / local network attacks
| Anomaly | What it looks like | Status |
|---|---|---|
| ARP spoofing / MITM | An IP suddenly claimed by a different MAC (often the gateway) | ✅ `ARP_SPOOF` (critical) |
| ARP flood / poisoning | One MAC sends dozens of ARP replies per window | ✅ `ARP_FLOOD` |
| Rogue DHCP server | DHCPOFFER from a server never seen before | ✅ `ROGUE_DHCP` |
| New / unknown device | A MAC never seen during learning appears | ✅ `NEW_DEVICE` |
| MAC flooding, VLAN hopping | Thousands of new source MACs, double-tagged frames | 🗺️ |

### DNS abuse
| Anomaly | What it looks like | Status |
|---|---|---|
| DNS tunnelling / exfil | Many unique, long, high-entropy subdomains of one domain (`a8f3k2....evil.example`) | ✅ `DNS_TUNNEL` (count and entropy) |
| DGA malware | Bursts of NXDOMAIN for random-looking domains | 🗺️ |
| DNS hijack | Answers from an unexpected resolver, TTLs of 0 | 🗺️ |

### Command and control, exfiltration
| Anomaly | What it looks like | Status |
|---|---|---|
| Beaconing | Same host to the same external IP:port at fixed intervals (5 s – 15 min) with <15 % jitter | ✅ `BEACONING` |
| Bulk exfiltration | Tens of MB from one LAN host to one external IP in a single window | ✅ `DATA_EXFIL` |
| Slow exfil | Small uploads, steady, for days | 🗺️ per-host long-term baseline |
| Unusual destinations | First contact with a new country/ASN, Tor exit nodes | 🗺️ |

### Lateral movement and credential attacks
| Anomaly | What it looks like | Status |
|---|---|---|
| Internal fan-out on admin ports | One host opens SMB (445), RDP (3389), SSH (22), WinRM to many peers | ✅ partly via `HOST_SWEEP`; 🗺️ port-specific rule |
| Brute force | Dozens of short connections to one auth port (22, 3389, 21) | 🗺️ |
| Cleartext legacy protocols | Telnet, FTP, plain HTTP login | 🗺️ |

### Protocol and context anomalies
| Anomaly | Status |
|---|---|
| Malformed packets, odd TTLs, heavy fragmentation, overlapping fragments | 🗺️ |
| TLS oddities: self-signed certs, rare JA3 fingerprints, SNI/IP mismatch | 🗺️ |
| Time-of-day: heavy traffic from a device at 03:00 when it's normally idle | 🗺️ hour-of-week baseline |

## 3. Tuning and false positives

- **Learning period**: statistical alerts start after `NW_LEARN` windows (default 30 × 10 s = 5 min). Use at least a few hours on a real network for a decent baseline.
- Backups, game downloads and speed tests *will* trigger `SPIKE_*` or `DATA_EXFIL`. Raise `NW_EXFIL_BYTES` / `NW_Z` if that annoys you.
- Legitimate periodic traffic (a chat app polling every 30 s) can look like beaconing. Check the destination before panicking.
- A replaced device that takes over an IP with a new MAC produces one `ARP_SPOOF`. Real attacks usually repeat.
- DNS tunnelling uses a naive registered-domain split; add noisy CDN domains to `DNS_ALLOW` in `engine.py`.
