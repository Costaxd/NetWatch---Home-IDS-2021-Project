# NetWatch---Home-IDS-2021-Project
A small network traffic anomaly detector from 2021. It sniffs packets with **Scapy**, learns what normal looks like, flags suspicious behaviour, stores everything in **SQLite**, shows it on a **Flask** dashboard and pushes alerts to your **phone**.


## What it detects

Signature rules: port scan, host sweep, SYN flood, ICMP flood, ARP spoofing, ARP flood, rogue DHCP server, new device, DNS tunnelling, C2 beaconing, bulk data exfiltration.
Statistical baseline: spikes in packets/s, bytes/s, SYN, DNS, ICMP and ARP rates, and sudden traffic collapse.

See **[docs/ANOMALIES.md](docs/ANOMALIES.md)** for what normal traffic looks like, the full anomaly catalogue, and what's still on the roadmap.

## Quick start

```bash
git clone <your-repo-url> && cd netwatch
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 1. Try it without root: synthetic traffic with every anomaly injected (nothing is sent on the network)
python -m netwatch --demo          # then open http://127.0.0.1:5000

# 2. Analyse a capture
python -m netwatch --pcap capture.pcap

# 3. Live monitoring (needs root/admin; on Windows install Npcap)
sudo .venv/bin/python -m netwatch --iface eth0
```

The dashboard has no authentication and binds to `127.0.0.1` by default. Put it behind a reverse proxy with auth or a VPN before exposing it.

## Phone alerts

**ntfy (easiest, free, no account):**
1. Install the *ntfy* app (Android / iOS).
2. Subscribe to a long random topic name, e.g. `netwatch-9f3k2x7q`.
3. Run NetWatch with:
   ```bash
   export NTFY_URL=https://ntfy.sh/netwatch-9f3k2x7q
   ```

**Telegram:** create a bot with @BotFather, then set `TELEGRAM_TOKEN` and `TELEGRAM_CHAT_ID`.

Pushes are sent for severity `medium` and above, at most once per 5 minutes per (alert type, source). Every alert is always stored in SQLite and shown on the dashboard. Tip: run `--demo` with `NTFY_URL` set to test that your phone gets the notifications.

## Configuration

All settings are environment variables (see `netwatch/config.py`):

| Variable | Default | Meaning |
|---|---|---|
| `NW_IFACE` | auto | Interface to sniff |
| `NW_DB` | `netwatch.db` | SQLite file |
| `NW_WINDOW` | 10 | Window length in seconds |
| `NW_LEARN` | 30 | Windows used for learning before statistical alerts start |
| `NW_Z` | 4.0 | z-score threshold for spikes |
| `NW_PORTSCAN_PORTS` / `NW_SWEEP_HOSTS` | 20 / 15 | Scan thresholds per window |
| `NW_SYN_FLOOD` / `NW_ICMP_FLOOD` / `NW_ARP_FLOOD` | 200 / 100 / 30 | Flood thresholds per window |
| `NW_EXFIL_BYTES` | 20000000 | Bytes LAN → one external IP per window |
| `NW_NOTIFY_MIN` | `medium` | Minimum severity for phone pushes |
| `NW_COOLDOWN` | 300 | Seconds between repeated pushes |

## Project layout

```
netwatch/
  engine.py      packet parsing, windows, baseline, all detectors
  db.py          SQLite schema and queries
  alerts.py      ntfy / Telegram notifier with cooldown
  app.py         Flask JSON API
  templates/     dashboard
  demo.py        synthetic traffic with injected anomalies
  __main__.py    CLI
docs/ANOMALIES.md
```

## Limitations

- Window-based detection means alerts arrive up to one window (10 s) late; ARP spoofing and rogue DHCP are reported instantly.
- The baseline is global, not per host or per hour of the week. A per-device, time-aware baseline (and an Isolation Forest on flow features) is the obvious next step.
- No IPv6 or deep TLS analysis yet.
- Thresholds are tuned for a home or small office LAN. Tune them for yours.

## Legal note

Only monitor networks you own or are explicitly authorised to monitor. Capturing traffic on someone else's network may be illegal.
