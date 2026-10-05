"""All tunables, overridable with environment variables (NW_*)."""
import os


def _i(k, d): return int(os.getenv(k, d))
def _f(k, d): return float(os.getenv(k, d))


IFACE = os.getenv("NW_IFACE") or None
DB_PATH = os.getenv("NW_DB", "netwatch.db")

WINDOW_SEC = _i("NW_WINDOW", 10)        # aggregation window
LEARN_WINDOWS = _i("NW_LEARN", 30)      #windows used to learn the baseline
Z_THRESHOLD = _f("NW_Z", 4.0)           # z-score needed for a statistical spike

# Rule thresholds (per window)
PORTSCAN_PORTS = _i("NW_PORTSCAN_PORTS", 20)   # distinct ports on one host from one source
SWEEP_HOSTS = _i("NW_SWEEP_HOSTS", 15)         # distinct LAN hosts probed by one source
SYN_FLOOD = _i("NW_SYN_FLOOD", 200)            # SYNs towards one destination
ICMP_FLOOD = _i("NW_ICMP_FLOOD", 100)          # echo requests
ARP_FLOOD = _i("NW_ARP_FLOOD", 30)             # ARP replies from one MAC
DNS_SUBDOMAINS = _i("NW_DNS_SUBDOMAINS", 30)   # unique subdomains of one domain
DNS_ENTROPY = _f("NW_DNS_ENTROPY", 3.6)        # avg Shannon entropy of subdomain labels
EXFIL_BYTES = _i("NW_EXFIL_BYTES", 20_000_000) # LAN -> internet bytes to one IP
BEACON_MIN_EVENTS = _i("NW_BEACON_MIN", 8)
BEACON_MAX_CV = _f("NW_BEACON_CV", 0.15)       # interval jitter (std/mean) below this = too regular

# Phone alerts
NTFY_URL = os.getenv("NTFY_URL")               # e.g. https://ntfy.sh/my-secret-topic
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
NOTIFY_MIN_SEVERITY = os.getenv("NW_NOTIFY_MIN", "medium")  # low|medium|high|critical
NOTIFY_COOLDOWN = _i("NW_COOLDOWN", 300)       # seconds between pushes for the same (kind, source)
