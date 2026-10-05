"""Packet -> 10s window features -> baseline (EWMA z-score) + signature rules -> alerts."""
import ipaddress
import math
import threading
from collections import Counter, defaultdict, deque

from scapy.all import ARP, DHCP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether

from . import config as C

# Statistical metrics and the minimum absolute value before a spike is worth reporting
FLOORS = {"pps": 50, "bps": 50_000, "syn": 50, "dns": 50, "icmp": 20, "arp": 20}
# CDNs legitimately generate lots of unique subdomains
DNS_ALLOW = {"akamaiedge.net", "akadns.net", "cloudfront.net", "amazonaws.com",
             "googleusercontent.com", "azureedge.net", "local", "arpa"}
SLD = {"co", "com", "org", "net", "gov", "ac"}


def is_private(ip):
    try:
        return ip != "0.0.0.0" and ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in Counter(s).values())


class EWMA:
    """Exponentially weighted mean/variance - the learned 'normal' for one metric."""

    def __init__(self, alpha=0.05):
        self.a, self.mean, self.var, self.n = alpha, 0.0, 0.0, 0

    def update(self, x):
        if self.n == 0:
            self.mean = x
        else:
            d = x - self.mean
            self.mean += self.a * d
            self.var = (1 - self.a) * (self.var + self.a * d * d)
        self.n += 1

    def z(self, x):
        std = max(math.sqrt(self.var), 0.1 * abs(self.mean), 1.0)  # floor avoids absurd z on flat links
        return (x - self.mean) / std


class Window:
    def __init__(self, start):
        self.start = start
        self.pkts = self.bytes = self.icmp = self.arp = self.dns = self.syn_total = 0
        self.ports = defaultdict(set)   # (src, dst) -> ports probed
        self.hosts = defaultdict(set)   # src -> LAN hosts SYN'd
        self.syn_dst = Counter()        # dst -> SYN count
        self.arp_replies = Counter()    # mac -> ARP replies
        self.out = Counter()            # (lan_src, public_dst) -> bytes
        self.dns_q = {}                 # base domain -> {src, subs, ent}
        self.macs = {}                  # mac -> ip seen this window
        self.beacon_keys = set()


class Engine:
    def __init__(self, db, notifier):
        self.db, self.notifier = db, notifier
        self.lock = threading.RLock()
        self.win = None
        self.base = {m: EWMA() for m in FLOORS}
        self.windows_seen = db.window_count()
        self.streak = 0
        self.devices = {d["mac"] for d in db.devices()}
        self.arp_table = {}                       # ip -> mac
        self.dhcp_servers = set()
        self.beacons = defaultdict(lambda: deque(maxlen=20))
        self.beacon_alerted = {}
        for w in db.baseline_windows():           # warm the baseline after a restart
            for k in FLOORS:
                self.base[k].update(w[k])

    @property
    def learning(self):
        return self.windows_seen < C.LEARN_WINDOWS

    def _emit(self, ts, kind, sev, src, detail):
        self.notifier.handle(ts, kind, sev, src, detail)

    # ---------------------------------------------------------------- windows
    def _roll(self, ts):
        sec = C.WINDOW_SEC
        if self.win is None:
            self.win = Window(ts - ts % sec)
            return
        if ts - self.win.start > 100 * sec:       # long capture gap: flush once, jump ahead
            self._flush(self.win)
            self.win = Window(ts - ts % sec)
            return
        while ts >= self.win.start + sec:
            self._flush(self.win)
            self.win = Window(self.win.start + sec)

    def tick(self, now):
        """Called by a timer in live mode so quiet networks still close windows."""
        with self.lock:
            if self.win is not None:
                self._roll(now)

    def flush_now(self):
        with self.lock:
            if self.win is not None:
                self._flush(self.win)
                self.win = None

    # ---------------------------------------------------------------- packets
    def process(self, pkt):
        ts = float(pkt.time)
        with self.lock:
            self._roll(ts)
            w, n = self.win, len(pkt)
            w.pkts += 1
            w.bytes += n

            if Ether in pkt:
                lan_ip = pkt[IP].src if IP in pkt else (pkt[ARP].psrc if ARP in pkt else None)
                if lan_ip and is_private(lan_ip):
                    w.macs[pkt[Ether].src] = lan_ip

            if IP in pkt:
                src, dst = pkt[IP].src, pkt[IP].dst
                if is_private(src) and not is_private(dst) and not ipaddress.ip_address(dst).is_multicast:
                    w.out[(src, dst)] += n
                if TCP in pkt:
                    if int(pkt[TCP].flags) & 0x12 == 0x02:      # pure SYN
                        w.syn_total += 1
                        w.syn_dst[dst] += 1
                        w.ports[(src, dst)].add(pkt[TCP].dport)
                        if is_private(dst):
                            w.hosts[src].add(dst)
                        else:
                            self._beacon(src, dst, pkt[TCP].dport, ts)
                elif UDP in pkt:
                    w.ports[(src, dst)].add(pkt[UDP].dport)
                elif ICMP in pkt and pkt[ICMP].type == 8:
                    w.icmp += 1
                if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
                    self._dns(w, src, pkt[DNSQR].qname)
                if pkt.haslayer(DHCP):
                    self._dhcp(ts, pkt)

            if ARP in pkt:
                self._arp(ts, w, pkt[ARP])

    def _beacon(self, src, dst, dport, ts):
        if len(self.beacons) > 5000:
            self.beacons.clear()
        self.beacons[(src, dst, dport)].append(ts)
        self.win.beacon_keys.add((src, dst, dport))

    def _dns(self, w, src, qname):
        labels = qname.decode(errors="ignore").rstrip(".").lower().split(".")
        if len(labels) < 3:
            return
        k = 3 if (labels[-2] in SLD and len(labels[-1]) == 2) else 2   # naive eTLD+1 (co.uk etc.)
        base, sub = ".".join(labels[-k:]), ".".join(labels[:-k])
        if not sub:
            return
        w.dns += 1
        d = w.dns_q.setdefault(base, {"src": src, "subs": set(), "ent": []})
        if sub not in d["subs"]:
            d["subs"].add(sub)
            d["ent"].append(entropy(sub.replace(".", "")))

    def _arp(self, ts, w, a):
        w.arp += 1
        if a.psrc != "0.0.0.0":
            old = self.arp_table.get(a.psrc)
            if old and old != a.hwsrc:
                self._emit(ts, "ARP_SPOOF", "critical", a.hwsrc,
                           f"{a.psrc} was {old}, now claimed by {a.hwsrc} (possible man-in-the-middle)")
            self.arp_table[a.psrc] = a.hwsrc
        if a.op == 2:
            w.arp_replies[a.hwsrc] += 1

    def _dhcp(self, ts, pkt):
        opts = {o[0]: o[1] for o in pkt[DHCP].options if isinstance(o, tuple) and len(o) >= 2}
        if opts.get("message-type") == 2:         # DHCPOFFER
            srv = pkt[IP].src
            if srv not in self.dhcp_servers:
                if self.dhcp_servers and not self.learning:
                    self._emit(ts, "ROGUE_DHCP", "high", srv, f"DHCP offer from unknown server {srv}")
                self.dhcp_servers.add(srv)

    # ------------------------------------------------------------------ flush
    def _flush(self, w):
        sec, end = C.WINDOW_SEC, w.start + C.WINDOW_SEC
        m = {"pps": w.pkts / sec, "bps": w.bytes / sec, "syn": w.syn_total,
             "dns": w.dns, "icmp": w.icmp, "arp": w.arp}
        found = []

        def add(kind, sev, src, detail):
            found.append((kind, sev, src, detail))

        # --- signature rules
        for (s, d), ports in w.ports.items():
            if len(ports) >= C.PORTSCAN_PORTS:
                add("PORT_SCAN", "high", s, f"{s} probed {len(ports)} ports on {d} in {sec}s")
        for s, hosts in w.hosts.items():
            if len(hosts) >= C.SWEEP_HOSTS:
                add("HOST_SWEEP", "high", s, f"{s} contacted {len(hosts)} different LAN hosts in {sec}s")
        for d, c in w.syn_dst.items():
            if c >= C.SYN_FLOOD:
                add("SYN_FLOOD", "high", d, f"{c} SYN packets towards {d} in {sec}s")
        if w.icmp >= C.ICMP_FLOOD:
            add("ICMP_FLOOD", "medium", "multiple", f"{w.icmp} ICMP echo requests in {sec}s")
        for mac, c in w.arp_replies.items():
            if c >= C.ARP_FLOOD:
                add("ARP_FLOOD", "high", mac, f"{c} ARP replies from {mac} in {sec}s (ARP poisoning / scan)")
        for (s, d), b in w.out.items():
            if b >= C.EXFIL_BYTES:
                add("DATA_EXFIL", "high", s, f"{b / 1e6:.1f} MB sent from {s} to {d} in {sec}s")
        for base, d in w.dns_q.items():
            if base in DNS_ALLOW or base.rsplit(".", 1)[-1] in DNS_ALLOW:
                continue
            n = len(d["subs"])
            avg_ent = sum(d["ent"]) / n
            avg_len = sum(len(x) for x in d["subs"]) / n
            if n >= C.DNS_SUBDOMAINS or (n >= 5 and avg_ent >= C.DNS_ENTROPY and avg_len >= 20):
                add("DNS_TUNNEL", "high", d["src"],
                    f"{n} unique subdomains of {base} (avg entropy {avg_ent:.1f}, avg length {avg_len:.0f})")
        for key in w.beacon_keys:
            ts_list = list(self.beacons[key])
            if len(ts_list) < C.BEACON_MIN_EVENTS or end - self.beacon_alerted.get(key, 0) < 1800:
                continue
            iv = [b - a for a, b in zip(ts_list, ts_list[1:])]
            mean = sum(iv) / len(iv)
            if 5 <= mean <= 900:
                cv = math.sqrt(sum((x - mean) ** 2 for x in iv) / len(iv)) / mean
                if cv <= C.BEACON_MAX_CV:
                    self.beacon_alerted[key] = end
                    add("BEACONING", "high", key[0],
                        f"{key[0]} -> {key[1]}:{key[2]} every {mean:.0f}s (jitter {cv:.0%}) - possible C2")

        # --- statistical anomalies vs. learned baseline
        if not self.learning:
            for k, v in m.items():
                z = self.base[k].z(v)
                if z >= C.Z_THRESHOLD and v >= FLOORS[k]:
                    add(f"SPIKE_{k.upper()}", "medium", "network",
                        f"{k} = {v:.0f} (baseline {self.base[k].mean:.0f}, z = {z:.1f})")
            if self.base["pps"].mean >= 20 and m["pps"] < 0.1 * self.base["pps"].mean:
                add("TRAFFIC_DROP", "medium", "network",
                    f"traffic fell to {m['pps']:.0f} pkt/s (baseline {self.base['pps'].mean:.0f})")

        # --- bookkeeping
        anomalous = bool(found)
        if self.learning or not anomalous or self.streak > 20:   # don't let attacks poison the baseline
            for k, v in m.items():
                self.base[k].update(v)
        self.streak = self.streak + 1 if anomalous else 0
        for mac, ip in w.macs.items():
            if mac not in self.devices:
                self.devices.add(mac)
                if not self.learning:
                    self._emit(end, "NEW_DEVICE", "medium", mac, f"unknown device {mac} ({ip}) appeared on the network")
            self.db.upsert_device(mac, ip, w.start)
        self.windows_seen += 1
        self.db.add_window(w.start, m, anomalous)
        for kind, sev, src, detail in found:
            self._emit(end, kind, sev, src, detail)
