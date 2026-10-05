"""Synthetic traffic: builds packets in memory (nothing is sent on the wire) and feeds the engine.

Timeline (10s windows): 0-31 normal, then one anomaly every few windows so every detector fires.
"""
import random
import string
import time

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw

GW = ("192.168.1.1", "aa:aa:aa:00:00:01")
HOSTS = [(f"192.168.1.{i}", f"02:00:00:00:00:{i:02x}") for i in range(10, 15)]
ATTACKER = ("192.168.1.99", "02:00:00:00:00:63")
SITES = ["142.250.74.46", "151.101.1.69", "104.16.132.229", "13.107.42.14"]
NAMES = ["www.google.com", "github.com", "www.youtube.com", "outlook.office.com"]
WINDOWS = 70


def _p(t, pkt):
    pkt.time = t
    return pkt


def _normal(t):
    out = []
    for ip, mac in HOSTS:
        for _ in range(random.randint(1, 3)):
            site, sp, tt = random.choice(SITES), random.randint(40000, 60000), t + random.random() * 8
            base = Ether(src=mac, dst=GW[1]) / IP(src=ip, dst=site)
            out.append(_p(tt, base / TCP(sport=sp, dport=443, flags="S")))
            for k in range(random.randint(5, 15)):
                out.append(_p(tt + 0.01 * (k + 1), base / TCP(sport=sp, dport=443, flags="A") / Raw(b"x" * random.randint(200, 1400))))
        q = Ether(src=mac, dst=GW[1]) / IP(src=ip, dst=GW[0]) / UDP(sport=random.randint(40000, 60000), dport=53)
        out.append(_p(t + random.random() * 9, q / DNS(rd=1, qd=DNSQR(qname=random.choice(NAMES)))))
    out.append(_p(t + 1, Ether(src=GW[1]) / ARP(op=2, psrc=GW[0], hwsrc=GW[1], pdst=HOSTS[0][0])))
    return out


def _attack(i, t):
    out = []
    rnd = lambda n: "".join(random.choices(string.ascii_lowercase + string.digits, k=n))
    if i == 32:   # port scan from a brand new device
        for k, port in enumerate(range(1, 101)):
            out.append(_p(t + 3 + k * 0.01, Ether(src=ATTACKER[1]) / IP(src=ATTACKER[0], dst=HOSTS[0][0]) / TCP(sport=44444, dport=port, flags="S")))
    elif i == 36:  # ARP spoofing: attacker claims the gateway's IP
        out.append(_p(t + 2, Ether(src=ATTACKER[1]) / ARP(op=2, psrc=GW[0], hwsrc=ATTACKER[1], pdst=HOSTS[1][0])))
    elif i == 40:  # DNS tunnelling
        for k in range(60):
            q = Ether(src=HOSTS[2][1]) / IP(src=HOSTS[2][0], dst=GW[0]) / UDP(sport=50000 + k, dport=53)
            out.append(_p(t + 1 + k * 0.1, q / DNS(rd=1, qd=DNSQR(qname=f"{rnd(32)}.tunnel-c2.example"))))
    elif i == 44:  # SYN flood from spoofed sources
        for k in range(400):
            src = ".".join(str(random.randint(11, 220)) for _ in range(4))
            out.append(_p(t + 2 + k * 0.01, Ether(src=GW[1]) / IP(src=src, dst=HOSTS[0][0]) / TCP(sport=random.randint(1024, 65000), dport=80, flags="S")))
    elif i == 48:  # data exfiltration (~25 MB to one external IP)
        for k in range(400):
            out.append(_p(t + 1 + k * 0.01, Ether(src=HOSTS[3][1]) / IP(src=HOSTS[3][0], dst="34.201.15.80") / TCP(sport=51000, dport=443, flags="A") / Raw(b"x" * 64000)))
    elif i == 66:  # ICMP flood
        for k in range(150):
            out.append(_p(t + 1 + k * 0.02, Ether(src=ATTACKER[1]) / IP(src=ATTACKER[0], dst=HOSTS[0][0]) / ICMP(type=8)))
    if 52 <= i <= 63:  # C2 beacon: one SYN every 10s with ~2% jitter
        out.append(_p(t + 5 + random.uniform(-0.1, 0.1), Ether(src=HOSTS[4][1]) / IP(src=HOSTS[4][0], dst="52.14.200.9") / TCP(sport=random.randint(40000, 60000), dport=443, flags="S")))
    return out


def run_demo(engine):
    t0 = int(time.time() // 10 * 10) - WINDOWS * 10
    for i in range(WINDOWS):
        t = t0 + i * 10
        for pkt in sorted(_normal(t) + _attack(i, t), key=lambda p: p.time):
            engine.process(pkt)
    engine.flush_now()
