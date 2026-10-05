import argparse
import logging
import os
import threading
import time

from . import config as C


def main():
    ap = argparse.ArgumentParser(prog="netwatch", description="Network traffic anomaly detector")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--iface", help="live capture on this interface (needs root/admin)")
    src.add_argument("--pcap", help="analyse a pcap file instead of sniffing")
    src.add_argument("--demo", action="store_true", help="synthetic traffic with injected anomalies (no root needed)")
    ap.add_argument("--host", default="127.0.0.1", help="dashboard bind address (no auth - keep it local)")
    ap.add_argument("--port", type=int, default=5000)
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

    if a.demo and "NW_DB" not in os.environ:
        C.DB_PATH = "netwatch_demo.db"
        if os.path.exists(C.DB_PATH):
            os.remove(C.DB_PATH)

    from .alerts import Notifier
    from .app import create_app
    from .db import DB
    from .engine import Engine

    db = DB()
    engine = Engine(db, Notifier(db))

    if a.demo:
        from .demo import run_demo
        run_demo(engine)
    elif a.pcap:
        from scapy.all import PcapReader
        with PcapReader(a.pcap) as r:
            for p in r:
                engine.process(p)
        engine.flush_now()
    else:
        from scapy.all import sniff

        def handler(p):
            try:
                engine.process(p)
            except Exception:
                logging.exception("packet processing failed")

        threading.Thread(target=lambda: sniff(iface=a.iface or C.IFACE, store=False, prn=handler),
                         daemon=True).start()

        def ticker():
            while True:
                time.sleep(C.WINDOW_SEC)
                engine.tick(time.time())
        threading.Thread(target=ticker, daemon=True).start()

    create_app(db).run(host=a.host, port=a.port, threaded=True)


if __name__ == "__main__":
    main()
