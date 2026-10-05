import logging
import threading
import time

import requests

from . import config as C

log = logging.getLogger("netwatch.alerts")
SEV = {"low": 0, "medium": 1, "high": 2, "critical": 3}
NTFY_PRIO = {"low": "2", "medium": "3", "high": "4", "critical": "5"}


class Notifier:
    """Stores every alert in SQLite; pushes to the phone with per-(kind, source) cooldown."""

    def __init__(self, db):
        self.db = db
        self.last = {}

    def handle(self, ts, kind, severity, src, detail):
        notified = 0
        key, now = (kind, src), time.time()
        enabled = C.NTFY_URL or (C.TELEGRAM_TOKEN and C.TELEGRAM_CHAT_ID)
        if (enabled and SEV[severity] >= SEV.get(C.NOTIFY_MIN_SEVERITY, 1)
                and now - self.last.get(key, 0) > C.NOTIFY_COOLDOWN):
            self.last[key] = now
            notified = 1
            threading.Thread(target=self._push, args=(kind, severity, src, detail), daemon=True).start()
        self.db.add_alert(ts, kind, severity, src, detail, notified)
        log.warning("[%s] %s %s - %s", severity.upper(), kind, src, detail)

    def _push(self, kind, severity, src, detail):
        title = f"NetWatch {severity.upper()}: {kind}"
        body = f"{detail}\nSource: {src}"
        try:
            if C.NTFY_URL:  # https://ntfy.sh - free push notifications, no account needed
                requests.post(C.NTFY_URL, data=body.encode("utf-8"), timeout=5, headers={
                    "Title": title, "Priority": NTFY_PRIO[severity],
                    "Tags": "rotating_light" if SEV[severity] >= 2 else "warning"})
            if C.TELEGRAM_TOKEN and C.TELEGRAM_CHAT_ID:
                requests.post(f"https://api.telegram.org/bot{C.TELEGRAM_TOKEN}/sendMessage", timeout=5,
                              json={"chat_id": C.TELEGRAM_CHAT_ID, "text": f"{title}\n{body}"})
        except requests.RequestException as e:
            log.error("push failed: %s", e)
