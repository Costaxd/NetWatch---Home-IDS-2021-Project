import sqlite3
import threading

from . import config as C

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS windows(
  ts REAL PRIMARY KEY, pps REAL, bps REAL, syn INTEGER, dns INTEGER,
  icmp INTEGER, arp INTEGER, anomalous INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, severity TEXT,
  src TEXT, detail TEXT, notified INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE TABLE IF NOT EXISTS devices(
  mac TEXT PRIMARY KEY, ip TEXT, first_seen REAL, last_seen REAL);
"""


class DB:
    """Thread-safe wrapper (sniffer, ticker and Flask all share one connection)."""

    def __init__(self, path=None):
        self.conn = sqlite3.connect(path or C.DB_PATH, check_same_thread=False)
        self.lock = threading.Lock()
        with self.lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    def _exec(self, sql, args=()):
        with self.lock:
            self.conn.execute(sql, args)
            self.conn.commit()

    def _query(self, sql, args=()):
        with self.lock:
            cur = self.conn.execute(sql, args)
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]

    # writes
    def add_window(self, ts, m, anomalous):
        self._exec("INSERT OR REPLACE INTO windows VALUES(?,?,?,?,?,?,?,?)",
                   (ts, m["pps"], m["bps"], m["syn"], m["dns"], m["icmp"], m["arp"], int(anomalous)))

    def add_alert(self, ts, kind, severity, src, detail, notified):
        self._exec("INSERT INTO alerts(ts,kind,severity,src,detail,notified) VALUES(?,?,?,?,?,?)",
                   (ts, kind, severity, src, detail, notified))

    def upsert_device(self, mac, ip, ts):
        self._exec("""INSERT INTO devices VALUES(?,?,?,?)
                      ON CONFLICT(mac) DO UPDATE SET ip=COALESCE(excluded.ip, ip), last_seen=excluded.last_seen""",
                   (mac, ip, ts, ts))

    # reads
    def recent_windows(self, minutes=30):
        return self._query("""SELECT * FROM windows
                              WHERE ts >= (SELECT COALESCE(MAX(ts),0) FROM windows) - ? ORDER BY ts""",
                           (minutes * 60,))

    def baseline_windows(self, limit=500):
        return self._query("SELECT * FROM windows WHERE anomalous=0 ORDER BY ts DESC LIMIT ?", (limit,))[::-1]

    def window_count(self):
        return self._query("SELECT COUNT(*) n FROM windows")[0]["n"]

    def alerts(self, limit=100):
        return self._query("SELECT * FROM alerts ORDER BY ts DESC, id DESC LIMIT ?", (limit,))

    def devices(self):
        return self._query("SELECT * FROM devices ORDER BY last_seen DESC")

    def summary(self):
        sev = {r["severity"]: r["n"] for r in
               self._query("SELECT severity, COUNT(*) n FROM alerts GROUP BY severity")}
        kinds = self._query("SELECT kind, COUNT(*) n FROM alerts GROUP BY kind ORDER BY n DESC LIMIT 8")
        n = self.window_count()
        return {"windows": n, "devices": len(self.devices()), "learning": n < C.LEARN_WINDOWS,
                "learn_target": C.LEARN_WINDOWS, "by_severity": sev, "by_kind": kinds,
                "alerts_total": sum(sev.values())}
