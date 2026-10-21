"""SQLite 存储：风险事件、每日流量、决策审计。"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,
    level TEXT,
    score INTEGER,
    title TEXT,
    detail TEXT,
    process TEXT,
    pid INTEGER,
    app TEXT,
    ip TEXT,
    port INTEGER,
    country_iso TEXT,
    country_cn TEXT,
    action TEXT,
    state TEXT,
    extra TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT,
    decision TEXT,
    ts REAL,
    operator TEXT
);
CREATE TABLE IF NOT EXISTS traffic_daily (
    day TEXT NOT NULL,
    rx INTEGER DEFAULT 0,
    tx INTEGER DEFAULT 0,
    PRIMARY KEY (day)
);
"""


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False, timeout=10)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            # 兼容 1.x/2.0 旧库：补 app 列
            try:
                self._conn.execute("ALTER TABLE events ADD COLUMN app TEXT")
            except sqlite3.OperationalError:
                pass
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except Exception:  # noqa: BLE001
                pass

    # ---------------------------------------------------------------- 事件
    def add_event(self, ev: Dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO events "
                "(id,ts,kind,level,score,title,detail,process,pid,app,ip,port,country_iso,country_cn,action,state,extra) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    ev["id"], ev["ts"], ev.get("kind", ""), ev.get("level", ""), ev.get("score", 0),
                    ev.get("title", ""), ev.get("detail", ""), ev.get("process", ""), ev.get("pid", 0),
                    ev.get("app", ""),
                    ev.get("ip", ""), ev.get("port", 0), ev.get("country_iso", ""),
                    ev.get("country_cn", ""), ev.get("action", ""), ev.get("state", ""),
                    json.dumps(ev.get("extra") or {}, ensure_ascii=False),
                ),
            )
            self._conn.commit()

    def update_event_state(self, event_id: str, state: str, action: Optional[str] = None) -> None:
        with self._lock:
            if action:
                self._conn.execute("UPDATE events SET state=?, action=? WHERE id=?", (state, action, event_id))
            else:
                self._conn.execute("UPDATE events SET state=? WHERE id=?", (state, event_id))
            self._conn.commit()

    def list_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute("SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,))
            out = []
            for row in cur.fetchall():
                d = dict(row)
                try:
                    d["extra"] = json.loads(d.get("extra") or "{}")
                except Exception:  # noqa: BLE001
                    d["extra"] = {}
                out.append(d)
            return out

    def add_decision(self, event_id: str, decision: str, operator: str = "机主") -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO decisions (event_id, decision, ts, operator) VALUES (?,?,?,?)",
                (event_id, decision, time.time(), operator),
            )
            self._conn.commit()

    # ---------------------------------------------------------------- 流量
    def add_traffic(self, day: str, rx: int, tx: int) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO traffic_daily (day, rx, tx) VALUES (?,?,?) "
                "ON CONFLICT(day) DO UPDATE SET rx=rx+excluded.rx, tx=tx+excluded.tx",
                (day, int(rx), int(tx)),
            )
            self._conn.commit()

    def traffic_history(self, days: int = 14) -> List[Dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT day, rx, tx FROM traffic_daily ORDER BY day DESC LIMIT ?", (days,)
            )
            return [dict(r) for r in cur.fetchall()]

    def prune(self, keep_days: int = 30) -> None:
        cutoff = time.time() - keep_days * 86400
        with self._lock:
            self._conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
            self._conn.commit()
