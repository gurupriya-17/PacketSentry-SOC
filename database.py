import sqlite3
import json
from pathlib import Path

DB_PATH = Path("packetsentry.db")

def _connect():
    return sqlite3.connect(DB_PATH)

def save_records(df, alerts):
    with _connect() as con:
        df.to_sql("packets", con, if_exists="append", index=False)
        con.execute("CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, alert_json TEXT NOT NULL)")
        con.executemany("INSERT INTO alerts(alert_json) VALUES (?)", [(json.dumps(a, default=str),) for a in alerts])

def load_records():
    if not DB_PATH.exists():
        return None
    with _connect() as con:
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        packets = con.execute("SELECT COUNT(*) FROM packets").fetchone()[0] if "packets" in tables else 0
        alerts = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] if "alerts" in tables else 0
    return {"packets": packets, "alerts": alerts}

def clear_records():
    if DB_PATH.exists():
        DB_PATH.unlink()
