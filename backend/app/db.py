import os
import sqlite3
from contextlib import contextmanager

from .security import hash_password


def db_path() -> str:
    return os.getenv("DB_PATH", "soc.db")


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def get_db():
    conn = connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('analyst','admin'))
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                dest_ip TEXT,
                signature TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'new',
                score INTEGER NOT NULL,
                mitre_id TEXT,
                mitre_name TEXT,
                raw TEXT
            );
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
                author TEXT NOT NULL,
                text TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
            """
        )
        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            admin_pw = os.getenv("ADMIN_PASSWORD", "admin123")
            analyst_pw = os.getenv("ANALYST_PASSWORD", "analyst123")
            db.execute("INSERT INTO users VALUES (?,?,?)", ("admin", hash_password(admin_pw), "admin"))
            db.execute("INSERT INTO users VALUES (?,?,?)", ("analyst", hash_password(analyst_pw), "analyst"))
