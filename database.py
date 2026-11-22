import sqlite3
from contextlib import contextmanager

from config import DATABASE_PATH, DATA_DIR


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS peers (
    node_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    hostname TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    port INTEGER NOT NULL,
    scheme TEXT NOT NULL,
    public_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    trusted INTEGER NOT NULL DEFAULT 0,
    last_seen REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS transfers (
    id TEXT PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    peer_id TEXT,
    direction TEXT NOT NULL,
    filename TEXT NOT NULL,
    size INTEGER NOT NULL,
    content_type TEXT NOT NULL,
    status TEXT NOT NULL,
    payload_path TEXT NOT NULL,
    wrapped_key TEXT,
    nonce TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS settings (
    user_id INTEGER NOT NULL REFERENCES users(id),
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (user_id, key)
);
CREATE TABLE IF NOT EXISTS activities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_transfers_owner_date ON transfers(owner_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_activities_user_date ON activities(user_id, created_at DESC);
"""


def connect():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection


@contextmanager
def transaction():
    connection = connect()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = connect()
    try:
        connection.executescript(SCHEMA)
    finally:
        connection.close()
