import sqlite3
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB = BASE_DIR / "ghostkey.db"

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.executescript("""
    CREATE TABLE IF NOT EXISTS cards (
        uid TEXT PRIMARY KEY,
        owner TEXT NOT NULL,
        status TEXT DEFAULT 'active',
        main_gate INTEGER DEFAULT 1,
        server_room INTEGER DEFAULT 0,
        future_card INTEGER DEFAULT 0,
        created_at REAL NOT NULL
    );

    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        node_id TEXT NOT NULL,
        uid TEXT NOT NULL,
        ts REAL NOT NULL,
        verdict TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        reason TEXT NOT NULL,
        direction TEXT NOT NULL,
        request_id TEXT
    );

    CREATE TABLE IF NOT EXISTS nonces_seen (
        nonce TEXT PRIMARY KEY,
        ts REAL NOT NULL
    );

    CREATE TABLE IF NOT EXISTS fail_counts (
        node_id TEXT PRIMARY KEY,
        count INTEGER DEFAULT 0,
        locked_until REAL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS presence (
        uid TEXT PRIMARY KEY,
        owner TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'OUTSIDE',
        entered_at REAL,
        exited_at REAL,
        last_node TEXT
    );

    CREATE TABLE IF NOT EXISTS exit_armed (
        uid TEXT PRIMARY KEY,
        armed_at REAL NOT NULL
    );

    CREATE TABLE IF NOT EXISTS pending_server (
        request_id TEXT PRIMARY KEY,
        uid TEXT NOT NULL,
        node_id TEXT NOT NULL,
        created_at REAL NOT NULL,
        expires_at REAL NOT NULL,
        status TEXT NOT NULL DEFAULT 'PENDING',
        reason TEXT DEFAULT ''
    );
    """)

    # Safe column migrations if database already existed
    try:
        c.execute("ALTER TABLE cards ADD COLUMN future_card INTEGER DEFAULT 0")
    except Exception:
        pass

    now = time.time()
    # Default Authorized Card E2E93719 (Main Gate + Server Room)
    c.execute("""
    INSERT INTO cards (uid, owner, status, main_gate, server_room, future_card, created_at)
    VALUES ('E2E93719', 'Authorized User 1', 'active', 1, 1, 0, ?)
    ON CONFLICT(uid) DO UPDATE SET
        status='active',
        main_gate=1,
        server_room=1
    """, (now,))

    # Second Authorized Card (Main Gate Only)
    c.execute("""
    INSERT INTO cards (uid, owner, status, main_gate, server_room, future_card, created_at)
    VALUES ('031459AD', 'Authorized User 2 (Main Gate Only)', 'active', 1, 0, 0, ?)
    ON CONFLICT(uid) DO UPDATE SET
        status='active',
        main_gate=1,
        server_room=0
    """, (now,))

    c.execute("INSERT OR IGNORE INTO fail_counts (node_id, count, locked_until) VALUES ('NODE_A', 0, 0)")
    c.execute("INSERT OR IGNORE INTO fail_counts (node_id, count, locked_until) VALUES ('NODE_B', 0, 0)")

    conn.commit()
    conn.close()

    print("======================================")
    print(" CYPHER GHOST KEY DATABASE INITIALIZED")
    print("======================================")
    print("Database:", DB)
    print("Default Authorized Cards:")
    print("  E2E93719 -> Authorized for Main Gate + Server Room")
    print("  031459AD -> Authorized for Main Gate Only")
    print("======================================")

if __name__ == "__main__":
    init_db()