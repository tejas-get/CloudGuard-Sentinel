import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), 'database.db')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            is_suspicious INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            role TEXT,
            timestamp TEXT,
            ip_address TEXT,
            user_agent TEXT,
            endpoint TEXT,
            method TEXT,
            status_code INTEGER,
            hour_of_day INTEGER,
            day_of_week INTEGER,
            is_off_hours INTEGER DEFAULT 0,
            device_type TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS anomaly_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id INTEGER,
            username TEXT,
            timestamp TEXT,
            isolation_score REAL,
            rule_flags TEXT,
            risk_level TEXT,
            details TEXT,
            FOREIGN KEY(log_id) REFERENCES access_logs(id)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            timestamp TEXT,
            risk_level TEXT,
            message TEXT,
            acknowledged INTEGER DEFAULT 0
        )
    ''')

    # Safe column additions — skip if already exist
    safe_alters = [
        "ALTER TABLE users ADD COLUMN totp_secret TEXT DEFAULT NULL",
        "ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN locked_until TEXT DEFAULT NULL",
        "ALTER TABLE access_logs ADD COLUMN country TEXT DEFAULT NULL",
        "ALTER TABLE access_logs ADD COLUMN city TEXT DEFAULT NULL",
        "ALTER TABLE access_logs ADD COLUMN region TEXT DEFAULT NULL",
    ]
    for sql in safe_alters:
        try:
            c.execute(sql)
        except Exception:
            pass  # Column already exists, skip silently

    conn.commit()
    conn.close()

def get_user_by_username(username):
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return dict(user) if user else None

def get_user_by_id(user_id):
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return dict(user) if user else None

def get_all_users():
    conn = get_db()
    users = conn.execute('SELECT id, username, role, is_suspicious, created_at FROM users').fetchall()
    conn.close()
    return [dict(u) for u in users]

def delete_user(user_id):
    conn = get_db()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

def mark_user_suspicious(username):
    conn = get_db()
    conn.execute('UPDATE users SET is_suspicious = 1 WHERE username = ?', (username,))
    conn.commit()
    conn.close()

def get_all_logs(limit=200):
    conn = get_db()
    logs = conn.execute(
        'SELECT * FROM access_logs ORDER BY id DESC LIMIT ?', (limit,)
    ).fetchall()
    conn.close()
    return [dict(l) for l in logs]

def get_logs_for_user(username, limit=50):
    conn = get_db()
    rows = conn.execute(
        'SELECT * FROM access_logs WHERE username=? ORDER BY id DESC LIMIT ?',
        (username, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_all_anomalies(limit=200):
    conn = get_db()
    rows = conn.execute(
        'SELECT * FROM anomaly_scores ORDER BY id DESC LIMIT ?', (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_all_alerts(limit=100):
    conn = get_db()
    rows = conn.execute(
        'SELECT * FROM alerts ORDER BY id DESC LIMIT ?', (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_unacknowledged_alerts():
    conn = get_db()
    rows = conn.execute(
        'SELECT * FROM alerts WHERE acknowledged = 0 ORDER BY id DESC'
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def acknowledge_alert(alert_id):
    conn = get_db()
    conn.execute('UPDATE alerts SET acknowledged = 1 WHERE id = ?', (alert_id,))
    conn.commit()
    conn.close()
