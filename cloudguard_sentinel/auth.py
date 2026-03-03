from werkzeug.security import generate_password_hash, check_password_hash
from models import get_db, get_user_by_username
from datetime import datetime, timedelta
import sqlite3

def register_user(username, password, role='user'):
    conn = get_db()
    try:
        conn.execute(
            'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
            (username, generate_password_hash(password), role)
        )
        conn.commit()
        return True, "User registered successfully."
    except sqlite3.IntegrityError:
        return False, "Username already exists."
    finally:
        conn.close()

def authenticate_user(username, password):
    user = get_user_by_username(username)
    if not user:
        return None, "Invalid credentials."

    # Check account lockout
    locked_until = user.get('locked_until')
    if locked_until:
        try:
            lock_dt = datetime.fromisoformat(locked_until)
            if datetime.utcnow() < lock_dt:
                remaining = int((lock_dt - datetime.utcnow()).total_seconds() / 60) + 1
                return None, f"Account locked. Try again in {remaining} minute(s)."
        except Exception:
            pass

    if not check_password_hash(user['password_hash'], password):
        # Increment failed attempts
        new_fails = (user.get('failed_attempts') or 0) + 1
        lock_time = None
        if new_fails >= 5:
            lock_time = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
        conn = get_db()
        conn.execute(
            "UPDATE users SET failed_attempts=?, locked_until=? WHERE username=?",
            (new_fails, lock_time, username)
        )
        conn.commit()
        conn.close()
        attempts_left = max(0, 5 - new_fails)
        if lock_time:
            return None, "Too many failed attempts. Account locked for 15 minutes."
        return None, f"Invalid credentials. {attempts_left} attempt(s) remaining."

    # Reset on successful login
    conn = get_db()
    conn.execute(
        "UPDATE users SET failed_attempts=0, locked_until=NULL WHERE username=?",
        (username,)
    )
    conn.commit()
    conn.close()
    return user, "Login successful."

def seed_default_users():
    if not get_user_by_username('admin'):
        register_user('admin', 'Admin@1234', role='admin')
    if not get_user_by_username('alice'):
        register_user('alice', 'Alice@1234', role='user')
    if not get_user_by_username('bob'):
        register_user('bob', 'Bob@1234', role='user')
