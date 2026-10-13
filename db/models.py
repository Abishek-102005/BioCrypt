"""
BioCrypt — SQLite Database Layer
"""
import sqlite3
import os
from datetime import datetime
from contextlib import contextmanager


DATABASE = None  # set by app.py after config is loaded


def set_database_path(path: str):
    global DATABASE
    DATABASE = path


@contextmanager
def get_db():
    """Context manager that yields a SQLite connection."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create all tables if they don't already exist."""
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT NOT NULL UNIQUE,
                email         TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                auth_mode     INTEGER NOT NULL DEFAULT 1,
                created_at    TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS activity_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL REFERENCES users(id),
                action     TEXT NOT NULL,
                filename   TEXT,
                status     TEXT NOT NULL DEFAULT 'success',
                timestamp  TEXT NOT NULL
            );
        """)


# ---------------------------------------------------------------------------
# User helpers
# ---------------------------------------------------------------------------

def create_user(username: str, email: str, password_hash: str) -> int:
    with get_db() as db:
        cur = db.execute(
            "INSERT INTO users (username, email, password_hash, auth_mode, created_at) "
            "VALUES (?, ?, ?, 1, ?)",
            (username, email, password_hash, datetime.utcnow().isoformat()),
        )
        return cur.lastrowid


def get_user_by_username(username: str):
    with get_db() as db:
        return db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()


def get_user_by_id(user_id: int):
    with get_db() as db:
        return db.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()


def update_password(user_id: int, new_hash: str):
    with get_db() as db:
        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (new_hash, user_id),
        )


def update_auth_mode(user_id: int, mode: int):
    with get_db() as db:
        db.execute(
            "UPDATE users SET auth_mode = ? WHERE id = ?",
            (mode, user_id),
        )


# ---------------------------------------------------------------------------
# Activity log helpers
# ---------------------------------------------------------------------------

def log_activity(user_id: int, action: str, filename: str = None, status: str = "success"):
    with get_db() as db:
        db.execute(
            "INSERT INTO activity_log (user_id, action, filename, status, timestamp) "
            "VALUES (?, ?, ?, ?, ?)",
            (user_id, action, filename, status, datetime.utcnow().isoformat()),
        )


def get_recent_activity(user_id: int, limit: int = 10) -> list:
    with get_db() as db:
        return db.execute(
            "SELECT * FROM activity_log WHERE user_id = ? "
            "ORDER BY timestamp DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()


def get_stats(user_id: int) -> dict:
    with get_db() as db:
        total = db.execute(
            "SELECT COUNT(*) as cnt FROM activity_log WHERE user_id = ?",
            (user_id,),
        ).fetchone()["cnt"]

        encrypted = db.execute(
            "SELECT COUNT(*) as cnt FROM activity_log "
            "WHERE user_id = ? AND action IN ('encrypt_file', 'encrypt_folder') AND status='success'",
            (user_id,),
        ).fetchone()["cnt"]

        decrypted = db.execute(
            "SELECT COUNT(*) as cnt FROM activity_log "
            "WHERE user_id = ? AND action IN ('decrypt_file', 'decrypt_folder') AND status='success'",
            (user_id,),
        ).fetchone()["cnt"]

    return {"total": total, "encrypted": encrypted, "decrypted": decrypted}
