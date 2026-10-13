"""
WebAuthn credential helper functions for BioCrypt.
"""
from .models import get_db

def _ensure_table(db):
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS webauthn_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            credential_id BLOB UNIQUE NOT NULL,
            public_key BLOB NOT NULL,
            sign_count INTEGER NOT NULL,
            transports TEXT
        )
        """
    )

def add_webauthn_credential(user_id: int, credential_id: bytes, public_key: bytes, sign_count: int = 0, transports: str = None):
    """Insert a new WebAuthn credential into the database.
    Table is created on first use.
    """
    with get_db() as db:
        _ensure_table(db)
        db.execute(
            "INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, transports) VALUES (?, ?, ?, ?, ?)",
            (user_id, credential_id, public_key, sign_count, transports),
        )

def get_webauthn_credentials_by_user(user_id: int):
    """Return all credentials for a given user."""
    with get_db() as db:
        _ensure_table(db)
        return db.execute(
            "SELECT * FROM webauthn_credentials WHERE user_id = ?", (user_id,)
        ).fetchall()

def get_webauthn_credential_by_id(credential_id: bytes):
    """Return a credential row by its credential_id."""
    with get_db() as db:
        _ensure_table(db)
        return db.execute(
            "SELECT * FROM webauthn_credentials WHERE credential_id = ?", (credential_id,)
        ).fetchone()

def update_webauthn_sign_count(credential_id: bytes, new_sign_count: int):
    """Update the sign_count for a stored credential."""
    with get_db() as db:
        _ensure_table(db)
        db.execute(
            "UPDATE webauthn_credentials SET sign_count = ? WHERE credential_id = ?", (new_sign_count, credential_id)
        )
