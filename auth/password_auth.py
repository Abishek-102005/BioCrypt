"""
BioCrypt — Password Authentication
Handles password hashing and verification using bcrypt.
"""
import bcrypt


def hash_password(password: str) -> str:
    """
    Hash *password* with bcrypt (work factor 12).

    Returns
    -------
    str
        bcrypt hash string, safe to store in the database.
    """
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))
    return hashed.decode("utf-8")


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verify *password* against *stored_hash*.

    Never logs the plaintext password or the hash.

    Returns
    -------
    bool
        True if password matches, False otherwise.
    """
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"),
            stored_hash.encode("utf-8"),
        )
    except Exception:
        return False


def password_strength(password: str) -> dict:
    """
    Return a simple strength assessment for client-side feedback.

    Returns
    -------
    dict
        {"score": 0-4, "label": str, "hints": [str]}
    """
    hints = []
    score = 0

    if len(password) >= 8:
        score += 1
    else:
        hints.append("Use at least 8 characters.")

    if any(c.isupper() for c in password):
        score += 1
    else:
        hints.append("Add an uppercase letter.")

    if any(c.isdigit() for c in password):
        score += 1
    else:
        hints.append("Add a number.")

    if any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in password):
        score += 1
    else:
        hints.append("Add a special character.")

    labels = {0: "Very Weak", 1: "Weak", 2: "Fair", 3: "Strong", 4: "Very Strong"}
    return {"score": score, "label": labels[score], "hints": hints}
