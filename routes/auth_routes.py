"""
BioCrypt — Auth Routes  (login, register, logout)
"""
import re
from flask import (
    Blueprint, render_template, request, redirect,
    url_for, session, flash, jsonify,
)
from auth.password_auth import hash_password, verify_password, password_strength
import db.models as db

auth_bp = Blueprint("auth", __name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _validate_registration(username, email, password, confirm):
    errors = []
    if not re.match(r"^[A-Za-z0-9_]{3,32}$", username):
        errors.append("Username must be 3‑32 alphanumeric characters or underscores.")
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        errors.append("Enter a valid email address.")
    if len(password) < 8:
        errors.append("Password must be at least 8 characters.")
    if password != confirm:
        errors.append("Passwords do not match.")
    return errors


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@auth_bp.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard.dashboard"))
    return render_template("index.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = db.get_user_by_username(username)
        # Generic error to prevent username enumeration
        if not user or not verify_password(password, user["password_hash"]):
            flash("Invalid username or password.", "error")
            return render_template("login.html", tab="login")

        session.permanent = True
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        db.log_activity(user["id"], "login")
        return redirect(url_for("dashboard.dashboard"))

    return render_template("login.html", tab="login")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        errors = _validate_registration(username, email, password, confirm)
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("login.html", tab="register")

        if db.get_user_by_username(username):
            flash("Username already taken.", "error")
            return render_template("login.html", tab="register")

        user_id = db.create_user(username, email, hash_password(password))
        session.permanent = True
        session["user_id"] = user_id
        session["username"] = username
        db.log_activity(user_id, "register")
        flash("Account created! Welcome to BioCrypt.", "success")
        return redirect(url_for("dashboard.dashboard"))

    return render_template("login.html", tab="register")


@auth_bp.route("/logout")
def logout():
    user_id = session.get("user_id")
    if user_id:
        db.log_activity(user_id, "logout")
    session.clear()
    return redirect(url_for("auth.index"))


@auth_bp.route("/api/password-strength", methods=["POST"])
def api_password_strength():
    data = request.get_json(silent=True) or {}
    pw = data.get("password", "")
    return jsonify(password_strength(pw))
