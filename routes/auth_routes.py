"""
BioCrypt — Auth Routes  (login, register, logout)
"""
import re
import sqlite3
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

        if db.get_user_by_email(email):
            flash("An account with this email already exists.", "error")
            return render_template("login.html", tab="register")

        try:
            user_id = db.create_user(username, email, hash_password(password))
        except sqlite3.IntegrityError:
            flash("Username or email already in use. Please try another.", "error")
            return render_template("login.html", tab="register")

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


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if "user_id" in session:
        return redirect(url_for("dashboard.dashboard"))

    step = request.args.get("step", "1")

    if request.method == "POST":
        step = request.form.get("step", "1")

        # ── Step 1: verify username + email ─────────────────────────────
        if step == "1":
            username = request.form.get("username", "").strip()
            email    = request.form.get("email", "").strip()

            user = db.get_user_by_username(username)
            if not user or user["email"].lower() != email.lower():
                flash("No account found with that username and email.", "error")
                return render_template("forgot_password.html", step="1")

            # Store verified user id in session temporarily
            session["reset_user_id"] = user["id"]
            return render_template("forgot_password.html", step="2")

        # ── Step 2: set new password ─────────────────────────────────────
        elif step == "2":
            reset_uid = session.get("reset_user_id")
            if not reset_uid:
                flash("Session expired. Please start again.", "error")
                return render_template("forgot_password.html", step="1")

            password = request.form.get("password", "")
            confirm  = request.form.get("confirm_password", "")

            if len(password) < 8:
                flash("Password must be at least 8 characters.", "error")
                return render_template("forgot_password.html", step="2")
            if password != confirm:
                flash("Passwords do not match.", "error")
                return render_template("forgot_password.html", step="2")

            db.update_password(reset_uid, hash_password(password))
            db.log_activity(reset_uid, "password_reset")
            session.pop("reset_user_id", None)
            flash("Password reset successfully! Please sign in.", "success")
            return redirect(url_for("auth.login"))

    return render_template("forgot_password.html", step=step)


@auth_bp.route("/api/password-strength", methods=["POST"])
def api_password_strength():
    data = request.get_json(silent=True) or {}
    pw = data.get("password", "")
    return jsonify(password_strength(pw))
