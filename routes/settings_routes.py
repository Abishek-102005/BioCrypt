"""
BioCrypt — Settings Routes
"""
from flask import (
    Blueprint, render_template, request, session,
    redirect, url_for, flash, jsonify,
)
from auth.password_auth import hash_password, verify_password
from auth.biometric_auth import is_available as biometric_available, unavailable_reason
import db.models as db

settings_bp = Blueprint("settings", __name__)


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


@settings_bp.route("/settings")
@login_required
def settings_page():
    user = db.get_user_by_id(session["user_id"])
    activity = db.get_recent_activity(session["user_id"], limit=20)
    bio_available = biometric_available()
    bio_reason = unavailable_reason() if not bio_available else ""
    return render_template(
        "settings.html",
        user=user,
        activity=list(activity),
        bio_available=bio_available,
        bio_reason=bio_reason,
    )


@settings_bp.route("/api/settings/change-password", methods=["POST"])
@login_required
def api_change_password():
    data = request.get_json(silent=True) or {}
    current_pw = data.get("current_password", "")
    new_pw     = data.get("new_password", "")
    confirm    = data.get("confirm_password", "")

    user = db.get_user_by_id(session["user_id"])

    if not verify_password(current_pw, user["password_hash"]):
        return jsonify({"error": "Current password is incorrect."}), 400
    if len(new_pw) < 8:
        return jsonify({"error": "New password must be at least 8 characters."}), 400
    if new_pw != confirm:
        return jsonify({"error": "Passwords do not match."}), 400

    db.update_password(session["user_id"], hash_password(new_pw))
    db.log_activity(session["user_id"], "change_password", status="success")
    return jsonify({"message": "Password changed successfully."})


@settings_bp.route("/api/settings/auth-mode", methods=["POST"])
@login_required
def api_set_auth_mode():
    data = request.get_json(silent=True) or {}
    mode = int(data.get("mode", 1))

    if mode not in (1, 2, 3):
        return jsonify({"error": "Invalid authentication mode."}), 400

    if mode in (2, 3) and not biometric_available():
        return jsonify({
            "error": "Biometric authentication is not available on this system.",
            "reason": unavailable_reason(),
        }), 400

    db.update_auth_mode(session["user_id"], mode)
    db.log_activity(session["user_id"], f"set_auth_mode_{mode}", status="success")
    return jsonify({"message": f"Authentication mode set to {mode}."})
