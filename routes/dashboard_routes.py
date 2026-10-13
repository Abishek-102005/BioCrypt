"""
BioCrypt — Dashboard Route
"""
from flask import Blueprint, render_template, session, redirect, url_for, jsonify
import db.models as db
from auth.biometric_auth import is_available as biometric_available

dashboard_bp = Blueprint("dashboard", __name__)


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


@dashboard_bp.route("/dashboard")
@login_required
def dashboard():
    user = db.get_user_by_id(session["user_id"])
    stats = db.get_stats(session["user_id"])
    activity = db.get_recent_activity(session["user_id"], limit=8)
    bio_available = biometric_available()
    return render_template(
        "dashboard.html",
        user=user,
        stats=stats,
        activity=list(activity),
        bio_available=bio_available,
    )


@dashboard_bp.route("/api/stats")
@login_required
def api_stats():
    stats = db.get_stats(session["user_id"])
    return jsonify(stats)
