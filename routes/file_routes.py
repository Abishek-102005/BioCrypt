"""
BioCrypt — File Encrypt / Decrypt Routes
"""
import io
from flask import (
    Blueprint, render_template, request, session,
    redirect, url_for, send_file, flash, jsonify,
)
from services.file_service import encrypt_file, decrypt_file
from crypto.encryption import DecryptionError
import db.models as db

files_bp = Blueprint("files", __name__)


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Encrypt
# ---------------------------------------------------------------------------

@files_bp.route("/encrypt", methods=["GET"])
@login_required
def encrypt_page():
    return render_template("encrypt.html")


@files_bp.route("/api/encrypt", methods=["POST"])
@login_required
def api_encrypt():
    if "file" not in request.files:
        return jsonify({"error": "No file provided."}), 400

    f = request.files["file"]
    if f.filename == "":
        return jsonify({"error": "No file selected."}), 400

    password = request.form.get("password", "")
    if not password:
        return jsonify({"error": "Password is required."}), 400

    try:
        data = f.read()
        blob, out_name = encrypt_file(data, f.filename, password)
        db.log_activity(session["user_id"], "encrypt_file", f.filename, "success")
        return send_file(
            io.BytesIO(blob),
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=out_name,
        )
    except ValueError as e:
        db.log_activity(session["user_id"], "encrypt_file", f.filename, "error")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        db.log_activity(session["user_id"], "encrypt_file", f.filename, "error")
        return jsonify({"error": "Encryption failed. Please try again."}), 500


# ---------------------------------------------------------------------------
# Decrypt
# ---------------------------------------------------------------------------

@files_bp.route("/decrypt", methods=["GET"])
@login_required
def decrypt_page():
    return render_template("decrypt.html")


@files_bp.route("/api/decrypt", methods=["POST"])
@login_required
def api_decrypt():
    if "file" not in request.files:
        return jsonify({"error": "No file provided."}), 400

    f = request.files["file"]
    if f.filename == "":
        return jsonify({"error": "No file selected."}), 400

    password = request.form.get("password", "")
    if not password:
        return jsonify({"error": "Password is required."}), 400

    try:
        data = f.read()
        plaintext, out_name = decrypt_file(data, f.filename, password)
        db.log_activity(session["user_id"], "decrypt_file", f.filename, "success")
        return send_file(
            io.BytesIO(plaintext),
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=out_name,
        )
    except DecryptionError as e:
        db.log_activity(session["user_id"], "decrypt_file", f.filename, "error")
        return jsonify({"error": str(e)}), 400
    except ValueError as e:
        db.log_activity(session["user_id"], "decrypt_file", f.filename, "error")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        db.log_activity(session["user_id"], "decrypt_file", f.filename, "error")
        return jsonify({"error": "Decryption failed. Please try again."}), 500
