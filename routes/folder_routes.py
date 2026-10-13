"""
BioCrypt — Folder Encrypt / Decrypt Routes
"""
import io
from flask import (
    Blueprint, render_template, request, session,
    redirect, url_for, send_file, flash, jsonify,
)
from services.folder_service import zip_and_encrypt, decrypt_to_zip
from crypto.encryption import DecryptionError
import db.models as db

folders_bp = Blueprint("folders", __name__)


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


@folders_bp.route("/folders", methods=["GET"])
@login_required
def folders_page():
    return render_template("folders.html")


@folders_bp.route("/api/folder/encrypt", methods=["POST"])
@login_required
def api_folder_encrypt():
    files = request.files.getlist("files")
    password = request.form.get("password", "")
    folder_name = request.form.get("folder_name", "folder").strip() or "folder"

    if not files or all(f.filename == "" for f in files):
        return jsonify({"error": "No files provided."}), 400
    if not password:
        return jsonify({"error": "Password is required."}), 400

    try:
        from werkzeug.utils import secure_filename
        file_list = []
        for f in files:
            rel = f.filename.replace("\\", "/")
            # Strip the top-level folder component provided by webkitRelativePath
            parts = rel.split("/", 1)
            rel_path = parts[1] if len(parts) > 1 else parts[0]
            file_list.append((rel_path, f.read()))

        blob, out_name = zip_and_encrypt(file_list, secure_filename(folder_name), password)
        db.log_activity(session["user_id"], "encrypt_folder", folder_name, "success")
        return send_file(
            io.BytesIO(blob),
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=out_name,
        )
    except ValueError as e:
        db.log_activity(session["user_id"], "encrypt_folder", folder_name, "error")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        db.log_activity(session["user_id"], "encrypt_folder", folder_name, "error")
        return jsonify({"error": "Folder encryption failed."}), 500


@folders_bp.route("/api/folder/decrypt", methods=["POST"])
@login_required
def api_folder_decrypt():
    if "file" not in request.files:
        return jsonify({"error": "No file provided."}), 400

    f = request.files["file"]
    password = request.form.get("password", "")
    if not password:
        return jsonify({"error": "Password is required."}), 400

    try:
        data = f.read()
        zip_bytes, out_name = decrypt_to_zip(data, password)
        db.log_activity(session["user_id"], "decrypt_folder", f.filename, "success")
        return send_file(
            io.BytesIO(zip_bytes),
            mimetype="application/zip",
            as_attachment=True,
            download_name=out_name,
        )
    except DecryptionError as e:
        db.log_activity(session["user_id"], "decrypt_folder", f.filename, "error")
        return jsonify({"error": str(e)}), 400
    except ValueError as e:
        db.log_activity(session["user_id"], "decrypt_folder", f.filename, "error")
        return jsonify({"error": str(e)}), 400
    except Exception:
        db.log_activity(session["user_id"], "decrypt_folder", f.filename, "error")
        return jsonify({"error": "Folder decryption failed."}), 500
