import os
import uuid

from flask import Blueprint, current_app, redirect, request, send_from_directory, session, url_for

from services.auth import get_current_user, require_auth, require_role
from services.storage import (
    load_files,
    load_shares,
    load_users,
    save_files,
    save_shares,
)


files_bp = Blueprint("files", __name__)


@files_bp.route("/upload", methods=["POST"])
@require_auth
@require_role("user")
def upload():
    if "file" not in request.files:
        return "No file selected. <a href='/'>Go back</a>"
    file = request.files["file"]
    if file.filename == "":
        return "No file selected. <a href='/'>Go back</a>"

    file_id = str(uuid.uuid4())
    unique_name = f"{file_id}_{file.filename}"
    file_path = os.path.join(current_app.config["UPLOAD_FOLDER"], unique_name)
    file.save(file_path)

    files = load_files()
    files.append(
        {
            "id": file_id,
            "owner": session["username"],
            "original_name": file.filename,
            "stored_name": unique_name,
        }
    )
    save_files(files)
    return redirect(url_for("home.home"))


@files_bp.route("/delete/<file_id>", methods=["POST"])
@require_auth
@require_role("user")
def delete_file(file_id):
    files = load_files()
    shares = load_shares()
    current_user = get_current_user()
    current_username = current_user["username"]
    current_role = current_user.get("role", "guest")

    target_file = next((f for f in files if f["id"] == file_id), None)
    if not target_file:
        return "File not found. <a href='/'>Go back</a>"
    if current_role != "admin" and target_file["owner"] != current_username:
        return "Access denied. <a href='/'>Go back</a>"

    file_path = os.path.join(current_app.config["UPLOAD_FOLDER"], target_file["stored_name"])
    if os.path.exists(file_path):
        os.remove(file_path)

    files = [f for f in files if f["id"] != file_id]
    shares = [s for s in shares if s["file_id"] != file_id]
    save_files(files)
    save_shares(shares)
    return redirect(url_for("home.home"))


@files_bp.route("/share/<file_id>", methods=["POST"])
@require_auth
@require_role("user")
def share_file(file_id):
    current_user = get_current_user()
    current_username = current_user["username"]
    current_role = current_user.get("role", "user")
    shared_with = request.form.get("shared_with", "").strip()

    if not shared_with:
        return "Must provide a username to share with. <a href='/'>Go back</a>"

    users = load_users()
    files = load_files()
    shares = load_shares()

    user_exists = any(u["username"] == shared_with for u in users)
    is_public_share = shared_with == "guest"
    if not user_exists and not is_public_share:
        return "That user does not exist. <a href='/'>Go back</a>"
    if shared_with == current_username:
        return "You already own this file. <a href='/'>Go back</a>"

    target_file = next((f for f in files if f["id"] == file_id), None)
    if not target_file:
        return "File not found. <a href='/'>Go back</a>"
    if current_role != "admin" and target_file["owner"] != current_username:
        return "You can only share your own files. <a href='/'>Go back</a>"

    for s in shares:
        if s.get("file_id") == file_id and s.get("shared_with") == shared_with:
            return redirect(url_for("home.home"))

    shares.append(
        {
            "file_id": file_id,
            "owner": target_file["owner"],
            "shared_with": shared_with,
        }
    )
    save_shares(shares)
    return redirect(url_for("home.home"))


@files_bp.route("/download/<stored_name>")
def download(stored_name):
    files = load_files()
    shares = load_shares()
    current_user = get_current_user()

    target_file = next((f for f in files if f["stored_name"] == stored_name), None)
    if not target_file:
        return "File not found. <a href='/'>Go back</a>"

    is_public = any(
        s["file_id"] == target_file["id"] and s["shared_with"] == "guest"
        for s in shares
    )

    if current_user is None:
        if not is_public:
            return "File not found or access denied. <a href='/'>Go back</a>"
    else:
        current_username = current_user["username"]
        current_role = current_user.get("role", "user")
        is_admin = current_role == "admin"
        is_owner = target_file["owner"] == current_username
        is_shared = any(
            s["file_id"] == target_file["id"] and s["shared_with"] == current_username
            for s in shares
        )
        if not (is_public or is_admin or is_owner or is_shared):
            return "File not found or access denied. <a href='/'>Go back</a>"

    return send_from_directory(
        current_app.config["UPLOAD_FOLDER"],
        stored_name,
        as_attachment=True,
        download_name=target_file["original_name"],
    )
