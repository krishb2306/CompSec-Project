import os
import uuid
import html

from flask import Blueprint, current_app, redirect, request, send_from_directory, session, url_for
from werkzeug.utils import secure_filename

from services.app_access import get_current_user, require_auth, require_role
from services.file_access import can_delete, can_edit, can_share, can_view, get_file_role_for_user
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


def _normalize_txt_filename(raw_name):
    if not raw_name or not raw_name.strip():
        return None
    base = secure_filename(raw_name.strip())
    if not base:
        return None
    lower = base.lower()
    if not lower.endswith(".txt"):
        base = f"{base}.txt"
    return base


@files_bp.route("/create-text", methods=["GET"])
@require_auth
@require_role("user")
def create_text_form():
    return """
    <h1>Create text file</h1>
    <p>Name must end in <code>.txt</code> (added automatically if omitted).</p>
    <form method='POST' action='/create-text'>
        <label>File name: <input name='filename' placeholder='notes.txt' required maxlength='200'></label><br><br>
        <label>Content (optional):</label><br>
        <textarea name='content' rows='16' cols='80' placeholder='Type your text here...'></textarea><br><br>
        <button type='submit'>Create</button>
    </form>
    <p><a href='/'>Cancel</a></p>
    """


@files_bp.route("/create-text", methods=["POST"])
@require_auth
@require_role("user")
def create_text():
    raw = request.form.get("filename", "")
    content = request.form.get("content", "")
    original_name = _normalize_txt_filename(raw)
    if not original_name:
        return "Invalid file name. Use letters, numbers, dots, dashes, underscores. <a href='/create-text'>Back</a>"

    file_id = str(uuid.uuid4())
    unique_name = f"{file_id}_{original_name}"
    file_path = os.path.join(current_app.config["UPLOAD_FOLDER"], unique_name)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)

    files = load_files()
    files.append(
        {
            "id": file_id,
            "owner": session["username"],
            "original_name": original_name,
            "stored_name": unique_name,
        }
    )
    save_files(files)
    return redirect(url_for("home.home"))


@files_bp.route("/edit/<file_id>")
@require_auth
@require_role("user")
def edit_file_form(file_id):
    files = load_files()
    shares = load_shares()
    current_user = get_current_user()
    target_file = next((f for f in files if f["id"] == file_id), None)

    if not target_file:
        return "File not found. <a href='/'>Go back</a>"

    file_role = get_file_role_for_user(target_file, shares, current_user)
    if not can_edit(file_role):
        return "Access denied. <a href='/'>Go back</a>"

    file_path = os.path.join(current_app.config["UPLOAD_FOLDER"], target_file["stored_name"])
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except UnicodeDecodeError:
        return "Only text files can be edited in the web app. <a href='/'>Go back</a>"

    return f"""
    <h2>Edit: {html.escape(target_file["original_name"])}</h2>
    <p>Your file role: <b>{file_role}</b></p>
    <form method='POST' action='/edit/{file_id}'>
        <textarea name='content' rows='24' cols='120' required>{html.escape(content)}</textarea><br><br>
        <button type='submit'>Save</button>
    </form>
    <a href='/'>Cancel</a>
    """


@files_bp.route("/edit/<file_id>", methods=["POST"])
@require_auth
@require_role("user")
def edit_file(file_id):
    files = load_files()
    shares = load_shares()
    current_user = get_current_user()
    target_file = next((f for f in files if f["id"] == file_id), None)

    if not target_file:
        return "File not found. <a href='/'>Go back</a>"

    file_role = get_file_role_for_user(target_file, shares, current_user)
    if not can_edit(file_role):
        return "Access denied. <a href='/'>Go back</a>"

    file_path = os.path.join(current_app.config["UPLOAD_FOLDER"], target_file["stored_name"])
    new_content = request.form.get("content", "")
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(new_content)

    return redirect(url_for("home.home"))


@files_bp.route("/share/<file_id>", methods=["POST"])
@require_auth
@require_role("user")
def share_file(file_id):
    current_user = get_current_user()
    current_username = current_user["username"]
    shared_with = request.form.get("shared_with", "").strip()
    file_role = request.form.get("file_role", "viewer").strip().lower()

    if not shared_with:
        return "Must provide a username to share with. <a href='/'>Go back</a>"
    if file_role not in {"viewer", "editor"}:
        return "Invalid file role. <a href='/'>Go back</a>"

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
    current_file_role = get_file_role_for_user(target_file, shares, current_user)
    if not can_share(current_file_role):
        return "You can only share your own files. <a href='/'>Go back</a>"

    if shared_with == "guest":
        file_role = "viewer"

    for s in shares:
        if s.get("file_id") == file_id and s.get("shared_with") == shared_with:
            s["file_role"] = file_role
            save_shares(shares)
            return redirect(url_for("home.home"))

    shares.append(
        {
            "file_id": file_id,
            "owner": target_file["owner"],
            "shared_with": shared_with,
            "file_role": file_role,
        }
    )
    save_shares(shares)
    return redirect(url_for("home.home"))


@files_bp.route("/delete/<file_id>", methods=["POST"])
@require_auth
@require_role("user")
def delete_file(file_id):
    files = load_files()
    shares = load_shares()
    current_user = get_current_user()

    target_file = next((f for f in files if f["id"] == file_id), None)
    if not target_file:
        return "File not found. <a href='/'>Go back</a>"
    file_role = get_file_role_for_user(target_file, shares, current_user)
    if not can_delete(file_role):
        return "Access denied. <a href='/'>Go back</a>"

    file_path = os.path.join(current_app.config["UPLOAD_FOLDER"], target_file["stored_name"])
    if os.path.exists(file_path):
        os.remove(file_path)

    files = [f for f in files if f["id"] != file_id]
    shares = [s for s in shares if s["file_id"] != file_id]
    save_files(files)
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

    file_role = get_file_role_for_user(target_file, shares, current_user)
    if not can_view(file_role):
        return "File not found or access denied. <a href='/'>Go back</a>"

    return send_from_directory(
        current_app.config["UPLOAD_FOLDER"],
        stored_name,
        as_attachment=True,
        download_name=target_file["original_name"],
    )


@files_bp.route("/open/<stored_name>")
def open_file(stored_name):
    files = load_files()
    shares = load_shares()
    current_user = get_current_user()
    target_file = next((f for f in files if f["stored_name"] == stored_name), None)

    if not target_file:
        return "File not found. <a href='/'>Go back</a>"

    file_role = get_file_role_for_user(target_file, shares, current_user)
    if not can_view(file_role):
        return "File not found or access denied. <a href='/'>Go back</a>"

    file_path = os.path.join(current_app.config["UPLOAD_FOLDER"], target_file["stored_name"])
    if not os.path.exists(file_path):
        return "File not found on disk. <a href='/'>Go back</a>"

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        safe_content = html.escape(content)
        return f"""
        <h2>Viewing: {html.escape(target_file["original_name"])}</h2>
        <p>Your file role: <b>{file_role}</b></p>
        <a href='/'>Back</a> | <a href='/download/{target_file["stored_name"]}'>Download</a>
        <pre style='white-space: pre-wrap; border: 1px solid #ccc; padding: 12px; margin-top: 12px;'>{safe_content}</pre>
        """
    except UnicodeDecodeError:
        return (
            "This file is not displayable as text in the web app. "
            f"<a href='/download/{target_file['stored_name']}'>Download instead</a>"
        )
