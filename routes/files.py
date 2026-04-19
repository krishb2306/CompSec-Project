import os
import uuid
from io import BytesIO

from flask import Blueprint, current_app, redirect, render_template, request, send_file, url_for
from werkzeug.utils import secure_filename

from services.app_access import get_current_user, require_auth, require_role
from services.encryption import FileEncryptor
from services.file_access import can_delete, can_edit, can_share, can_view, get_file_role_for_user
from services.storage import (
    load_files,
    load_shares,
    load_users,
    save_files,
    save_shares,
)
from ui.pages import nav_context, render_message_page

from services.security import (
    log_event,
)
from services.upload_validation import MalwareDetectedError, read_upload_limited, validate_upload
from services.validation import sanitize_input, validate_length, safe_filename, safe_file_path


files_bp = Blueprint("files", __name__)
file_encryptor = FileEncryptor()


def _write_encrypted_file(file_path, data: bytes) -> None:
    """Encrypt and persist raw bytes to the uploads folder."""
    encrypted = file_encryptor.encrypt_bytes(data)
    with open(file_path, "wb") as f:
        f.write(encrypted)


def _read_stored_file_bytes(file_path) -> bytes:
    """Read encrypted bytes from disk and return plaintext.

    Falls back to returning the raw bytes if decryption fails, so any
    files that existed before encryption was enabled still work.
    """
    with open(file_path, "rb") as f:
        data = f.read()
    try:
        return file_encryptor.decrypt_bytes(data)
    except Exception:
        return data


@files_bp.route("/upload", methods=["POST"])
@require_auth
@require_role("user")
def upload():
    if "file" not in request.files:
        return render_message_page("Upload", "No file selected.")
    file = request.files["file"]
    if file.filename == "":
        return render_message_page("Upload", "No file selected.")

    try:
        basename = safe_filename(file.filename)
    except ValueError as e:
        log_event("INPUT_VALIDATION_FAILURE", get_current_user()["username"], request.remote_addr, details="invalid filename")
        return render_message_page("Upload", f"Invalid filename: {str(e)}")

    try:
        data = read_upload_limited(file.stream, current_app.config["MAX_UPLOAD_SIZE_BYTES"])
        validate_upload(basename, data)
    except MalwareDetectedError:
        log_event(
            "MALWARE_BLOCKED",
            get_current_user()["username"],
            request.remote_addr,
            details=f"Upload rejected: {basename}",
        )
        return render_message_page(
            "Upload",
            "This file was blocked after a malware scan.",
        )
    except ValueError as e:
        log_event(
            "FILE_UPLOAD_REJECTED",
            get_current_user()["username"],
            request.remote_addr,
            details=f"{basename}: {str(e)}",
        )
        return render_message_page("Upload", str(e))

    file_id = str(uuid.uuid4())
    unique_name = f"{file_id}_{basename}"
    file_path = os.path.join(current_app.config["UPLOAD_FOLDER"], unique_name)
    _write_encrypted_file(file_path, data)

    files = load_files()
    files.append(
        {
            "id": file_id,
            "owner": get_current_user()["username"],
            "original_name": basename,
            "stored_name": unique_name,
        }
    )
    save_files(files)
    log_event("DATA_CREATE", get_current_user()["username"], request.remote_addr, details=f"Uploaded file: {basename}")
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
    ctx = nav_context()
    return render_template("files/create_text.html", **ctx)


@files_bp.route("/create-text", methods=["POST"])
@require_auth
@require_role("user")
def create_text():
    raw = request.form.get("filename", "")
    content = request.form.get("content", "")
    original_name = _normalize_txt_filename(raw)
    if not original_name:
        return render_message_page(
            "Invalid name",
            "Use letters, numbers, dots, dashes, and underscores in the file name.",
            back_href=url_for("files.create_text_form"),
            back_label="Try again",
        )

    file_id = str(uuid.uuid4())
    unique_name = f"{file_id}_{original_name}"
    file_path = os.path.join(current_app.config["UPLOAD_FOLDER"], unique_name)
    _write_encrypted_file(file_path, content.encode("utf-8"))

    files = load_files()
    files.append(
        {
            "id": file_id,
            "owner": get_current_user()["username"],
            "original_name": original_name,
            "stored_name": unique_name,
        }
    )
    save_files(files)
    log_event("DATA_CREATE", get_current_user()["username"], request.remote_addr, details=f"Created text file: {original_name}")
    
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
        return render_message_page("Not found", "That file does not exist.")

    file_role = get_file_role_for_user(target_file, shares, current_user)
    if not can_edit(file_role):
        log_event("AUTHORIZATION_FAILURE", 
              current_user["username"] if current_user else None, 
              request.remote_addr, 
              details=f"Attempted to edit file {target_file['id']}")
        return render_message_page("Access Denied", "You can not edit that file")


    file_path = os.path.join(current_app.config["UPLOAD_FOLDER"], target_file["stored_name"])
    try:
        content = _read_stored_file_bytes(file_path).decode("utf-8")
    except UnicodeDecodeError:
        return render_message_page(
            "Not a text file",
            "Only text files can be edited in the web app. Download the file instead.",
        )

    ctx = nav_context()
    ctx.update(
        original_name=target_file["original_name"],
        file_role=file_role,
        file_id=file_id,
        content=content,
    )
    return render_template("files/edit.html", **ctx)


@files_bp.route("/edit/<file_id>", methods=["POST"])
@require_auth
@require_role("user")
def edit_file(file_id):
    files = load_files()
    shares = load_shares()
    current_user = get_current_user()
    target_file = next((f for f in files if f["id"] == file_id), None)

    if not target_file:
        return render_message_page("Not found", "That file does not exist.")

    file_role = get_file_role_for_user(target_file, shares, current_user)
    if not can_edit(file_role):
        log_event("AUTHORIZATION_FAILURE", 
              current_user["username"] if current_user else None, 
              request.remote_addr, 
              details=f"Attempted to edit file {target_file['id']}")
        return render_message_page("Access Denied", "You can not edit that file")

    file_path = os.path.join(current_app.config["UPLOAD_FOLDER"], target_file["stored_name"])
    new_content = request.form.get("content", "")
    _write_encrypted_file(file_path, new_content.encode("utf-8"))
    log_event("DATA_UPDATE", current_user["username"], request.remote_addr, details=f"Edited file: {target_file['original_name']}")
    return redirect(url_for("home.home"))


@files_bp.route("/share/<file_id>", methods=["POST"])
@require_auth
@require_role("user")
def share_file(file_id):
    current_user = get_current_user()
    current_username = current_user["username"]
    shared_with = request.form.get("shared_with", "").strip()
    file_role = request.form.get("file_role", "viewer").strip().lower()

    try:
        validate_length(shared_with, min_len=3, max_len=20)
        shared_with = sanitize_input(shared_with)
    except ValueError:
        log_event("INPUT_VALIDATION_FAILURE", current_user["username"], request.remote_addr, details="invalid username")
        return render_message_page("Share failed", "Invalid username.")

    if not shared_with or shared_with.lower() == "guest":
        return render_message_page("Share failed", "Enter a username to share with.")
    if file_role not in {"viewer", "editor"}:
        return render_message_page("Share failed", "Invalid permission (use viewer or editor).")

    users = load_users()
    files = load_files()
    shares = load_shares()

    user_exists = any(u["username"] == shared_with for u in users)
    if not user_exists:
        return render_message_page("Share failed", "That user does not exist.")
    if shared_with == current_username:
        return render_message_page("Share failed", "You already own this file.")

    target_file = next((f for f in files if f["id"] == file_id), None)
    if not target_file:
        return render_message_page("Not found", "That file does not exist.")
    current_file_role = get_file_role_for_user(target_file, shares, current_user)
    if not can_share(current_file_role):
        log_event("AUTHORIZATION_FAILURE", 
              current_user["username"] if current_user else None, 
              request.remote_addr, 
              details=f"Attempted to share file {target_file['id']}")
        return render_message_page("Share failed", "You can only share files you own.")
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


@files_bp.route("/make-public/<file_id>", methods=["POST"])
@require_auth
@require_role("user")
def make_public(file_id):
    current_user = get_current_user()
    files = load_files()
    shares = load_shares()

    target_file = next((f for f in files if f["id"] == file_id), None)
    if not target_file:
        return render_message_page("Not found", "That file does not exist.")
    current_file_role = get_file_role_for_user(target_file, shares, current_user)
    if not can_share(current_file_role):
        log_event("AUTHORIZATION_FAILURE", 
              current_user["username"] if current_user else None, 
              request.remote_addr, 
              details=f"Attempted to share file {target_file['id']}")
        return render_message_page("Access denied", "You can only change visibility for files you own.")
    for s in shares:
        if s.get("file_id") == file_id and s.get("shared_with") == "guest":
            s["file_role"] = "viewer"
            save_shares(shares)
            return redirect(url_for("home.home"))

    shares.append(
        {
            "file_id": file_id,
            "owner": target_file["owner"],
            "shared_with": "guest",
            "file_role": "viewer",
        }
    )
    save_shares(shares)
    return redirect(url_for("home.home"))


@files_bp.route("/unmake-public/<file_id>", methods=["POST"])
@require_auth
@require_role("user")
def unmake_public(file_id):
    current_user = get_current_user()
    files = load_files()
    shares = load_shares()

    target_file = next((f for f in files if f["id"] == file_id), None)
    if not target_file:
        return render_message_page("Not found", "That file does not exist.")
    current_file_role = get_file_role_for_user(target_file, shares, current_user)
    if not can_share(current_file_role):
        log_event("AUTHORIZATION_FAILURE", 
              current_user["username"] if current_user else None, 
              request.remote_addr, 
              details=f"Attempted to share file {target_file['id']}")
        return render_message_page("Access denied", "You can only change visibility for files you own.")
    new_shares = [s for s in shares if not (s.get("file_id") == file_id and s.get("shared_with") == "guest")]
    if len(new_shares) != len(shares):
        save_shares(new_shares)
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
        return render_message_page("Not found", "That file does not exist.")
    file_role = get_file_role_for_user(target_file, shares, current_user)
    if not can_delete(file_role):
        log_event("AUTHORIZATION_FAILURE", 
              current_user["username"] if current_user else None, 
              request.remote_addr, 
              details=f"Attempted to share file {target_file['id']}")
        return render_message_page("Access denied", "You cannot delete this file.")
    file_path = os.path.join(current_app.config["UPLOAD_FOLDER"], target_file["stored_name"])
    if os.path.exists(file_path):
        os.remove(file_path)

    files = [f for f in files if f["id"] != file_id]
    shares = [s for s in shares if s["file_id"] != file_id]
    save_files(files)
    save_shares(shares)
    log_event("DATA_DELETE", current_user["username"], request.remote_addr, details=f"Deleted file: {target_file['original_name']}")

    return redirect(url_for("home.home"))


@files_bp.route("/download/<stored_name>")
def download(stored_name):
    try:
        safe_file_path(stored_name, current_app.config["UPLOAD_FOLDER"])
    except ValueError:
        return render_message_page("Not found", "Invalid file name.")
    
    files = load_files()
    shares = load_shares()
    current_user = get_current_user()

    target_file = next((f for f in files if f["stored_name"] == stored_name), None)
    if not target_file:
        return render_message_page("Not found", "That file does not exist or you do not have access.")

    file_role = get_file_role_for_user(target_file, shares, current_user)
    if not can_view(file_role):
        log_event("AUTHORIZATION_FAILURE", 
              current_user["username"] if current_user else None, 
              request.remote_addr, 
              details=f"Attempted to download file {target_file['id']}")
        return render_message_page("Not found", "That file does not exist or you do not have access.")
    
    log_event("DATA_READ", current_user["username"] if current_user else "guest", request.remote_addr, details=f"Downloaded file: {target_file['original_name']}")

    file_path = os.path.join(current_app.config["UPLOAD_FOLDER"], stored_name)
    if not os.path.exists(file_path):
        return render_message_page("Not found", "That file is missing on disk.")

    plaintext = _read_stored_file_bytes(file_path)
    return send_file(
        BytesIO(plaintext),
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
        return render_message_page("Not found", "That file does not exist or you do not have access.")

    file_role = get_file_role_for_user(target_file, shares, current_user)
    if not can_view(file_role):
        log_event("AUTHORIZATION_FAILURE", 
              current_user["username"] if current_user else None, 
              request.remote_addr, 
              details=f"Attempted to download file {target_file['id']}")
        return render_message_page("Not found", "That file does not exist or you do not have access.")

    file_path = os.path.join(current_app.config["UPLOAD_FOLDER"], target_file["stored_name"])
    if not os.path.exists(file_path):
        return render_message_page("Not found", "That file is missing on disk.")

    try:
        content = _read_stored_file_bytes(file_path).decode("utf-8")

        log_event("DATA_READ", current_user["username"] if current_user else "guest", request.remote_addr, details=f"Opened file: {target_file['original_name']}")

        ctx = nav_context()
        ctx.update(
            original_name=target_file["original_name"],
            file_role=file_role,
            stored_name=target_file["stored_name"],
            preview_text=content,
        )
        return render_template("files/view_text.html", **ctx)
    except UnicodeDecodeError:
        return render_message_page(
            "Binary or non-text file",
            "This file cannot be shown as text here.",
            back_href=url_for("files.download", stored_name=target_file["stored_name"]),
            back_label="Download instead",
        )