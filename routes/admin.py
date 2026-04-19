import time
import re
import bcrypt

from flask import Blueprint, current_app, redirect, render_template, request, url_for

from services.app_access import get_current_user, require_auth, require_role
from services.security import (
    generate_secure_temp_password,
    log_event,
    security_log_rows,
)
from services.sessions import destroy_session_by_token
from services.storage import (
    load_security_logs,
    load_sessions,
    load_users,
    save_users,
)
from ui.pages import render_message_page
from services.validation import sanitize_input, validate_length

admin_bp = Blueprint("admin", __name__)


def validate_and_sanitize_username(username):
    """One-stop validation for username inputs - prevents XSS and injection"""
    if not username:
        log_event("INPUT_VALIDATION_FAILURE", None, request.remote_addr, details="Username required but empty")
        raise ValueError("Username is required")
    
    username = sanitize_input(username)
    try:
        validate_length(username, min_len=3, max_len=20)
    except ValueError:
        log_event("INPUT_VALIDATION_FAILURE", username, request.remote_addr, details="Username length invalid")
        raise ValueError("Username must be 3-20 characters")
    
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        log_event("INPUT_VALIDATION_FAILURE", username, request.remote_addr, details="Username has invalid characters")
        raise ValueError("Username can only contain letters, numbers, and underscores")
    
    return username


def validate_and_sanitize_session_token(token):
    """Validate session token to prevent injection"""
    if not token:
        log_event("INPUT_VALIDATION_FAILURE", None, request.remote_addr, details="Session token required but is empty")
        raise ValueError("Session token is required")

    token = sanitize_input(token)

    try:
        validate_length(token, min_len=10, max_len=200)
    except ValueError:
        log_event("INPUT_VALIDATION_FAILURE", None, request.remote_addr, details="Session token length invalid")
        raise ValueError("Invalid session token format")
    
    if not re.match(r'^[a-zA-Z0-9_\-]+$', token):
        log_event("INPUT_VALIDATION_FAILURE", None, request.remote_addr, details="Session token contains invalid characters")
        raise ValueError("Invalid session token characters")
    
    return token


def _listed_users(users):
    """Regular accounts only: exclude admin role and synthetic guest user."""
    out = []
    for u in users:
        if u.get("username") == "guest":
            continue
        if u.get("role") == "admin":
            continue
        out.append(u)
    return out


def _lock_until_timestamp(user):
    lock_until = user.get("locked_until")
    if lock_until is None:
        return None
    try:
        return float(lock_until)
    except (TypeError, ValueError):
        return None


def _password_lockout_active(user):
    """True if login is blocked by failed-attempt lockout (locked_until still in the future)."""
    lu = _lock_until_timestamp(user)
    if lu is None:
        return False
    return time.time() < lu


def _admin_back():
    return url_for("admin.admin_users"), "Back to admin"


@admin_bp.route("/admin/users")
@require_auth
@require_role("admin")
def admin_users():
    users = load_users()
    listed = _listed_users(users)
    sessions = load_sessions()
    logs = load_security_logs()
    admin_name = current_app.config.get("ADMIN_USERNAME", "admin")

    listed_users = []
    for user in listed:
        sanitized_username = sanitize_input(user["username"])
        sanitized_email = sanitize_input(user.get("email") or "—")
        
        admin_locked = bool(user.get("locked_by_admin"))
        lockout = _password_lockout_active(user)
        lu = _lock_until_timestamp(user)
        until_label = (
            time.strftime("%Y-%m-%d %H:%M", time.localtime(lu)) if lockout and lu is not None else ""
        )
        listed_users.append(
            {
                "username": sanitized_username,
                "email": sanitized_email,
                "show_active_badge": not admin_locked and not lockout,
                "admin_locked": admin_locked,
                "lockout_active": lockout,
                "lockout_until_label": until_label,
            }
        )

    sessions_rows = []
    for token, metadata in sessions.items():
        preview = sanitize_input(token[:12] + "…" if len(token) > 12 else token)
        sessions_rows.append(
            {
                "username": sanitize_input(metadata.get("username") or "—"),
                "ip": sanitize_input(metadata.get("ip") or "—"),
                "token_preview": preview,
                "token": token, 
            }
        )
    log_rows = security_log_rows(logs)
    sanitized_logs = []
    for log in log_rows:
        sanitized_logs.append({
            "event": sanitize_input(log.get("event", "")),
            "user": sanitize_input(log.get("user", "")),
            "ip": sanitize_input(log.get("ip", "")),
            "details": sanitize_input(log.get("details", "")),
            "ua": sanitize_input(log.get("ua", "")),
            "ts": sanitize_input(log.get("ts", "")),
        })

    return render_template(
        "admin/users.html",
        app_title="Secure Document Sharing",
        admin_name=sanitize_input(admin_name),
        listed_users=listed_users,
        sessions_rows=sessions_rows,
        log_rows=sanitized_logs,
    )


@admin_bp.route("/admin/lock-user/<username>", methods=["POST"])
@require_auth
@require_role("admin")
def lock_user(username):
    try:
        username = validate_and_sanitize_username(username)
    except ValueError as e:
        href, label = _admin_back()
        return render_message_page("Invalid input", str(e), back_href=href, back_label=label)
    
    actor = get_current_user()["username"]
    users = load_users()
    target_user = next((u for u in users if u["username"] == username), None)
    
    if not target_user:
        href, label = _admin_back()
        return render_message_page("User not found", "That user does not exist.", back_href=href, back_label=label)
    
    if target_user["username"] == actor:
        href, label = _admin_back()
        return render_message_page(
            "Cannot lock",
            "You cannot lock your own account.",
            back_href=href,
            back_label=label,
        )

    target_user["locked_by_admin"] = True
    save_users(users)
    log_event("ACCOUNT_LOCKED_BY_ADMIN", actor, request.remote_addr, details=username)
    return redirect(url_for("admin.admin_users"))


@admin_bp.route("/admin/unlock-user/<username>", methods=["POST"])
@require_auth
@require_role("admin")
def unlock_user(username):
    try:
        username = validate_and_sanitize_username(username)
    except ValueError as e:
        href, label = _admin_back()
        return render_message_page("Invalid input", str(e), back_href=href, back_label=label)
    
    actor = get_current_user()["username"]
    users = load_users()
    target_user = next((u for u in users if u["username"] == username), None)
    
    if not target_user:
        href, label = _admin_back()
        return render_message_page("User not found", "That user does not exist.", back_href=href, back_label=label)

    target_user["locked_by_admin"] = False
    save_users(users)
    log_event("ACCOUNT_UNLOCKED_BY_ADMIN", actor, request.remote_addr, details=username)
    return redirect(url_for("admin.admin_users"))


@admin_bp.route("/admin/unlock-password-lockout/<username>", methods=["POST"])
@require_auth
@require_role("admin")
def unlock_password_lockout(username):
    try:
        username = validate_and_sanitize_username(username)
    except ValueError as e:
        href, label = _admin_back()
        return render_message_page("Invalid input", str(e), back_href=href, back_label=label)
    
    actor = get_current_user()["username"]
    users = load_users()
    target_user = next((u for u in users if u["username"] == username), None)
    
    if not target_user:
        href, label = _admin_back()
        return render_message_page("User not found", "That user does not exist.", back_href=href, back_label=label)
    
    if not _password_lockout_active(target_user):
        return redirect(url_for("admin.admin_users"))

    target_user["failed_attempts"] = 0
    target_user["locked_until"] = None
    save_users(users)
    log_event(
        "PASSWORD_LOCKOUT_CLEARED_BY_ADMIN",
        actor,
        request.remote_addr,
        details=username,
    )
    return redirect(url_for("admin.admin_users"))


@admin_bp.route("/admin/force-close-session/<session_token>", methods=["POST"])
@require_auth
@require_role("admin")
def force_close_session(session_token):
    try:
        session_token = validate_and_sanitize_session_token(session_token)
    except ValueError as e:
        href, label = _admin_back()
        return render_message_page("Invalid input", str(e), back_href=href, back_label=label)
    
    actor = get_current_user()["username"]
    
    if not destroy_session_by_token(session_token, actor_username=actor, ip=request.remote_addr):
        href, label = _admin_back()
        return render_message_page(
            "Session not found",
            "That session token is no longer active.",
            back_href=href,
            back_label=label,
        )
    log_event("FORCE_CLOSED_BY_ADMIN", actor, request.remote_addr, details=session_token)

    return redirect(url_for("admin.admin_users"))


@admin_bp.route("/admin/reset-password/<username>", methods=["POST"])
@require_auth
@require_role("admin")
def reset_password(username):
    try:
        username = validate_and_sanitize_username(username)
    except ValueError as e:
        href, label = _admin_back()
        return render_message_page("Invalid input", str(e), back_href=href, back_label=label)
    
    actor = get_current_user()["username"]
    users = load_users()
    target_user = next((u for u in users if u["username"] == username), None)
    
    if not target_user:
        href, label = _admin_back()
        return render_message_page("User not found", "That user does not exist.", back_href=href, back_label=label)

    temp_password = generate_secure_temp_password()
    hashed = bcrypt.hashpw(temp_password.encode("utf-8"), bcrypt.gensalt(12))
    target_user["password"] = hashed.decode("utf-8")
    target_user["failed_attempts"] = 0
    target_user["locked_until"] = None
    target_user["locked_by_admin"] = False
    save_users(users)
    log_event("PASSWORD_RESET_BY_ADMIN", actor, request.remote_addr, details=username)
    
    sanitized_username = sanitize_input(username)
    
    return render_template(
        "admin/temp_password.html",
        app_title="Secure Document Sharing",
        username=sanitized_username,
        temp_password=temp_password, 
    )


@admin_bp.route("/admin/set-role/<username>", methods=["POST"])
@require_auth
@require_role("admin")
def set_role_disabled(username):
    try:
        username = validate_and_sanitize_username(username)
    except ValueError:
        username = sanitize_input(username)
    
    actor = get_current_user()["username"]
    log_event("ROLE_CHANGE_ATTEMPT_BLOCKED", actor, request.remote_addr, details=username)
    href, label = _admin_back()
    return render_message_page(
        "Role changes disabled",
        "Changing user roles through this panel is not allowed.",
        back_href=href,
        back_label=label,
    )