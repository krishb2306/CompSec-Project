import time

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

admin_bp = Blueprint("admin", __name__)


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
        admin_locked = bool(user.get("locked_by_admin"))
        lockout = _password_lockout_active(user)
        lu = _lock_until_timestamp(user)
        until_label = (
            time.strftime("%Y-%m-%d %H:%M", time.localtime(lu)) if lockout and lu is not None else ""
        )
        listed_users.append(
            {
                "username": user["username"],
                "email": user.get("email") or "—",
                "show_active_badge": not admin_locked and not lockout,
                "admin_locked": admin_locked,
                "lockout_active": lockout,
                "lockout_until_label": until_label,
            }
        )

    sessions_rows = []
    for token, metadata in sessions.items():
        preview = token[:12] + "…" if len(token) > 12 else token
        sessions_rows.append(
            {
                "username": metadata.get("username") or "—",
                "ip": metadata.get("ip") or "—",
                "token_preview": preview,
                "token": token,
            }
        )

    log_rows = security_log_rows(logs)

    return render_template(
        "admin/users.html",
        app_title="Secure Document Sharing",
        admin_name=admin_name,
        listed_users=listed_users,
        sessions_rows=sessions_rows,
        log_rows=log_rows,
    )


@admin_bp.route("/admin/lock-user/<username>", methods=["POST"])
@require_auth
@require_role("admin")
def lock_user(username):
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
    actor = get_current_user()["username"]
    if not destroy_session_by_token(session_token, actor_username=actor, ip=request.remote_addr):
        href, label = _admin_back()
        return render_message_page(
            "Session not found",
            "That session token is no longer active.",
            back_href=href,
            back_label=label,
        )
    return redirect(url_for("admin.admin_users"))


@admin_bp.route("/admin/reset-password/<username>", methods=["POST"])
@require_auth
@require_role("admin")
def reset_password(username):
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
    return render_template(
        "admin/temp_password.html",
        app_title="Secure Document Sharing",
        username=username,
        temp_password=temp_password,
    )


@admin_bp.route("/admin/set-role/<username>", methods=["POST"])
@require_auth
@require_role("admin")
def set_role_disabled(username):
    actor = get_current_user()["username"]
    log_event("ROLE_CHANGE_ATTEMPT_BLOCKED", actor, request.remote_addr, details=username)
    href, label = _admin_back()
    return render_message_page(
        "Role changes disabled",
        "Changing user roles through this panel is not allowed.",
        back_href=href,
        back_label=label,
    )
