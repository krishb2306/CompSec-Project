import time

import bcrypt
from flask import Blueprint, make_response, redirect, render_template, request, url_for

from ui.pages import nav_context, render_message_page
from services.security import (
    log_event,
    validate_email,
    validate_password,
    validate_username,
)
from services.app_access import require_auth
from services.sessions import (
    attach_session_cookie,
    clear_session_cookie,
    create_logged_session,
    destroy_logged_session,
)
from services.storage import load_users, save_users
from services.validation import sanitize_input, validate_length


auth_bp = Blueprint("auth", __name__)

login_attempts = {}


@auth_bp.route("/register", methods=["POST"])
def register():
    ip = request.remote_addr
    username = sanitize_input(request.form.get("username", "").strip())
    email = sanitize_input(request.form.get("email", "").strip())
    password = request.form.get("password", "").strip() # im leaving this unsanitized
    confirm = request.form.get("confirm_password", "").strip()

    if not username or not email or not password or not confirm:
        log_event("INPUT_VALIDATION_FAILURE", username or None, ip, details="missing_fields")
        return render_message_page("Registration", "All fields are required.")
    try:
        validate_length(username, min_len=3, max_len=20)
        validate_length(email, min_len=5, max_len=100)
        validate_length(password, min_len=12, max_len=128)
    except ValueError as e:
        log_event("INPUT_VALIDATION_FAILURE", username or None, ip, details="length_validation")
        return render_message_page("Registration", str(e))
    
    if not validate_username(username):
        log_event("INPUT_VALIDATION_FAILURE", username, ip, details="invalid_username")
        return render_message_page(
            "Registration",
            "Invalid username. Use 3–20 characters: letters, numbers, and underscores only.",
        )
    if not validate_email(email):
        log_event("INPUT_VALIDATION_FAILURE", username, ip, details="invalid_email")
        return render_message_page("Registration", "Invalid email format.")
    if not validate_password(password):
        log_event("INPUT_VALIDATION_FAILURE", username, ip, details="invalid_password")
        return render_message_page(
            "Registration",
            "Password must be at least 12 characters and include upper, lower, number, and special (!@#$%^&*).",
        )
    if password != confirm:
        log_event("INPUT_VALIDATION_FAILURE", username, ip, details="password_mismatch")
        return render_message_page("Registration", "Passwords do not match.")

    users = load_users()
    for user in users:
        if user["username"] == username:
            log_event("INPUT_VALIDATION_FAILURE", username, ip, details="duplicate_username")
            return render_message_page("Registration", "That username is already taken.")
        if user.get("email") == email:
            log_event("INPUT_VALIDATION_FAILURE", username, ip, details="duplicate_email")
            return render_message_page("Registration", "That email is already registered.")

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(12))
    new_user = {
        "username": username,
        "email": email,
        "password": hashed.decode("utf-8"),
        "role": "user",
        "failed_attempts": 0,
        "locked_until": None,
        "locked_by_admin": False,
        "password_reset_requested": False,
        "created_at": time.time(),
    }
    users.append(new_user)
    save_users(users)
    token = create_logged_session(username, ip)
    log_event("DATA_CREATE", username, ip, details="New user registered")
    log_event("REGISTER_SUCCESS", username, ip)
    resp = make_response(redirect(url_for("home.home")))
    attach_session_cookie(resp, token)
    return resp


@auth_bp.route("/login", methods=["POST"])
def login():
    ip = request.remote_addr
    current_time = time.time()
    
    if ip not in login_attempts:
        login_attempts[ip] = []

    login_attempts[ip] = [t for t in login_attempts[ip] if current_time - t < 60]
    if len(login_attempts[ip]) >= 10:
        log_event("SUSPICIOUS_ACTIVITY", None, ip, details="Rate limit exceeded - too many login attempts from IP")
        return render_message_page(
            "Too many attempts",
            "Too many login attempts from this network. Please wait a minute and try again.",
        )
    login_attempts[ip].append(current_time)

    username = sanitize_input(request.form.get("username", "").strip())
    password = request.form.get("password", "").strip()
    
    log_event("LOGIN_ATTEMPT", username or None, ip)

    if username and (len(username) < 1 or len(username) > 20):
        log_event("INPUT_VALIDATION_FAILURE", username, ip, details="invalid_username_format")
        return render_message_page("Sign in failed", "Invalid username format.")

    users = load_users()

    for user in users:
        if user["username"] == username:
            if user.get("locked_by_admin"):
                log_event("LOGIN_BLOCKED_ADMIN_LOCK", username, ip)
                return render_message_page(
                    "Account locked",
                    "This account has been locked by an administrator. Contact support.",
                )
            if user.get("locked_until") and time.time() < user["locked_until"]:
                log_event("LOGIN_BLOCKED_LOCKED", username, ip)
                return render_message_page(
                    "Account locked",
                    "Too many failed sign-ins. Try again after the lockout period ends.",
                )

            if bcrypt.checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
                user["failed_attempts"] = 0
                user["locked_until"] = None
                save_users(users)
                token = create_logged_session(username, ip)
                log_event("LOGIN_SUCCESS", username, ip)
                resp = make_response(redirect(url_for("home.home")))
                attach_session_cookie(resp, token)
                return resp

            user["failed_attempts"] += 1
            log_event("LOGIN_FAILED", username, ip, details="invalid_credentials")
            if user["failed_attempts"] >= 5:
                user["locked_until"] = time.time() + (15 * 60)
                log_event("ACCOUNT_LOCKED", username, ip, details="failed_attempts_exceeded")
            save_users(users)
            return render_message_page("Sign in failed", "Invalid username or password.")

    log_event("LOGIN_FAILED", username or None, ip, details="unknown_user")
    return render_message_page("Sign in failed", "Invalid username or password.")


@auth_bp.route("/logout")
def logout():
    destroy_logged_session()
    resp = make_response(redirect(url_for("home.home")))
    clear_session_cookie(resp)
    return resp


@auth_bp.route("/account/password")
@require_auth
def password_settings():
    current_user = nav_context()["current_user"]
    users = load_users()
    user = next((u for u in users if u["username"] == current_user["username"]), None)
    if not user:
        return redirect(url_for("home.home"))

    ctx = nav_context()
    ctx.update(app_title="Secure Document Sharing")
    return render_template("auth/password_settings.html", **ctx)


@auth_bp.route("/account/password/change", methods=["POST"])
@require_auth
def change_password():
    ip = request.remote_addr
    current_user = nav_context()["current_user"]
    old_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not old_password or not new_password or not confirm_password:
        return render_message_page(
            "Change password",
            "All fields are required.",
            back_href=url_for("auth.password_settings"),
            back_label="Back to password settings",
        )

    try:
        validate_length(new_password, min_len=12, max_len=128)
    except ValueError as e:
        log_event("INPUT_VALIDATION_FAILURE", current_user["username"], ip, details="password_length_validation")
        return render_message_page(
            "Change password",
            str(e),
            back_href=url_for("auth.password_settings"),
            back_label="Back to password settings",
        )

    if not validate_password(new_password):
        return render_message_page(
            "Change password",
            "New password must be at least 12 characters and include upper, lower, number, and special (!@#$%^&*).",
            back_href=url_for("auth.password_settings"),
            back_label="Back to password settings",
        )

    if new_password != confirm_password:
        return render_message_page(
            "Change password",
            "New password and confirmation do not match.",
            back_href=url_for("auth.password_settings"),
            back_label="Back to password settings",
        )

    users = load_users()
    user = next((u for u in users if u["username"] == current_user["username"]), None)
    if not user:
        return render_message_page("Change password", "User account not found.")

    if not bcrypt.checkpw(old_password.encode("utf-8"), user["password"].encode("utf-8")):
        log_event("PASSWORD_CHANGE_FAILED", current_user["username"], ip, details="invalid_current_password")
        return render_message_page(
            "Change password",
            "Current password is incorrect.",
            back_href=url_for("auth.password_settings"),
            back_label="Back to password settings",
        )

    if bcrypt.checkpw(new_password.encode("utf-8"), user["password"].encode("utf-8")):
        return render_message_page(
            "Change password",
            "New password must be different from your current password.",
            back_href=url_for("auth.password_settings"),
            back_label="Back to password settings",
        )

    hashed = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt(12))
    user["password"] = hashed.decode("utf-8")
    user["password_reset_requested"] = False
    user["failed_attempts"] = 0
    user["locked_until"] = None
    save_users(users)
    log_event("PASSWORD_CHANGED_BY_USER", current_user["username"], ip)
    return render_message_page(
        "Change password",
        "Your password has been updated.",
        back_href=url_for("auth.password_settings"),
        back_label="Back to password settings",
    )


@auth_bp.route("/forgot-password", methods=["POST"])
def forgot_password():
    ip = request.remote_addr
    username = sanitize_input(request.form.get("username", "").strip())
    email = sanitize_input(request.form.get("email", "").strip())

    if not username or not email:
        return render_message_page(
            "Forgot password",
            "Username and email are required.",
            back_href=url_for("home.home"),
            back_label="Back to sign in",
        )

    if not validate_username(username):
        return render_message_page(
            "Forgot password",
            "Invalid username format.",
            back_href=url_for("home.home"),
            back_label="Back to sign in",
        )

    if not validate_email(email):
        return render_message_page(
            "Forgot password",
            "Invalid email format.",
            back_href=url_for("home.home"),
            back_label="Back to sign in",
        )

    users = load_users()
    user = next((u for u in users if u["username"] == username), None)

    if not user:
        log_event("PASSWORD_RESET_REQUEST_FAILED", username, ip, details="unknown_user")
        return render_message_page(
            "Forgot password",
            "Username not in our records.",
            back_href=url_for("home.home"),
            back_label="Back to sign in",
        )

    if user.get("role") == "admin":
        return render_message_page(
            "Forgot password",
            "Admin account cannot use forgot password.",
            back_href=url_for("home.home"),
            back_label="Back to sign in",
        )

    if user.get("email") != email:
        log_event("PASSWORD_RESET_REQUEST_FAILED", username, ip, details="email_mismatch")
        return render_message_page(
            "Forgot password",
            "Email does not match the email used at registration.",
            back_href=url_for("home.home"),
            back_label="Back to sign in",
        )

    user["password_reset_requested"] = True
    save_users(users)
    log_event("PASSWORD_RESET_REQUESTED_BY_USER", username, ip, details=user.get("email"))
    return render_message_page(
        "Forgot password",
        "Your password reset request has been sent to admin. Once the admin has reset your password, you will receive an email with your new password.",
        back_href=url_for("home.home"),
        back_label="Back to sign in",
    )