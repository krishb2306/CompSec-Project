import time

import bcrypt
from flask import Blueprint, make_response, redirect, request, url_for

from ui.pages import render_message_page
from services.security import (
    log_event,
    validate_email,
    validate_password,
    validate_username,
)
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
        log_event("REGISTER_FAILED", username or None, ip, details="missing_fields")
        return render_message_page("Registration", "All fields are required.")
    try:
        validate_length(username, min_len=3, max_len=20)
        validate_length(email, min_len=5, max_len=100)
        validate_length(password, min_len=12, max_len=128)
    except ValueError as e:
        log_event("REGISTER_FAILED", username or None, ip, details="length_validation")
        return render_message_page("Registration", str(e))
    
    if not validate_username(username):
        log_event("REGISTER_FAILED", username, ip, details="invalid_username")
        return render_message_page(
            "Registration",
            "Invalid username. Use 3–20 characters: letters, numbers, and underscores only.",
        )
    if not validate_email(email):
        log_event("REGISTER_FAILED", username, ip, details="invalid_email")
        return render_message_page("Registration", "Invalid email format.")
    if not validate_password(password):
        log_event("REGISTER_FAILED", username, ip, details="invalid_password")
        return render_message_page(
            "Registration",
            "Password must be at least 12 characters and include upper, lower, number, and special (!@#$%^&*).",
        )
    if password != confirm:
        log_event("REGISTER_FAILED", username, ip, details="password_mismatch")
        return render_message_page("Registration", "Passwords do not match.")

    users = load_users()
    for user in users:
        if user["username"] == username:
            log_event("REGISTER_FAILED", username, ip, details="duplicate_username")
            return render_message_page("Registration", "That username is already taken.")
        if user.get("email") == email:
            log_event("REGISTER_FAILED", username, ip, details="duplicate_email")
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
        "created_at": time.time(),
    }
    users.append(new_user)
    save_users(users)
    token = create_logged_session(username, ip)
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
        log_event("RATE_LIMIT", None, ip, details="login_attempts_per_ip")
        return render_message_page(
            "Too many attempts",
            "Too many login attempts from this network. Please wait a minute and try again.",
        )
    login_attempts[ip].append(current_time)

    username = sanitize_input(request.form.get("username", "").strip())
    password = request.form.get("password", "").strip()
    
    log_event("LOGIN_ATTEMPT", username or None, ip)

    if username and (len(username) < 1 or len(username) > 20):
        log_event("LOGIN_FAILED", username, ip, details="invalid_username_format")
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