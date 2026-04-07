import time

import bcrypt
from flask import Blueprint, redirect, request, session, url_for

from services.security import (
    log_event,
    validate_email,
    validate_password,
    validate_username,
)
from services.storage import load_users, save_users


auth_bp = Blueprint("auth", __name__)

login_attempts = {}


@auth_bp.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "").strip()
    confirm = request.form.get("confirm_password", "").strip()

    if not username or not email or not password or not confirm:
        return "All fields are required."
    if not validate_username(username):
        return "Invalid username (3-20 chars, letters/numbers/_ only)."
    if not validate_email(email):
        return "Invalid email format."
    if not validate_password(password):
        return "Password must be 12+ chars with upper, lower, number, special."
    if password != confirm:
        return "Passwords do not match."

    users = load_users()
    for user in users:
        if user["username"] == username:
            return "Username already exists."
        if user.get("email") == email:
            return "Email already exists."

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(12))
    new_user = {
        "username": username,
        "email": email,
        "password": hashed.decode("utf-8"),
        "role": "user",
        "failed_attempts": 0,
        "locked_until": None,
        "created_at": time.time(),
    }
    users.append(new_user)
    save_users(users)
    session["username"] = username
    log_event("REGISTER_SUCCESS", username)
    return redirect(url_for("home.home"))


@auth_bp.route("/login", methods=["POST"])
def login():
    ip = request.remote_addr
    current_time = time.time()
    if ip not in login_attempts:
        login_attempts[ip] = []

    login_attempts[ip] = [t for t in login_attempts[ip] if current_time - t < 60]
    if len(login_attempts[ip]) >= 10:
        log_event("RATE_LIMIT", None, ip)
        return "Too many login attempts. Try again later."
    login_attempts[ip].append(current_time)

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    users = load_users()

    for user in users:
        if user["username"] == username:
            if user.get("locked_until") and time.time() < user["locked_until"]:
                log_event("LOGIN_BLOCKED_LOCKED", username, ip)
                return "Account locked. Try again later."

            if bcrypt.checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
                user["failed_attempts"] = 0
                user["locked_until"] = None
                save_users(users)
                log_event("LOGIN_SUCCESS", username, ip)
                session["username"] = username
                return redirect(url_for("home.home"))

            user["failed_attempts"] += 1
            log_event("LOGIN_FAILED", username, ip)
            if user["failed_attempts"] >= 5:
                user["locked_until"] = time.time() + (15 * 60)
                log_event("ACCOUNT_LOCKED", username, ip)
            save_users(users)
            return "Invalid username or password."

    log_event("LOGIN_FAILED", username, ip)
    return "Invalid username or password."


@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home.home"))
