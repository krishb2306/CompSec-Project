import time
from functools import wraps

import bcrypt
from flask import abort, current_app, redirect, session, url_for

from services.storage import load_users, save_users


def get_current_user():
    username = session.get("username")
    if not username:
        return None
    users = load_users()
    for user in users:
        if user["username"] == username:
            return user
    return None


def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("home.home"))
        return f(*args, **kwargs)

    return decorated_function


def require_role(min_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user()
            if not user:
                return redirect(url_for("home.home"))
            user_role = user.get("role", "guest")
            role_hierarchy = current_app.config["ROLE_HIERARCHY"]
            if role_hierarchy.get(user_role, 0) < role_hierarchy.get(min_role, 0):
                abort(403)
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def ensure_admin_user():
    """Ensure one admin account exists (override credentials via env in production)."""
    username = current_app.config["ADMIN_USERNAME"]
    email = current_app.config["ADMIN_EMAIL"]
    password = current_app.config["ADMIN_PASSWORD"]

    users = load_users()
    for u in users:
        if u["username"] == username:
            if u.get("role") != "admin":
                u["role"] = "admin"
                save_users(users)
            return

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(12))
    users.append(
        {
            "username": username,
            "email": email,
            "password": hashed.decode("utf-8"),
            "role": "admin",
            "failed_attempts": 0,
            "locked_until": None,
            "created_at": time.time(),
        }
    )
    save_users(users)


def ensure_guest_user():
    users = load_users()
    guest_exists = any(u["username"] == "guest" for u in users)
    if not guest_exists:
        users.append(
            {
                "username": "guest",
                "password": "",
                "role": "guest",
            }
        )
        save_users(users)
