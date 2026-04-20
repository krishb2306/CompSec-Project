import time
from functools import wraps

import bcrypt
from flask import abort, current_app, g, has_request_context, redirect, url_for

from services.storage import load_users, save_users


def get_current_user():
    if not has_request_context():
        return None
    return getattr(g, "current_user", None)


# Supplementary RBAC logic (not really needed bc require_role kinda takes care of this, but just to be explicit)
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not get_current_user():
            return redirect(url_for("home.home"))
        return f(*args, **kwargs)

    return decorated_function


# Main RBAC logic
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


# Automatically creates an admin user if one doesn't exist on app startup
def ensure_admin_user():
    """Ensure one admin account exists (override credentials via env in production)."""
    username = current_app.config["ADMIN_USERNAME"]
    email = current_app.config["ADMIN_EMAIL"]
    password = current_app.config["ADMIN_PASSWORD"]

    users = load_users()
    for u in users:
        if u["username"] == username:
            if "locked_by_admin" not in u:
                u["locked_by_admin"] = False
            if "password_reset_requested" not in u:
                u["password_reset_requested"] = False
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
            "locked_by_admin": False,
            "password_reset_requested": False,
            "created_at": time.time(),
        }
    )
    save_users(users)


# Automatically creates a guest user if one doesn't exist on app startup (guest is treated as the public)
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
