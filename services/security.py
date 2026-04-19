import os
import secrets
import string
import time

from email_validator import validate_email as ev_validate_email, EmailNotValidError

from flask import has_request_context, request

from services.storage import load_security_logs, save_security_logs


def init_security_logging(app):
    """Ensure security log storage exists for encrypted-at-rest events."""
    log_path = os.path.abspath(app.config["SECURITY_LOG_FILE"])
    parent = os.path.dirname(log_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    if not os.path.exists(log_path):
        save_security_logs([])


def validate_username(username):
    if len(username) < 3 or len(username) > 20:
        return False
    for char in username:
        if not (char.isalnum() or char == "_"):
            return False
    return True


def validate_email(email):
    try:
        ev_validate_email(email)
        return True
    except EmailNotValidError:
        return False


def validate_password(password):
    if len(password) < 12:
        return False
    has_upper = False
    has_lower = False
    has_number = False
    has_special = False
    special_chars = "!@#$%^&*"

    for char in password:
        if char.isupper():
            has_upper = True
        elif char.islower():
            has_lower = True
        elif char.isdigit():
            has_number = True
        elif char in special_chars:
            has_special = True
    return has_upper and has_lower and has_number and has_special


def log_event(event_type, username=None, ip=None, details=None):
    if has_request_context():
        ip_addr = ip if ip is not None else request.remote_addr
        user_agent = request.headers.get("User-Agent")
    else:
        ip_addr = ip
        user_agent = None

    payload = {
        "event": event_type,
        "user": username,
        "ip": ip_addr,
        "details": details,
        "user_agent": user_agent,
        "ts": time.time(),
    }
    logs = load_security_logs()
    logs.append(payload)
    save_security_logs(logs)


def generate_secure_temp_password(length=16):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(length))
        has_upper = any(c.isupper() for c in candidate)
        has_lower = any(c.islower() for c in candidate)
        has_number = any(c.isdigit() for c in candidate)
        has_special = any(c in "!@#$%^&*" for c in candidate)
        if has_upper and has_lower and has_number and has_special:
            return candidate


def security_log_rows(logs):
    """Newest-first rows for Jinja (values are escaped by the template)."""
    if not logs:
        return []
    rows = []
    for entry in reversed(logs):
        ts = float(entry.get("ts", 0))
        readable_ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "-"
        rows.append(
            {
                "event": entry.get("event", "UNKNOWN"),
                "user": entry.get("user") or "-",
                "ip": entry.get("ip") or "-",
                "details": entry.get("details") or "-",
                "ua": entry.get("user_agent") or "-",
                "ts": readable_ts,
            }
        )
    return rows
