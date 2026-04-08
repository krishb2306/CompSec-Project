import json
import logging
import os
import time

from email_validator import validate_email as ev_validate_email, EmailNotValidError

from flask import has_request_context, request

security_logger = logging.getLogger("security")
security_logger.setLevel(logging.INFO)
security_logger.propagate = False


def init_security_logging(app):
    """Append security events to logs/security.log (plain text, one JSON object per line)."""
    log_path = os.path.abspath(app.config["SECURITY_LOG_FILE"])
    parent = os.path.dirname(log_path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    for h in security_logger.handlers:
        if isinstance(h, logging.FileHandler):
            existing = getattr(h, "baseFilename", None)
            if existing and os.path.abspath(existing) == log_path:
                return

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    security_logger.addHandler(fh)


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
        "user_agent": user_agent,
        "details": details,
        "ts": time.time(),
    }
    security_logger.info("%s", json.dumps(payload, default=str, ensure_ascii=False))
