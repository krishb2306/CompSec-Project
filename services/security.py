import logging
import time

from flask import request

from services.storage import load_logs, save_logs


security_logger = logging.getLogger("security")
if not security_logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    security_logger.addHandler(handler)
security_logger.setLevel(logging.INFO)


def validate_username(username):
    if len(username) < 3 or len(username) > 20:
        return False
    for char in username:
        if not (char.isalnum() or char == "_"):
            return False
    return True


def validate_email(email):
    return "@" in email and "." in email


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


def log_event(event_type, username=None, ip=None):
    ip_addr = ip or request.remote_addr
    logs = load_logs()
    logs.append(
        {
            "time": time.time(),
            "event": event_type,
            "user": username,
            "ip": ip_addr,
            "user_agent": request.headers.get("User-Agent"),
        }
    )
    save_logs(logs)
    security_logger.info("%s user=%s ip=%s", event_type, username, ip_addr)
