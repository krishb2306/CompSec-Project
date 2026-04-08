import secrets
import time

from flask import request, session

from services.security import log_event
from services.storage import load_sessions, save_sessions


def create_logged_session(username, ip=None):
    token = secrets.token_urlsafe(32)
    now = time.time()
    ip_addr = ip if ip is not None else request.remote_addr
    user_agent = request.headers.get("User-Agent")

    sessions = load_sessions()
    sessions[token] = {
        "username": username,
        "created_at": now,
        "last_activity": now,
        "ip": ip_addr,
        "user_agent": user_agent,
    }
    save_sessions(sessions)

    session["session_token"] = token
    session["username"] = username
    log_event("SESSION_CREATED", username, ip_addr)
    return token


def touch_session():
    token = session.get("session_token")
    if not token:
        return
    sessions = load_sessions()
    if token not in sessions:
        return
    sessions[token]["last_activity"] = time.time()
    save_sessions(sessions)


def destroy_logged_session(username_for_log=None, ip=None):
    token = session.get("session_token")
    username = username_for_log or session.get("username")
    ip_addr = ip if ip is not None else request.remote_addr

    if token:
        sessions = load_sessions()
        if token in sessions:
            del sessions[token]
            save_sessions(sessions)

    session.clear()
    if username:
        log_event("SESSION_DESTROYED", username, ip_addr)
