import secrets
import time

from flask import current_app, g, has_request_context, request

from services.security import log_event
from services.storage import load_sessions, save_sessions


class SessionManager:
    """Server-side sessions with timeout, aligned with secure cookie pattern."""

    def __init__(self, timeout=1800):
        self.timeout = timeout

    def create_session(self, user_id):
        """Create a new session token and persist metadata (user_id = username in this app)."""
        token = secrets.token_urlsafe(32)
        now = time.time()
        ip_addr = request.remote_addr
        user_agent = request.headers.get("User-Agent")

        record = {
            "token": token,
            "user_id": user_id,
            "created_at": now,
            "last_activity": now,
            "ip_address": ip_addr,
            "user_agent": user_agent,
            # Aliases for admin UI / older rows
            "username": user_id,
            "ip": ip_addr,
        }

        sessions = load_sessions()
        sessions[token] = record
        save_sessions(sessions)
        return token

    def validate_session(self, token):
        """Return session dict if valid; enforce idle timeout and refresh last_activity."""
        if not token:
            return None

        sessions = load_sessions()
        if token not in sessions:
            return None

        rec = sessions[token]
        user_id = rec.get("user_id") or rec.get("username")
        if not user_id:
            del sessions[token]
            save_sessions(sessions)
            return None

        last = rec.get("last_activity")
        if last is None:
            last = rec.get("created_at", 0)
        try:
            last_f = float(last)
        except (TypeError, ValueError):
            last_f = 0.0

        if time.time() - last_f > self.timeout:
            del sessions[token]
            save_sessions(sessions)
            return None

        now = time.time()
        rec["last_activity"] = now
        rec["user_id"] = user_id
        sessions[token] = rec
        save_sessions(sessions)
        return rec

    def destroy_session(self, token):
        if not token:
            return
        sessions = load_sessions()
        if token in sessions:
            del sessions[token]
            save_sessions(sessions)


def get_session_manager():
    timeout = current_app.config.get("SESSION_TIMEOUT", 1800)
    return SessionManager(timeout=timeout)


def _cookie_name():
    return current_app.config.get("SESSION_COOKIE_NAME", "session_token")


def session_cookie_settings():
    """Parameters for Set-Cookie (login / logout)."""
    secure = current_app.config.get("SESSION_COOKIE_SECURE")
    if secure is None:
        secure = not current_app.debug
    return {
        "key": _cookie_name(),
        "max_age": int(current_app.config.get("SESSION_TIMEOUT", 1800)),
        "httponly": True,
        "secure": bool(secure),
        "samesite": current_app.config.get("SESSION_SAMESITE", "Strict"),
        "path": "/",
    }


def attach_session_cookie(response, token):
    s = session_cookie_settings()
    response.set_cookie(
        s["key"],
        token,
        max_age=s["max_age"],
        httponly=s["httponly"],
        secure=s["secure"],
        samesite=s["samesite"],
        path=s["path"],
    )


def clear_session_cookie(response):
    s = session_cookie_settings()
    response.set_cookie(
        s["key"],
        "",
        max_age=0,
        httponly=s["httponly"],
        secure=s["secure"],
        samesite=s["samesite"],
        path=s["path"],
    )


def load_user_into_g():
    """
    Populate g.user_id, g.current_user, g.session_token from the session cookie.
    Sets g._clear_session_cookie when the cookie should be dropped (invalid/expired).
    """
    g.user_id = None
    g.current_user = None
    g.session_token = None
    g._clear_session_cookie = False

    if not has_request_context():
        return

    token = request.cookies.get(_cookie_name())
    if not token:
        return

    sm = get_session_manager()
    data = sm.validate_session(token)
    if not data:
        g._clear_session_cookie = True
        return

    user_id = data.get("user_id") or data.get("username")
    if not user_id:
        sm.destroy_session(token)
        g._clear_session_cookie = True
        return

    from services.storage import load_users

    users = load_users()
    user = next((u for u in users if u["username"] == user_id), None)
    if not user:
        sm.destroy_session(token)
        g._clear_session_cookie = True
        return

    g.user_id = user_id
    g.session_token = token
    g.current_user = user


def create_logged_session(username, ip=None):
    """Create server session; caller must attach attach_session_cookie to the response."""
    sm = get_session_manager()
    token = sm.create_session(username)
    ip_addr = ip if ip is not None else request.remote_addr
    log_event("SESSION_CREATED", username, ip_addr)
    return token


def destroy_logged_session(username_for_log=None, ip=None):
    """Remove server session; caller should clear_session_cookie on the response."""
    if not has_request_context():
        return

    token = request.cookies.get(_cookie_name()) or getattr(g, "session_token", None)
    username = username_for_log or getattr(g, "user_id", None)
    ip_addr = ip if ip is not None else request.remote_addr

    if token:
        get_session_manager().destroy_session(token)

    if username:
        log_event("SESSION_DESTROYED", username, ip_addr)


def destroy_session_by_token(session_token, actor_username=None, ip=None):
    sessions = load_sessions()
    target = sessions.get(session_token)
    if not target:
        return False

    terminated = target.get("user_id") or target.get("username")
    del sessions[session_token]
    save_sessions(sessions)
    log_event(
        "SESSION_FORCE_CLOSED",
        actor_username,
        ip,
        details=f"terminated_user={terminated}",
    )
    return True
