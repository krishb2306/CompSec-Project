import os


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, os.environ.get("DATA_DIR", "data"))
LOGS_DIR = os.path.join(BASE_DIR, os.environ.get("LOGS_DIR", "logs"))

ROLE_HIERARCHY = {
    "guest": 1,
    "user": 2,
    "admin": 3,
}


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")
    # Secure session cookie (idle timeout in seconds; template default 30 min).
    SESSION_TIMEOUT = int(os.environ.get("SESSION_TIMEOUT", "1800"))
    SESSION_COOKIE_NAME = os.environ.get("SESSION_COOKIE_NAME", "session_token")
    SESSION_SAMESITE = os.environ.get("SESSION_SAMESITE", "Strict")
    # Set to "0" for HTTP local dev. If unset, secure cookies are off when DEBUG.
    _sc = os.environ.get("SESSION_COOKIE_SECURE", "").strip().lower()
    SESSION_COOKIE_SECURE = None if _sc == "" else _sc in ("1", "true", "yes")
    LOGIN_RATE_LIMIT = int(os.environ.get("LOGIN_RATE_LIMIT", "10"))
    FAILED_ATTEMPTS_LIMIT = int(os.environ.get("FAILED_ATTEMPTS_LIMIT", "5"))
    LOCKOUT_DURATION = int(os.environ.get("LOCKOUT_DURATION", "15"))
    # Bootstrap admin (created on startup if missing). Override via env in production.
    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
    ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@gmail.com")
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "ChangeMeAdmin123!")
    USERS_FILE = os.path.join(DATA_DIR, "users.json")
    FILES_FILE = os.path.join(DATA_DIR, "files.json")
    SHARES_FILE = os.path.join(DATA_DIR, "shares.json")
    SESSIONS_FILE = os.path.join(DATA_DIR, "sessions.json")
    SECURITY_LOG_FILE = os.path.join(LOGS_DIR, "security.log")
    UPLOAD_FOLDER = os.path.join(BASE_DIR, os.environ.get("UPLOAD_FOLDER", "uploads"))
    MAX_UPLOAD_SIZE_BYTES = int(os.environ.get("MAX_UPLOAD_SIZE_BYTES", str(5 * 1024 * 1024))) # 5 MBytes
    ROLE_HIERARCHY = ROLE_HIERARCHY
