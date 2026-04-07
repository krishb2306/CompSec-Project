import os


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, os.environ.get("DATA_DIR", "data"))
UPLOAD_FOLDER = os.path.join(BASE_DIR, os.environ.get("UPLOAD_FOLDER", "uploads"))
LOGS_DIR = os.path.join(BASE_DIR, os.environ.get("LOGS_DIR", "logs"))

USERS_FILE = os.path.join(DATA_DIR, "users.json")
FILES_FILE = os.path.join(DATA_DIR, "files.json")
SHARES_FILE = os.path.join(DATA_DIR, "shares.json")
SESSIONS_FILE = os.path.join(DATA_DIR, "sessions.json")
SECURITY_LOG_FILE = os.path.join(LOGS_DIR, "security.log")
SECURITY_JSON_FILE = os.path.join(DATA_DIR, "security.json")

ROLE_HIERARCHY = {
    "guest": 1,
    "user": 2,
    "admin": 3,
}


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")
    USERS_FILE = USERS_FILE
    FILES_FILE = FILES_FILE
    SHARES_FILE = SHARES_FILE
    SESSIONS_FILE = SESSIONS_FILE
    SECURITY_LOG_FILE = SECURITY_LOG_FILE
    SECURITY_JSON_FILE = SECURITY_JSON_FILE
    UPLOAD_FOLDER = UPLOAD_FOLDER
    ROLE_HIERARCHY = ROLE_HIERARCHY
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_SAMESITE = "Lax"
