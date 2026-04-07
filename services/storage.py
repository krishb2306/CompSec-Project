import json
import os

from flask import current_app


def ensure_storage_directories():
    os.makedirs(current_app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(os.path.dirname(current_app.config["USERS_FILE"]), exist_ok=True)
    os.makedirs(os.path.dirname(current_app.config["SECURITY_LOG_FILE"]), exist_ok=True)


def load_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)


def load_users():
    return load_json(current_app.config["USERS_FILE"], [])


def save_users(users):
    save_json(current_app.config["USERS_FILE"], users)


def load_files():
    return load_json(current_app.config["FILES_FILE"], [])


def save_files(files):
    save_json(current_app.config["FILES_FILE"], files)


def load_shares():
    return load_json(current_app.config["SHARES_FILE"], [])


def save_shares(shares):
    save_json(current_app.config["SHARES_FILE"], shares)


def load_logs():
    return load_json(current_app.config["SECURITY_JSON_FILE"], [])


def save_logs(logs):
    save_json(current_app.config["SECURITY_JSON_FILE"], logs)
