import json
import os

from flask import current_app
from services.encryption import EncryptedStorage

storage = EncryptedStorage()

def ensure_storage_directories():
    os.makedirs(current_app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(os.path.dirname(current_app.config["USERS_FILE"]), exist_ok=True)
    os.makedirs(os.path.dirname(current_app.config["FILES_FILE"]), exist_ok=True)
    os.makedirs(os.path.dirname(current_app.config["SHARES_FILE"]), exist_ok=True)
    os.makedirs(os.path.dirname(current_app.config["SESSIONS_FILE"]), exist_ok=True)
    os.makedirs(os.path.dirname(current_app.config["SECURITY_LOG_FILE"]), exist_ok=True)


def load_users():
    return storage.load_encrypted(current_app.config["USERS_FILE"])


def save_users(users):
    storage.save_encrypted(current_app.config["USERS_FILE"], users)


def load_files():
    return storage.load_encrypted(current_app.config["FILES_FILE"])


def save_files(files):
    storage.save_encrypted(current_app.config["FILES_FILE"], files)


def load_shares():
    return storage.load_encrypted(current_app.config["SHARES_FILE"])


def save_shares(shares):
    storage.save_encrypted(current_app.config["SHARES_FILE"], shares)


def load_sessions():
    data = storage.load_encrypted(current_app.config["SESSIONS_FILE"])
    if isinstance(data, dict):
        return data
    return {}


def save_sessions(sessions):
    storage.save_encrypted(current_app.config["SESSIONS_FILE"], sessions)


def load_security_logs():
    data = storage.load_encrypted(current_app.config["SECURITY_LOG_FILE"])
    if isinstance(data, list):
        return data
    return []


def save_security_logs(logs):
    storage.save_encrypted(current_app.config["SECURITY_LOG_FILE"], logs)
