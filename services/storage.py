import json
import os

from flask import current_app
from services.encryption import EncryptedStorage

storage = EncryptedStorage()

def ensure_storage_directories():
    os.makedirs(current_app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(os.path.dirname(current_app.config["USERS_FILE"]), exist_ok=True)
    os.makedirs(os.path.dirname(current_app.config["SECURITY_LOG_FILE"]), exist_ok=True)


def load_users():
    return storage.load(current_app.config["USERS_FILE"])


def save_users(users):
    storage.save(current_app.config["USERS_FILE"], users)


def load_files():
    return storage.load(current_app.config["FILES_FILE"])


def save_files(files):
    storage.save(current_app.config["FILES_FILE"], files)


def load_shares():
    return storage.load(current_app.config["SHARES_FILE"])


def save_shares(shares):
    storage.save(current_app.config["SHARES_FILE"], shares)


def load_logs():
    return storage.load(current_app.config["SECURITY_LOG_FILE"])

def save_logs(logs):
    storage.save(current_app.config["SECURITY_LOG_FILE"], logs)
