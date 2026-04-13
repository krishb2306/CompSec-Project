import html
import os
import re
from werkzeug.utils import secure_filename

# XSS
def sanitize_input(user_input):
    if not isinstance(user_input, str):
        return user_input
    return html.escape(user_input)

def sanitize_output(data):
    if isinstance(data, str):
        return html.escape(data)
    return data

# Command Injection
def safe_filename(filename):
    filename = os.path.basename(filename)
    if not re.match(r'^[\w\-\.]+$', filename):
        raise ValueError("Invalid filename")
    return filename

# Path Traversal
def safe_file_path(user_path, base_dir):
    filename = secure_filename(user_path)
    full_path = os.path.join(base_dir, filename)

    if not os.path.abspath(full_path).startswith(os.path.abspath(base_dir)):
        raise ValueError("Path traversal detected")

    return full_path

# General Length
def validate_length(value, min_len=1, max_len=100):
    if not value or not (min_len <= len(value) <= max_len):
        raise ValueError("Invalid length")
    return value