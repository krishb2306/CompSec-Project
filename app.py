import json
import os
import uuid
import bcrypt
import time
from functools import wraps

from flask import Flask, request, redirect, url_for, session, send_from_directory, abort

app = Flask(__name__)
app.secret_key = 'dev-secret-key'  # basic app only; replace later

DATA_DIR = 'data'
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
FILES_FILE = os.path.join(DATA_DIR, 'files.json')
SHARES_FILE = os.path.join(DATA_DIR, 'shares.json')
LOG_FILE = os.path.join(DATA_DIR, 'security.json')
UPLOAD_FOLDER = 'uploads'

login_attempts = {}

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


ROLE_HIERARCHY = {
    'guest': 1,
    'user': 2,
    'admin': 3
}

def load_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except:
        return default

def save_json(path, data):
    with open(path, 'w') as f:
        json.dump(data, f, indent=4)

def load_users():
    return load_json(USERS_FILE, [])

def save_users(users):
    save_json(USERS_FILE, users)

def load_files():
    return load_json(FILES_FILE, [])

def save_files(files):
    save_json(FILES_FILE, files)

def load_logs():
    return load_json(LOG_FILE, [])

def save_logs(logs):
    save_json(LOG_FILE, logs)

def load_shares():
    return load_json(SHARES_FILE, [])

def save_shares(shares):
    save_json(SHARES_FILE, shares)

def get_current_user():
    username = session.get('username')
    if not username:
        return None
    
    users = load_users()
    for user in users:
        if user['username'] == username:
            return user
    return None

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def require_role(min_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user()
            if not user:
                return redirect(url_for('home'))
            user_role = user.get('role', 'guest')
            if ROLE_HIERARCHY.get(user_role, 0) < ROLE_HIERARCHY.get(min_role, 0):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_username(username):
    if len(username) < 3 or len(username) > 20:
        return False
    
    for char in username:
        if not (char.isalnum() or char == '_'):
            return False

    return True

def validate_email(email):
    if '@' not in email or '.' not in email:
        return False
    return True

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
    logs = load_logs()

    logs.append({
        "time": time.time(),
        "event": event_type,
        "user": username,
        "ip": ip
    })

    save_logs(logs)

@app.route('/')
def home():
    current_user = get_current_user()
    files = load_files()
    shares = load_shares()

    public_file_ids = [s['file_id'] for s in shares if s['shared_with'] == 'guest']
    public_files = [f for f in files if f['id'] in public_file_ids]
    public_html = ''
    if public_files:
        for f in public_files:
            public_html += f'''
            <li>
                <b>{f['original_name']}</b>
                (shared publicly by {f['owner']})
                - <a href='/download/{f['stored_name']}'>Download</a>
            </li>
            '''
    else:
        public_html = '<li>No public files available.</li>'

    if not current_user:
        return f'''
        <h1>Secure Document Sharing System</h1>
        <p>Welcome! Please login or register.</p>

        <h2>Publicly Shared Files</h2>
        <ul>
            {public_html}
        </ul>

        <h2>Register</h2>
        <form method='POST' action='/register'>
            <input name='username' placeholder='Username' required><br><br>
            <input name='email' placeholder='Email' required><br><br>
            <input name='password' type='password' placeholder='Password' required><br><br>
            <input name='confirm_password' type='password' placeholder='Confirm Password' required><br><br>
            <button type='submit'>Register</button>
        </form>

        <h2>Login</h2>
        <form method='POST' action='/login'>
            <input name='username' placeholder='Username' required><br><br>
            <input name='password' type='password' placeholder='Password' required><br><br>
            <button type='submit'>Login</button>
        </form>
        '''

    username = current_user['username']
    role = current_user.get('role', 'user')

    upload_html = ''
    if role in ('user', 'admin'):
        upload_html = '''
        <h2>Upload File</h2>
        <form method='POST' action='/upload' enctype='multipart/form-data'>
            <input type='file' name='file' required>
            <button type='submit'>Upload</button>
        </form>
        '''
    
    owned_files = [f for f in files if f['owner'] == username]
    owned_html = ''
    if owned_files:
        for f in owned_files:
            owned_html += f'''
            <li>
                <b>{f['original_name']}</b>
                - <a href='/download/{f['stored_name']}'>Download</a>

                <form method='POST' action='/share/{f['id']}' style='margin-top:8px; margin-bottom:12px;'>
                    <input name='shared_with' placeholder='Username or guest (public)' required>
                    <button type='submit'>Share</button>
                </form>

                <form method='POST' action='/delete/{f['id']}' style='display:inline; margin-left:8px;'>
                    <button type='submit'>Delete</button>
                </form>
            </li>
            '''
    else:
        owned_html = '<li>No files uploaded yet.</li>'

    shared_file_ids = [s['file_id'] for s in shares if s['shared_with'] == username]
    shared_files = [f for f in files if f['id'] in shared_file_ids]
    shared_html = ''
    if shared_files:
        for f in shared_files:
            shared_html += f'''
            <li>
                <b>{f['original_name']}</b>
                (shared by {f['owner']})
                - <a href='/download/{f['stored_name']}'>Download</a>
            </li>
            '''
    else:
        shared_html = '<li>No files have been shared with you.</li>'

    if role == 'admin':
        all_files = files
    else:
        all_files = []
    all_files_html = ''
    if all_files:
        for f in all_files:
            all_files_html += f'''
            <li>
                <b>{f['original_name']}</b>
                (owner: {f['owner']})
                - <a href='/download/{f['stored_name']}'>Download</a>
            </li>
            '''
    else:
        all_files_html = '<li>No files in the system.</li>'

    admin_html = ''
    if role == 'admin':
        admin_html = f'''
        <h2>Admin View</h2>
        <a href='/admin/users'>Manage Users</a>
        <h3>All Files</h3>
        <ul>
            {all_files_html}
        </ul>
        '''

    return f'''
    <h1>Home</h1>
    <p>Logged in as: <b>{username}</b> ({role})</p>
    <a href='/logout'>Logout</a>

    {upload_html}

    <h2>Your Files</h2>
    <ul>
        {owned_html}
    </ul>

    <h2>Files Shared With You</h2>
    <ul>
        {shared_html}
    </ul>

    <h2>Publicly Shared Files</h2>
    <ul>
        {public_html}
    </ul>

    {admin_html}
    '''


'''
TODO:
[ ] Username: 3-20 characters, alphanumeric + underscore
[ ] Email: Valid email format
[ ] Password: Minimum 12 characters, complexity requirements:
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 number
    - At least 1 special character
[ ] Password confirmation must match
[ ] Check for duplicate username/email
[ ] Salt + Hash
'''
@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()
    confirm = request.form.get('confirm_password', '').strip()

    if not username or not email or not password or not confirm:
        return "All fields are required."

    if not validate_username(username):
        return "Invalid username (3-20 chars, letters/numbers/_ only)."

    if not validate_email(email):
        return "Invalid email format."

    if not validate_password(password):
        return "Password must be 12+ chars with upper, lower, number, special."

    if password != confirm:
        return "Passwords do not match."

    users = load_users()

    for user in users:
        if user['username'] == username:
            return "Username already exists."
        if user.get('email') == email:
            return "Email already exists."

    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(12))

    new_user = {
        'username': username,
        'email': email,
        'password': hashed.decode('utf-8'),
        'role': 'user',
        'failed_attempts': 0,
        'locked_until': None,
        'created_at': time.time()
    }

    users.append(new_user)
    save_users(users)

    session['username'] = username
    return redirect(url_for('home'))


'''
TODO:
[ ] Implement account lockout after 5 failed attempts (15 minutes)
[ ] Rate limiting: Max 10 loging attempts per IP per minute
[ ] Session creation on successful login
[ ] Log all authentication attempts
'''
@app.route('/login', methods=['POST'])
def login():
    
    ip = request.remote_addr
    current_time = time.time()

    if ip not in login_attempts:
        login_attempts[ip] = []

    login_attempts[ip] = [
        t for t in login_attempts[ip]
        if current_time - t < 60
    ]

    if len(login_attempts[ip]) >= 10:
        log_event(f"RATE LIMIT EXCEEDED: {ip}")
        return "Too many login attempts. Try again later."

    login_attempts[ip].append(current_time)

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()

    users = load_users()

    for user in users:
        if user['username'] == username:

            if user.get('locked_until'):
                if time.time() < user['locked_until']:
                    log_event("LOGIN BLOCKED (LOCKED):", username, ip)
                    return "Account locked. Try again later."

            if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                user['failed_attempts'] = 0
                user['locked_until'] = None
                save_users(users)

                log_event("LOGIN_SUCCESS", username, ip)

                session['username'] = username
                return redirect(url_for('home'))

            else:
                user['failed_attempts'] += 1

                log_event("LOGIN_FAILED", username, ip)

                # 🔒 LOCK ACCOUNT AFTER 5 FAILS
                if user['failed_attempts'] >= 5:
                    user['locked_until'] = time.time() + (15 * 60)
                    log_event("ACCOUNT LOCKED", username, ip)

                save_users(users)
                return "Invalid username or password."

    log_event("LOGIN_FAILED", username, ip)
    return "Invalid username or password."

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


@app.route('/upload', methods=['POST'])
@require_auth
@require_role('user')
def upload():
    if 'file' not in request.files:
        return "No file selected. <a href='/'>Go back</a>"

    file = request.files['file']

    if file.filename == '':
        return "No file selected. <a href='/'>Go back</a>"

    file_id = str(uuid.uuid4())
    unique_name = f'{file_id}_{file.filename}'
    file_path = os.path.join(UPLOAD_FOLDER, unique_name)
    file.save(file_path)

    files = load_files()
    files.append({
        'id': file_id,
        'owner': session['username'],
        'original_name': file.filename,
        'stored_name': unique_name
    })
    save_files(files)

    return redirect(url_for('home'))


@app.route('/delete/<file_id>', methods=['POST'])
@require_auth
@require_role('user')
def delete_file(file_id):
    files = load_files()
    shares = load_shares()
    current_user = get_current_user()
    current_username = current_user['username']
    current_role = current_user.get('role', 'guest')

    target_file = next((f for f in files if f['id'] == file_id), None)
    if not target_file:
        return "File not found. <a href='/'>Go back</a>"

    if current_role != 'admin' and target_file['owner'] != current_username:
        return "Access denied. <a href='/'>Go back</a>"

    file_path = os.path.join(UPLOAD_FOLDER, target_file['stored_name'])
    if os.path.exists(file_path):
        os.remove(file_path)

    files = [f for f in files if f['id'] != file_id]
    shares = [s for s in shares if s['file_id'] != file_id]

    save_files(files)
    save_shares(shares)

    return redirect(url_for('home'))


@app.route("/share/<file_id>", methods=["POST"])
@require_auth
@require_role('user')
def share_file(file_id):
    current_user = get_current_user()
    current_username = current_user['username']
    current_role = current_user.get('role', 'user')

    shared_with = request.form.get('shared_with', '').strip()

    if not shared_with:
        return "Must provide a username to share with. <a href='/'>Go back</a>"

    users = load_users()
    files = load_files()
    shares = load_shares()

    user_exists = any(u["username"] == shared_with for u in users)
    if not user_exists:
        return "That user does not exist. <a href='/'>Go back</a>"

    if shared_with == current_username:
        return "You already own this file. <a href='/'>Go back</a>"

    target_file = next((f for f in files if f['id'] == file_id), None)
    if not target_file:
        return "File not found. <a href='/'>Go back</a>"

    if current_role != 'admin' and target_file['owner'] != current_username:
        return "You can only share your own files. <a href='/'>Go back</a>"

    for s in shares:
        if s.get("file_id") == file_id and s.get("shared_with") == shared_with:
            return redirect(url_for('home'))

    shares.append({
        'file_id': file_id,
        'owner': target_file['owner'],
        'shared_with': shared_with
    })
    save_shares(shares)

    return redirect(url_for("home"))


@app.route('/download/<stored_name>')
def download(stored_name):
    files = load_files()
    shares = load_shares()
    current_user = get_current_user()

    target_file = next((f for f in files if f['stored_name'] == stored_name), None)

    if not target_file:
        return "File not found. <a href='/'>Go back</a>"

    is_public = any(
        s['file_id'] == target_file['id'] and s['shared_with'] == 'guest'
        for s in shares
    )

    if current_user is None:
        if not is_public:
            return "File not found or access denied. <a href='/'>Go back</a>"
    else:
        current_username = current_user['username']
        current_role = current_user.get('role', 'user')

        is_admin = current_role == 'admin'
        is_owner = target_file['owner'] == current_username
        is_shared = any(
            s['file_id'] == target_file['id'] and s['shared_with'] == current_username
            for s in shares
        )

        if not (is_public or is_admin or is_owner or is_shared):
            return "File not found or access denied. <a href='/'>Go back</a>"

    return send_from_directory(
        UPLOAD_FOLDER,
        stored_name,
        as_attachment=True,
        download_name=target_file['original_name']
    )


@app.route('/admin/users')
@require_auth
@require_role('admin')
def admin_users():
    users = load_users()

    html = "<h1>User Management</h1><a href='/'>Back</a><ul>"
    for user in users:
        html += f"""
        <li>
            {user['username']} - role: <b>{user.get('role', 'guest')}</b>
            <form method='POST' action='/admin/set-role/{user["username"]}' style='display:inline; margin-left:10px;'>
                <select name='role'>
                    <option value='guest'>guest</option>
                    <option value='user'>user</option>
                    <option value='admin'>admin</option>
                </select>
                <button type='submit'>Update</button>
            </form>
        </li>
        """
    html += "</ul>"
    return html


@app.route('/admin/set-role/<username>', methods=['POST'])
@require_auth
@require_role('admin')
def set_role(username):
    new_role = request.form.get('role', '').strip()

    if new_role not in ROLE_HIERARCHY:
        return "Invalid role. <a href='/admin/users'>Go back</a>"

    users = load_users()

    admins = [u for u in users if u.get('role') == 'admin']
    target_user = next((u for u in users if u['username'] == username), None)

    if not target_user:
        return "User not found. <a href='/admin/users'>Go back</a>"

    if target_user.get('role') == 'admin' and new_role != 'admin' and len(admins) == 1:
        return "Cannot remove the last admin. <a href='/admin/users'>Go back</a>"

    target_user['role'] = new_role
    save_users(users)
    return redirect(url_for('admin_users'))


def ensure_guest_user():
    users = load_users()
    guest_exists = any(u['username'] == 'guest' for u in users)

    if not guest_exists:
        users.append({
            'username': 'guest',
            'password': '',
            'role': 'guest'
        })
        save_users(users)


if __name__ == '__main__':
    ensure_guest_user()
    app.run(debug=True)