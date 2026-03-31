import json
import os
import uuid

from flask import Flask, request, redirect, url_for, session, send_from_directory

app = Flask(__name__)
app.secret_key = 'dev-secret-key'  # basic app only; replace later

DATA_DIR = 'data'
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
FILES_FILE = os.path.join(DATA_DIR, 'files.json')
SHARES_FILE = os.path.join(DATA_DIR, 'shares.json')
UPLOAD_FOLDER = 'uploads'

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, 'r') as f:
        return json.load(f)

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

def load_shares():
    return load_json(SHARES_FILE, [])

def save_shares(shares):
    save_json(SHARES_FILE, shares)


@app.route('/')
def home():
    username = session.get('username')
    files = load_files()
    shares = load_shares()

    if not username:
        return '''
        <h1>Secure Document Sharing System</h1>
        <p>Welcome! Please login or register.</p>

        <h2>Register</h2>
        <form method='POST' action='/register'>
            <input name='username' placeholder='Username' required><br><br>
            <input name='password' type='password' placeholder='Password' required><br><br>
            <button type='submit'>Register</button>
        </form>

        <h2>Login</h2>
        <form method='POST' action='/login'>
            <input name='username' placeholder='Username' required><br><br>
            <input name='password' type='password' placeholder='Password' required><br><br>
            <button type='submit'>Login</button>
        </form>
        '''

    owned_files = [f for f in files if f['owner'] == username]

    shared_file_ids = [s['file_id'] for s in shares if s['shared_with'] == username]
    shared_files = [f for f in files if f['id'] in shared_file_ids]

    owned_html = ''
    if owned_files:
        for f in owned_files:
            owned_html += f'''
            <li>
                <b>{f['original_name']}</b>
                - <a href='/download/{f['stored_name']}'>Download</a>

                <form method='POST' action='/share/{f['id']}' style='margin-top:8px; margin-bottom:12px;'>
                    <input name='shared_with' placeholder='Username to share with' required>
                    <button type='submit'>Share</button>
                </form>
            </li>
            '''
    else:
        owned_html = '<li>No files uploaded yet.</li>'

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

    return f'''
    <h1>Home</h1>
    <p>Logged in as: <b>{username}</b></p>
    <a href='/logout'>Logout</a>

    <h2>Upload File</h2>
    <form method='POST' action='/upload' enctype='multipart/form-data'>
        <input type='file' name='file' required>
        <button type='submit'>Upload</button>
    </form>

    <h2>Your Files</h2>
    <ul>
        {owned_html}
    </ul>

    <h2>Files Shared With You</h2>
    <ul>
        {shared_html}
    </ul>
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
    password = request.form.get('password', '').strip()

    if not username or not password:
        return 'Username and password are required.'

    users = load_users()

    for user in users:
        if user['username'] == username:
            return "Username already exists. <a href='/'>Go back</a>"

    new_user = {
        'username': username,
        'password': password
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
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()

    users = load_users()

    for user in users:
        if user['username'] == username and user['password'] == password:
            session['username'] = username
            return redirect(url_for('home'))

    return 'Invalid username or password. <a href='/'>Go back</a>'


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


@app.route('/upload', methods=['POST'])
def upload():
    if 'username' not in session:
        return redirect(url_for('home'))

    if 'file' not in request.files:
        return 'No file selected. <a href='/'>Go back</a>'

    file = request.files['file']

    if file.filename == '':
        return 'No file selected. <a href='/'>Go back</a>'

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


@app.route("/share/<file_id>", methods=["POST"])
def share_file(file_id):
    if "username" not in session:
        return redirect(url_for("home"))

    current_user = session["username"]
    shared_with = request.form.get("shared_with", "").strip()

    if not shared_with:
        return "Must provide a username to share with. <a href='/'>Go back</a>"

    users = load_users()
    files = load_files()
    shares = load_shares()

    user_exists = any(u["username"] == shared_with for u in users)
    if not user_exists:
        return "That user does not exist. <a href='/'>Go back</a>"

    if shared_with == current_user:
        return "You already own this file. <a href='/'>Go back</a>"

    target_file = None
    for f in files:
        if f.get("id") == file_id:
            target_file = f
            break

    if not target_file:
        return "File not found. <a href='/'>Go back</a>"

    if target_file.get("owner") != current_user:
        return "You can only share your own files. <a href='/'>Go back</a>"

    for s in shares:
        if s.get("file_id") == file_id and s.get("shared_with") == shared_with:
            return redirect(url_for("home"))

    shares.append({
        "file_id": file_id,
        "owner": current_user,
        "shared_with": shared_with
    })
    save_shares(shares)

    return redirect(url_for("home"))


@app.route('/download/<stored_name>')
def download(stored_name):
    if 'username' not in session:
        return redirect(url_for('home'))

    files = load_files()
    shares = load_shares()
    current_user = session['username']

    target_file = None
    for f in files:
        if f['stored_name'] == stored_name:
            target_file = f
            break

    if not target_file:
        return 'File not found. <a href='/'>Go back</a>'

    is_owner = target_file['owner'] == current_user
    is_shared = any(
        s['file_id'] == target_file['id'] and s['shared_with'] == current_user
        for s in shares
    )

    if not is_owner and not is_shared:
        return 'File not found or access denied. <a href='/'>Go back</a>'

    return send_from_directory(
        UPLOAD_FOLDER,
        stored_name,
        as_attachment=True,
        download_name=target_file['original_name']
    )


if __name__ == '__main__':
    app.run(debug=True)