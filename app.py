import json
import os
import uuid

from flask import Flask, request, redirect, url_for, session, send_from_directory

app = Flask(__name__)
app.secret_key = "dev-secret-key"  # basic app only; replace later

DATA_DIR = 'data'
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
FILES_FILE = os.path.join(DATA_DIR, 'files.json')
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


'''
TODO:
[ ] Formatting and styling
'''
@app.route('/')
def home():
    username = session.get('username')

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

    files = load_files()
    user_files = [f for f in files if f['owner'] == username]

    file_list_html = ''
    if user_files:
        for f in user_files:
            file_list_html += f'''
            <li>
                {f['original_name']}
                - <a href='/download/{f['stored_name']}'>Download</a>
            </li>
            '''
    else:
        file_list_html = '<li>No files uploaded yet.</li>'

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
        {file_list_html}
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
            return 'Username already exists. <a href='/'>Go back</a>'

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

    unique_name = f'{uuid.uuid4()}_{file.filename}'
    file_path = os.path.join(UPLOAD_FOLDER, unique_name)
    file.save(file_path)

    files = load_files()
    files.append({
        'owner': session['username'],
        'original_name': file.filename,
        'stored_name': unique_name
    })
    save_files(files)

    return redirect(url_for('home'))


@app.route('/download/<stored_name>')
def download(stored_name):
    if 'username' not in session:
        return redirect(url_for('home'))

    files = load_files()
    current_user = session['username']

    for f in files:
        if f['stored_name'] == stored_name and f['owner'] == current_user:
            return send_from_directory(
                UPLOAD_FOLDER,
                stored_name,
                as_attachment=True,
                download_name=f['original_name']
            )

    return 'File not found or access denied. <a href='/'>Go back</a>'


if __name__ == '__main__':
    app.run(debug=True)