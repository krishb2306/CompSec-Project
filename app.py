import json
import os

from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

USERS_FILE = 'data/users.json'

@app.route('/')
@app.route('/')
def home():
    return '''
        <h1>Welcome</h1>
        <a href="/register">Register</a><br>
        <a href="/login">Login</a>
    '''
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        users = load_users()

        # Check if username already exists
        for user in users:
            if user['username'] == username:
                return "Username already exists!"

        # Add new user
        new_user = {
            "username": username,
            "password": password
        }

        users.append(new_user)
        save_users(users)

        return f"User {username} registered successfully!"

    return '''
        <h2>Register</h2>
        <form method="POST">
            <input name="username" placeholder="Username" required><br>
            <input name="password" type="password" placeholder="Password" required><br>
            <button type="submit">Register</button>
        </form>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        return f"Logged in: {username}"
    return '''
        <h2>Login</h2>
        <form method="POST">
            <input name="username" placeholder="Username" required><br>
            <input name="password" type="password" placeholder="Password" required><br>
            <button type="submit">Login</button>
        </form>
    '''
def load_users():
    if not os.path.exists(USERS_FILE):
        return []
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)
if __name__ == '__main__':
    app.run(debug=True)