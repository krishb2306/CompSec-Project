# Computer Security Project

This project is a Flask-based secure document sharing app with role-based access controls. It includes hardened authentication features like password policy enforcement, rate-limited login attempts, account lockouts, and session controls. Security-focused file handling is also included, with upload validation and audit-style security logging.

## Virtual Environment Setup (optional)

1. Open a terminal in the project root:
   ```bash
   cd /path/to/project
   ```
2. Create a virtual environment:
   ```bash
   python3 -m venv .venv
   ```
3. Activate it:
   ```bash
   source .venv/bin/activate
   ```

## Download Required Packages

Install dependencies from `requirements.txt`:

```bash
pip install -r requirements.txt
```

## Certificate Generation

The app starts with TLS and expects `cert.pem` and `key.pem` in the project root.

Generate them with OpenSSL:

```bash
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
```

## App Startup Instructions

1. (Optional) Set environment variables in a `.env` file (for example `SECRET_KEY`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`).
2. Start the application:
   ```bash
   python app.py
   ```
3. Open your browser at:
   [https://localhost:5001](https://localhost:5001)

## Admin Login Instructions

An admin account is auto-created on startup if it does not already exist.

- Default username: `admin`
- Default email: `admin@gmail.com`
- Default password: `ChangeMeAdmin123!`

Sign in from the home page using the admin username and password above (or your overridden values from environment variables). For security, change the default admin password immediately after first login.
