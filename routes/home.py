from flask import Blueprint

from services.auth import get_current_user
from services.storage import load_files, load_shares


home_bp = Blueprint("home", __name__)


@home_bp.route("/")
def home():
    current_user = get_current_user()
    files = load_files()
    shares = load_shares()

    public_file_ids = [s["file_id"] for s in shares if s["shared_with"] == "guest"]
    public_files = [f for f in files if f["id"] in public_file_ids]
    public_html = ""
    if public_files:
        for f in public_files:
            public_html += f"""
            <li>
                <b>{f['original_name']}</b>
                (shared publicly by {f['owner']})
                - <a href='/download/{f['stored_name']}'>Download</a>
            </li>
            """
    else:
        public_html = "<li>No public files available.</li>"

    if not current_user:
        return f"""
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
        """

    username = current_user["username"]
    role = current_user.get("role", "user")

    upload_html = ""
    if role in ("user", "admin"):
        upload_html = """
        <h2>Upload File</h2>
        <form method='POST' action='/upload' enctype='multipart/form-data'>
            <input type='file' name='file' required>
            <button type='submit'>Upload</button>
        </form>
        """

    owned_files = [f for f in files if f["owner"] == username]
    owned_html = ""
    if owned_files:
        for f in owned_files:
            owned_html += f"""
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
            """
    else:
        owned_html = "<li>No files uploaded yet.</li>"

    shared_file_ids = [s["file_id"] for s in shares if s["shared_with"] == username]
    shared_files = [f for f in files if f["id"] in shared_file_ids]
    shared_html = ""
    if shared_files:
        for f in shared_files:
            shared_html += f"""
            <li>
                <b>{f['original_name']}</b>
                (shared by {f['owner']})
                - <a href='/download/{f['stored_name']}'>Download</a>
            </li>
            """
    else:
        shared_html = "<li>No files have been shared with you.</li>"

    all_files = files if role == "admin" else []
    all_files_html = ""
    if all_files:
        for f in all_files:
            all_files_html += f"""
            <li>
                <b>{f['original_name']}</b>
                (owner: {f['owner']})
                - <a href='/download/{f['stored_name']}'>Download</a>
            </li>
            """
    else:
        all_files_html = "<li>No files in the system.</li>"

    admin_html = ""
    if role == "admin":
        admin_html = f"""
        <h2>Admin View</h2>
        <a href='/admin/users'>Manage Users</a>
        <h3>All Files</h3>
        <ul>
            {all_files_html}
        </ul>
        """

    return f"""
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
    """
