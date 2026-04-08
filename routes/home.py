from flask import Blueprint

from services.app_access import get_current_user
from services.file_access import can_delete, can_edit, can_share, can_view, get_file_role_for_user
from services.storage import load_files, load_shares


home_bp = Blueprint("home", __name__)


@home_bp.route("/")
def home():
    current_user = get_current_user()
    files = load_files()
    shares = load_shares()
    current_role = current_user.get("role", "guest") if current_user else "guest"
    current_username = current_user["username"] if current_user else None

    def file_actions_html(file_record, file_role):
        if not can_view(file_role):
            return ""
        actions = (
            f"<a href='/open/{file_record['stored_name']}'>Open</a> | "
            f"<a href='/download/{file_record['stored_name']}'>Download</a>"
        )
        if current_user and can_edit(file_role):
            actions += f" | <a href='/edit/{file_record['id']}'>Edit</a>"
        return actions

    public_file_ids = [s["file_id"] for s in shares if s["shared_with"] == "guest"]
    public_files = [f for f in files if f["id"] in public_file_ids]
    public_html = ""
    if public_files:
        for f in public_files:
            file_role = get_file_role_for_user(f, shares, current_user)
            public_html += f"""
            <li>
                <b>{f['original_name']}</b>
                (shared publicly by {f['owner']})
                - {file_actions_html(f, file_role)}
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
    role = current_role

    add_html = ""
    if role in ("user", "admin"):
        add_html = """
        <h2>Upload/Create File</h2>
        <form method='POST' action='/upload' enctype='multipart/form-data'>
            <input type='file' name='file' required>
            <button type='submit'>Upload</button>
        </form>
        <p><a href='/create-text'>Create new .txt file</a></p>
        """

    owned_files = [f for f in files if f["owner"] == username]
    owned_html = ""
    if owned_files:
        for f in owned_files:
            file_role = get_file_role_for_user(f, shares, current_user)
            owner_actions = file_actions_html(f, file_role)
            share_controls = ""
            if can_share(file_role):
                share_controls = f"""
                <form method='POST' action='/share/{f['id']}' style='margin-top:8px; margin-bottom:12px;'>
                    <input name='shared_with' placeholder='Username or guest (public)' required>
                    <select name='file_role' required>
                        <option value='viewer'>viewer</option>
                        <option value='editor'>editor</option>
                    </select>
                    <button type='submit'>Share</button>
                </form>
                """

            delete_controls = ""
            if can_delete(file_role):
                delete_controls = f"""
                <form method='POST' action='/delete/{f['id']}' style='display:inline; margin-left:8px;'>
                    <button type='submit'>Delete</button>
                </form>
                """

            owned_html += f"""
            <li>
                <b>{f['original_name']}</b>
                (file role: {file_role})
                - {owner_actions}
                {share_controls}
                {delete_controls}
            </li>
            """
    else:
        owned_html = "<li>No files uploaded yet.</li>"

    shared_file_ids = [s["file_id"] for s in shares if s["shared_with"] == username or s["shared_with"] == "guest"]
    shared_files = [f for f in files if f["id"] in shared_file_ids and f["owner"] != current_username]
    shared_html = ""
    if shared_files:
        for f in shared_files:
            file_role = get_file_role_for_user(f, shares, current_user)
            shared_html += f"""
            <li>
                <b>{f['original_name']}</b>
                (shared by {f['owner']})
                (file role: {file_role})
                - {file_actions_html(f, file_role)}
            </li>
            """
    else:
        shared_html = "<li>No files have been shared with you.</li>"

    all_files = files if role == "admin" else []
    all_files_html = ""
    if all_files:
        for f in all_files:
            file_role = get_file_role_for_user(f, shares, current_user)
            all_files_html += f"""
            <li>
                <b>{f['original_name']}</b>
                (owner: {f['owner']})
                (file role: {file_role})
                - {file_actions_html(f, file_role)}
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

    {add_html}

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
