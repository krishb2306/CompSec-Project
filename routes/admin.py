from flask import Blueprint, current_app, redirect, request, url_for

from services.auth import require_auth, require_role
from services.storage import load_users, save_users


admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/admin/users")
@require_auth
@require_role("admin")
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


@admin_bp.route("/admin/set-role/<username>", methods=["POST"])
@require_auth
@require_role("admin")
def set_role(username):
    new_role = request.form.get("role", "").strip()
    role_hierarchy = current_app.config["ROLE_HIERARCHY"]
    if new_role not in role_hierarchy:
        return "Invalid role. <a href='/admin/users'>Go back</a>"

    users = load_users()
    admins = [u for u in users if u.get("role") == "admin"]
    target_user = next((u for u in users if u["username"] == username), None)

    if not target_user:
        return "User not found. <a href='/admin/users'>Go back</a>"
    if target_user.get("role") == "admin" and new_role != "admin" and len(admins) == 1:
        return "Cannot remove the last admin. <a href='/admin/users'>Go back</a>"

    target_user["role"] = new_role
    save_users(users)
    return redirect(url_for("admin.admin_users"))
