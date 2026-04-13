from flask import Blueprint, render_template, url_for

from services.app_access import get_current_user
from services.file_access import can_delete, can_edit, can_share, can_view, get_file_role_for_user
from services.storage import load_files, load_shares

from services.validation import sanitize_output

home_bp = Blueprint("home", __name__)


def _file_action_links(file_record, file_role, current_user):
    links = []
    if can_view(file_role):
        links.append(
            {
                "href": url_for("files.open_file", stored_name=file_record["stored_name"]),
                "label": "Open",
            }
        )
        links.append(
            {
                "href": url_for("files.download", stored_name=file_record["stored_name"]),
                "label": "Download",
            }
        )
    if current_user and can_edit(file_role):
        links.append(
            {
                "href": url_for("files.edit_file_form", file_id=file_record["id"]),
                "label": "Edit",
            }
        )
    return links


def _public_file_entry(f, shares, current_user):
    file_role = get_file_role_for_user(f, shares, current_user)
    return {
        "name": sanitize_output(f["original_name"]),
        "meta": sanitize_output(f"Shared publicly by {f['owner']}"),
        "links": _file_action_links(f, file_role, current_user),
    }


def _owned_file_entry(f, shares, current_user):
    file_role = get_file_role_for_user(f, shares, current_user)
    entry = {
        "name": sanitize_output(f["original_name"]),
        "meta": sanitize_output(f"Your role on this file: {file_role}"),
        "links": _file_action_links(f, file_role, current_user),
    }
    if can_share(file_role):
        entry["share_form"] = {"action": url_for("files.share_file", file_id=f["id"])}
        entry["public_toggle"] = {
            "is_public": any(
                s.get("file_id") == f["id"] and s.get("shared_with") == "guest" for s in shares
            ),
            "make_public_action": url_for("files.make_public", file_id=f["id"]),
            "unpublic_action": url_for("files.unmake_public", file_id=f["id"]),
        }
    if can_delete(file_role):
        entry["delete_form"] = {"action": url_for("files.delete_file", file_id=f["id"])}
    return entry


def _shared_file_entry(f, shares, current_user):
    file_role = get_file_role_for_user(f, shares, current_user)
    return {
        "name": sanitize_output(f["original_name"]),
        "meta": sanitize_output(f"Shared by {f['owner']} · your role: {file_role}"),
        "links": _file_action_links(f, file_role, current_user),
    }


def _admin_file_entry(f, shares, current_user):
    file_role = get_file_role_for_user(f, shares, current_user)
    return {
        "name": sanitize_output(f["original_name"]),
        "meta": sanitize_output(f"Owner: {f['owner']} · your role: {file_role}"),
        "links": _file_action_links(f, file_role, current_user),
    }


@home_bp.route("/")
def home():
    current_user = get_current_user()
    files = load_files()
    shares = load_shares()
    current_role = current_user.get("role", "guest") if current_user else "guest"

    public_file_ids = [s["file_id"] for s in shares if s["shared_with"] == "guest"]
    public_files = [_public_file_entry(f, shares, current_user) for f in files if f["id"] in public_file_ids]

    ctx = {
        "app_title": "Secure Document Sharing",
        "current_user": None,
        "show_admin_link": False,
        "show_admin_section": False,
        "can_upload": False,
        "public_files": public_files,
        "owned_files": [],
        "shared_files": [],
        "all_files": [],
    }

    if not current_user:
        return render_template("home.html", **ctx)

    username = sanitize_output(current_user["username"])
    ctx["current_user"] = {"username": username, "role": current_role}
    ctx["show_admin_link"] = current_role == "admin"
    ctx["show_admin_section"] = current_role == "admin"
    ctx["can_upload"] = current_role in ("user", "admin")

    owned_files = [f for f in files if f["owner"] == username]
    ctx["owned_files"] = [_owned_file_entry(f, shares, current_user) for f in owned_files]

    shared_file_ids = [s["file_id"] for s in shares if s["shared_with"] == username]
    shared_files = [f for f in files if f["id"] in shared_file_ids]
    ctx["shared_files"] = [_shared_file_entry(f, shares, current_user) for f in shared_files]

    if current_role == "admin":
        ctx["all_files"] = [_admin_file_entry(f, shares, current_user) for f in files]

    return render_template("home.html", **ctx)
