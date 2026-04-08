def normalize_file_role(role):
    if role in {"owner", "editor", "viewer"}:
        return role
    return "viewer"


def get_file_role_for_user(file_record, shares, current_user):
    username = current_user.get("username", "guest")
    user_role = current_user.get("role", "guest")

    # File is owned by user -> owner
    if file_record["owner"] == username:
        return "owner"

    # File is shared with user -> editor/viewer
    direct_share = next(
        (
            s
            for s in shares
            if s.get("file_id") == file_record["id"] and s.get("shared_with") == username
        ),
        None,
    )
    if direct_share:
        return normalize_file_role(direct_share.get("file_role", "viewer"))

    # File is public -> viewer
    public_share = next(
        (
            s
            for s in shares
            if s.get("file_id") == file_record["id"] and s.get("shared_with") == "guest"
        ),
        None,
    )
    if public_share:
        return normalize_file_role(public_share.get("file_role", "viewer"))

    # App-role admin -> viewer by default
    # Placed here as a fallback for when all other conditions are not met
    if user_role == "admin":
        return "viewer"

    return None


def can_view(file_role):
    return file_role in {"owner", "editor", "viewer"}


def can_edit(file_role):
    return file_role in {"owner", "editor"}


def can_share(file_role):
    return file_role == "owner"


def can_delete(file_role):
    return file_role == "owner"
