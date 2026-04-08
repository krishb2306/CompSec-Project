def normalize_file_role(role):
    if role in {"owner", "editor", "viewer"}:
        return role
    return "viewer"


def get_file_role_for_user(file_record, shares, current_user):
    if current_user is None:
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
        return None

    username = current_user["username"]
    user_role = current_user.get("role", "guest")

    if file_record["owner"] == username:
        return "owner"

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

    if user_role == "admin":
        # App-role admin can always view all content.
        return "viewer"

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

    return None


def can_view(file_role):
    return file_role in {"owner", "editor", "viewer"}


def can_edit(file_role):
    return file_role in {"owner", "editor"}


def can_share(file_role):
    return file_role == "owner"


def can_delete(file_role):
    return file_role == "owner"
