from flask import render_template, url_for

from services.app_access import get_current_user


def nav_context():
    user = get_current_user()
    if not user:
        return {"current_user": None, "show_admin_link": False}
    role = user.get("role", "guest")
    return {
        "current_user": {"username": user["username"], "role": role},
        "show_admin_link": role == "admin",
    }


def render_message_page(title, message, back_href=None, back_label="Back to home"):
    ctx = nav_context()
    ctx.update(
        title=title,
        message=message,
        back_href=back_href or url_for("home.home"),
        back_label=back_label,
    )
    return render_template("page_message.html", **ctx)
