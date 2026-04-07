from flask import Flask, redirect, request

from config import Config
from routes.admin import admin_bp
from routes.auth import auth_bp
from routes.files import files_bp
from routes.home import home_bp
from services.auth import ensure_guest_user
from services.storage import ensure_storage_directories


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    @app.before_request
    def require_https():
        if not request.is_secure and not app.debug:
            url = request.url.replace("http://", "https://", 1)
            return redirect(url, code=301)
        return None

    app.register_blueprint(home_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(admin_bp)

    with app.app_context():
        ensure_storage_directories()
        ensure_guest_user()

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        ssl_context=("cert.pem", "key.pem"),
        host="0.0.0.0",
        port=5001,
        debug=True,
    )