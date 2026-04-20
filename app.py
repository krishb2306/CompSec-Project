from flask import Flask, g, redirect, request, make_response

from config import Config
from routes.admin import admin_bp
from routes.auth import auth_bp
from routes.files import files_bp
from routes.home import home_bp
from services.app_access import ensure_admin_user, ensure_guest_user
from services.security import init_security_logging
from services.sessions import clear_session_cookie, load_user_into_g
from services.storage import ensure_storage_directories


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    init_security_logging(app)

    @app.after_request
    def add_security_headers(response):
    # Content Security Policy
        response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
        )
    
    # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'DENY'
    
    # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # XSS Protection (legacy browsers)
        response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Referrer Policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # HSTS (HTTPS only)
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Permissions-Policy'] = ('geolocation=(), microphone=(), camera=()')
    # Hide server information
        response.headers.pop('Server', None)
        response.headers.pop('server', None)
        
        return response

    @app.before_request
    def require_https():
        if not request.is_secure and not app.debug:
            url = request.url.replace("http://", "https://", 1)
            return redirect(url, code=301)
        return None

    @app.before_request
    def load_user_session():
        load_user_into_g()

    @app.after_request
    def drop_invalid_session_cookie(response):
        if getattr(g, "_clear_session_cookie", False):
            clear_session_cookie(response)
        return response

    app.register_blueprint(home_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(admin_bp)

    with app.app_context():
        ensure_storage_directories()
        ensure_admin_user()
        ensure_guest_user()

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        ssl_context=("cert.pem", "key.pem"),
        host="0.0.0.0",
        port=5001,
        debug=False,
    )