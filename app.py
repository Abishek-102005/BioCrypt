"""
BioCrypt — Flask Application Entry Point
"""
import os
from flask import Flask
from flask_wtf.csrf import CSRFProtect
from config import config
import db.models as db_models

csrf = CSRFProtect()


def create_app(config_name: str = "default") -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(config[config_name])

    # Ensure temp dir exists
    os.makedirs(app.config["TEMP_DIR"], exist_ok=True)

    # Database
    db_models.set_database_path(app.config["DATABASE"])
    db_models.init_db()

    # CSRF
    csrf.init_app(app)

    # Register blueprints
    from routes.auth_routes import auth_bp
    from routes.dashboard_routes import dashboard_bp
    from routes.file_routes import files_bp
    from routes.folder_routes import folders_bp
    from routes.settings_routes import settings_bp
    from routes.biometric_routes import biometric_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(folders_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(biometric_bp)

    # Exempt API routes from CSRF (they use JSON bodies with fetch)
    csrf.exempt(files_bp)
    csrf.exempt(folders_bp)
    csrf.exempt(biometric_bp)
    csrf.exempt(settings_bp)

    return app


if __name__ == "__main__":
    app = create_app("development")
    # Bind to localhost only — never expose to the network in dev
    app.run(host="127.0.0.1", port=5000, debug=True)
