"""
BioCrypt — Application Configuration
"""
import os
import secrets

# WebAuthn / FIDO2 settings
RP_ID = os.getenv('BIOCRYPT_RP_ID', 'localhost')
RP_NAME = os.getenv('BIOCRYPT_RP_NAME', 'BioCrypt')

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    # -------------------------------------------------------------------
    # Flask core
    # -------------------------------------------------------------------
    SECRET_KEY = os.environ.get("BIOCRYPT_SECRET_KEY") or secrets.token_hex(32)
    DEBUG = False
    TESTING = False

    # -------------------------------------------------------------------
    # Session
    # -------------------------------------------------------------------
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = 1800  # 30 minutes

    # -------------------------------------------------------------------
    # File uploads
    # -------------------------------------------------------------------
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB hard limit
    UPLOAD_EXTENSIONS = {".biocrypt"}  # for decrypt endpoint
    TEMP_DIR = os.path.join(BASE_DIR, "tmp")

    # -------------------------------------------------------------------
    # Database
    # -------------------------------------------------------------------
    DATABASE = os.path.join(BASE_DIR, "biocrypt.db")

    # -------------------------------------------------------------------
    # CSRF (Flask-WTF)
    # -------------------------------------------------------------------
    WTF_CSRF_TIME_LIMIT = 3600


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True


config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
