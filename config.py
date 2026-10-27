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
    _key_file = os.path.join(BASE_DIR, ".secret_key")
    if os.environ.get("BIOCRYPT_SECRET_KEY"):
        SECRET_KEY = os.environ["BIOCRYPT_SECRET_KEY"]
    elif os.path.exists(_key_file):
        with open(_key_file) as _f:
            SECRET_KEY = _f.read().strip()
    else:
        SECRET_KEY = secrets.token_hex(32)
        with open(_key_file, "w") as _f:
            _f.write(SECRET_KEY)
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
    DATABASE = os.environ.get(
    "BIOCRYPT_DATABASE",
    os.path.join(BASE_DIR, "biocrypt.db")
)

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
