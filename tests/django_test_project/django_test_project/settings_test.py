# ruff: noqa: F405, F403        allow the * import
from .settings_base import *

# Database
# https://docs.djangoproject.com/en/3.2/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

OPENID_BASE_URI = "https://app.example.com"
OPENID_ISSUER = "https://provider.example.com"
OPENID_CLIENT_ID = "test-client-id"
OPENID_CLIENT_SECRET = "test-client-secret"
OPENID_SCOPE = "openid profile email"
