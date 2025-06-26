# ruff: noqa: F405, F403      allow the * import
from .settings_base import *

# Database
# https://docs.djangoproject.com/en/3.2/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

OPENID_BASE_URI = "http://localhost:8000/"
OPENID_ISSUER = "http://localhost:8080/realms/dev"
OPENID_CLIENT_ID = "django_test_project"
OPENID_CLIENT_SECRET = "J2GslOfIEISn3XLXESIjU1X6SR9iaHB5"
OPENID_SCOPE = "openid profile email"
