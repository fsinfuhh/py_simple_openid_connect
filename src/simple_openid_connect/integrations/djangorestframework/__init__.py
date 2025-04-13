"""
Django REST Framework integration for :mod:`simple_openid_connect`.
"""

# try to import drf spectacular extensions but silently ignore failures if drf-spectacular is not installed
# we do this import because of its side effect which defines openapi metadata for the authentication classes used in this integration
try:
    import simple_openid_connect.integrations.djangorestframework.drf_spectacular_schema  # noqa: F401
except Exception:
    pass
