"""
Django REST Framework integration for :mod:`simple_openid_connect`.
"""

# try to import drf spectacular extensions but silently ignore failures if drf-spectacular is not installed
try:
    import simple_openid_connect.integrations.djangorestframework.drf_spectacular_schema
except Exception:
    pass
