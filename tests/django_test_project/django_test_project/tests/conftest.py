import pytest


@pytest.fixture
def mafiasi_identity_settings(settings, secrets):
    settings.OPENID_ISSUER = (
        "https://identity.mafiasi.de/auth/realms/simple_openid_test"
    )
    settings.OPENID_CLIENT_ID = secrets["mafiasi_identity_confidential_client_id"]
    settings.OPENID_CLIENT_SECRET = secrets[
        "mafiasi_identity_confidential_client_secret"
    ]
