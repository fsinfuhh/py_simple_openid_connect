from cryptojwt import JWK

from simple_openid.jwk import fetch_jwks


def test_load_jwks(mock_known_provider_configs, mock_known_provider_jwks):
    keys = fetch_jwks(
        "https://identity.mafiasi.de/auth/realms/mafiasi/protocol/openid-connect/certs"
    )
    assert all(isinstance(k, JWK) for k in keys)
    assert len(keys) == 1
    assert keys[0].kid == "P9ONvIAIs3TvrQ9Qh_CArFhJXXN3uJrS-kiEcBbt8Ug"
