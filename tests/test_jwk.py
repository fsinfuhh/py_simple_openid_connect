from cryptojwt import JWK

from simple_openid_connect.jwk import fetch_jwks


def test_load_mafiasi_jwks(known_provider_configs):
    keys = fetch_jwks(
        "https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/certs"
    )
    assert all(isinstance(k, JWK) for k in keys)
    assert len(keys) == 1
    assert keys[0].kid == "JAehgk0O0uzTEht7KGCPVB_urwfsBGe22phHVDZezeo"


def test_load_dummy_jwks(dummy_provider_config):
    keys = fetch_jwks("https://provider.example.com/jwks")
    assert all(isinstance(k, JWK) for k in keys)
    assert len(keys) == 1
