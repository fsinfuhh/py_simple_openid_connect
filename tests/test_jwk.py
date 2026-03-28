from datetime import datetime, timezone

from freezegun import freeze_time
from cryptojwt import JWK

from simple_openid_connect.jwk import fetch_jwks, fetch_jwks_max_age


def test_load_mafiasi_jwks(known_provider_configs):
    keys = fetch_jwks(
        "https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/certs"
    )
    assert all(isinstance(k, JWK) for k in keys)
    assert len(keys) == 1
    assert keys[0].kid == "JAehgk0O0uzTEht7KGCPVB_urwfsBGe22phHVDZezeo"
    

def test_load_hanse_jwks(known_provider_configs):
    keys = fetch_jwks(
        "https://auth.hanse.de/application/o/git/jwks/"
    )
    assert all(isinstance(k, JWK) for k in keys)
    assert len(keys) == 1
    assert keys[0].kid == "25bfaaaa8e5aed3a44d130d66ac81022"


def test_load_dummy_jwks(dummy_provider_config):
    keys = fetch_jwks("https://provider.example.com/jwks")
    assert all(isinstance(k, JWK) for k in keys)
    assert len(keys) == 1


def test_load_dummy_jwks_max_age_without_cache_header(dummy_provider_config):
    keys, max_age = fetch_jwks_max_age("https://provider.example.com/jwks")
    assert all(isinstance(k, JWK) for k in keys)
    assert len(keys) == 1
    assert max_age is None


@freeze_time("2026-01-01T00:00:00")
def test_load_dummy_jwks_max_age_with_cache_header(dummy_provider_config):
    keys, max_age = fetch_jwks_max_age(
        "https://provider.example.com/jwks-with-expiry"
    )  # returns a 60 second Cache-Control header
    assert all(isinstance(k, JWK) for k in keys)
    assert len(keys) == 1
    assert max_age == datetime(
        year=2026, month=1, day=1, hour=0, minute=1, second=0, tzinfo=timezone.utc
    )
