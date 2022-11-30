import pytest

from simple_openid_connect import discovery
from simple_openid_connect.exceptions import OpenidProtocolError


def test_mafiasi_identity(mock_known_provider_configs):
    discovery.discover_configuration_from_issuer(
        "https://identity.mafiasi.de/auth/realms/simple_openid_test"
    )


def test_google(mock_known_provider_configs):
    discovery.discover_configuration_from_issuer("https://accounts.google.com")


def test_errors(mock_known_provider_configs):
    with pytest.raises(OpenidProtocolError):
        discovery.discover_configuration_from_issuer("https://example.com/not-found")
    with pytest.raises(OpenidProtocolError):
        discovery.discover_configuration_from_issuer(
            "https://example.com/invalid-json-document"
        )
    with pytest.raises(OpenidProtocolError):
        discovery.discover_configuration_from_issuer(
            "https://example.com/invalid-json-syntax"
        )
