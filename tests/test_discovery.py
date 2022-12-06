import pytest

from simple_openid_connect import discovery
from simple_openid_connect.exceptions import OpenidProtocolError


def test_mafiasi_identity(known_provider_configs):
    discovery.discover_configuration_from_issuer(
        "https://identity.mafiasi.de/auth/realms/simple_openid_test"
    )


def test_google(known_provider_configs):
    discovery.discover_configuration_from_issuer("https://accounts.google.com")


def test_errors(known_provider_configs, response_mock):
    # arrange
    response_mock.get(
        url="https://example.com/not-found/.well-known/openid-configuration",
        content_type="text/plain",
        body="Issuer config not found",
        status=404,
    )
    response_mock.get(
        url="https://example.com/invalid-json-document/.well-known/openid-configuration",
        content_type="application/json",
        body="{ 'hello': 'world' }",
    )
    response_mock.get(
        url="https://example.com/invalid-json-syntax/.well-known/openid-configuration",
        content_type="application/json",
        body="{ 'hello }",
    )

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
