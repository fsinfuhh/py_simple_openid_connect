from base64 import b64encode

import pytest
import requests
from responses import RequestsMock

from simple_openid_connect.client_authentication import ClientSecretBasicAuth, NoneAuth


@pytest.fixture
def mock_empty_response(response_mock):
    response_mock.get(url="https://example.com")


def test_none_auth(mock_empty_response):
    # arrange
    auth = NoneAuth("test-id")

    # act
    response = requests.get("https://example.com", auth=auth)

    # assert
    assert "Authorization" not in response.request.headers.keys()


def test_client_secret_basic_auth(mock_empty_response):
    # arrange
    auth = ClientSecretBasicAuth("test-id", "foobar123")

    # act
    response = requests.get("https://example.com", auth=auth)

    # assert
    assert (
        response.request.headers["Authorization"]
        == f"Basic {b64encode(b':'.join(['test-id'.encode('ASCII'), 'foobar123'.encode('ASCII')])).decode('ASCII')}"
    )
