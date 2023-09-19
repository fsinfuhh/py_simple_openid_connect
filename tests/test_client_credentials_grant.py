from base64 import b64encode

import pytest
from responses import matchers

from simple_openid_connect.client_authentication import ClientSecretBasicAuth
from simple_openid_connect.flows import client_credentials_grant


@pytest.fixture
def dummy_token_response(response_mock):
    response_mock.post(
        url="https://provider.example.com/token",
        match=[
            matchers.urlencoded_params_matcher(
                {
                    "grant_type": "client_credentials",
                    "scope": "openid",
                }
            ),
            matchers.header_matcher(
                {
                    "Authorization": f"Basic {b64encode(b'client-id:client-secret').decode()}",
                }
            ),
        ],
        json={
            "access_token": "access_token.foobar123",
            "token_type": "Bearer",
            "id_token": "id_token.foobar123",
        },
    )


def test_auth_exchange(user_agent, dummy_token_response):
    # act
    response = client_credentials_grant.authenticate(
        "https://provider.example.com/token",
        "openid",
        ClientSecretBasicAuth("client-id", "client-secret"),
    )

    # assert
    assert response.access_token
