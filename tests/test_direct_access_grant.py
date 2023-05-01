from base64 import b64encode

import pytest
from responses import matchers

from simple_openid_connect.client_authentication import ClientSecretBasicAuth
from simple_openid_connect.flows import direct_access_grant


@pytest.fixture
def dummy_token_response(response_mock):
    response_mock.post(
        url="https://provider.example.com/token",
        match=[
            matchers.urlencoded_params_matcher(
                {
                    "grant_type": "password",
                    "username": "testi-testfrau",
                    "password": "foobar123",
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
            "id_token": "id_token.foobar123",
            "token_type": "Bearer",
        },
    )


def test_auth_exchange(user_agent, dummy_token_response):
    # act
    response = direct_access_grant.authenticate(
        "https://provider.example.com/token",
        "openid",
        "testi-testfrau",
        "foobar123",
        ClientSecretBasicAuth("client-id", "client-secret"),
    )

    # assert
    assert response.access_token
    assert response.id_token
