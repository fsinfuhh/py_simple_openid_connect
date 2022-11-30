import json

import pytest
from django.shortcuts import resolve_url


def test_unauth_access(client):
    response = client.get(resolve_url("access-token-protected-view"))
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.interactive
def test_invalid_token_text(client, live_server, mafiasi_identity_settings):
    response = client.get(
        resolve_url("access-token-protected-view"),
        HTTP_Authorization="Bearer foobar123",
    )
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert (
        response.content
        == b"the used access token is not valid or does not grant enough access"
    )


@pytest.mark.interactive
def test_invalid_token_json(client, mafiasi_identity_settings):
    response = client.get(
        resolve_url("access-token-protected-view"),
        HTTP_Authorization="Bearer foobar123",
        HTTP_Accept="application/json",
    )
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.headers["Content-Type"] == "application/json"
    json_response = json.loads(response.content)
    assert json_response["error"] == "invalid_token"
    assert (
        json_response["error_description"]
        == "the used access token is not valid or does not grant enough access"
    )
