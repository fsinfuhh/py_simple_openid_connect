import json

from django.shortcuts import resolve_url


def test_unauth_access(client):
    response = client.get(resolve_url("access-token-protected-view"))
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_invalid_token_text(
    client,
    dummy_provider_settings,
    dummy_provider_config,
    dummy_token_introspection_response,
    response_mock,
):
    # act
    response = client.get(
        resolve_url("access-token-protected-view"),
        HTTP_Authorization="Bearer invalid-token",
    )

    # assert
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert (
        response.content
        == b"the used access token is not valid or does not grant enough access"
    )


def test_invalid_token_json(
    client,
    dummy_provider_settings,
    dummy_provider_config,
    dummy_token_introspection_response,
):
    # act
    response = client.get(
        resolve_url("access-token-protected-view"),
        HTTP_Authorization="Bearer access_token.invalid",
        HTTP_Accept="application/json",
    )

    # assert
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.headers["Content-Type"] == "application/json"
    json_response = json.loads(response.content)
    assert json_response["error"] == "invalid_token"
    assert (
        json_response["error_description"]
        == "the used access token is not valid or does not grant enough access"
    )
