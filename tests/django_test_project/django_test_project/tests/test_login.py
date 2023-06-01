import json
import sys
from base64 import b64encode

import pytest
from cryptojwt import JWS
from django.shortcuts import resolve_url
from responses import matchers

from simple_openid_connect.integrations.django.apps import OpenidAppConfig


@pytest.mark.django_db
def test_directly_calling_login_endpoint(
    dyn_client, dummy_provider_config, dummy_provider_settings, response_mock, jwks
):
    # arrange
    settings = OpenidAppConfig.get_instance().safe_settings
    client_auth = b64encode(
        f"{settings.OPENID_CLIENT_ID}:{settings.OPENID_CLIENT_SECRET}".encode()
    ).decode()
    response_mock.get(
        url="https://provider.example.com/auth",
        match=[
            matchers.query_param_matcher(
                {
                    "client_id": settings.OPENID_CLIENT_ID,
                    "redirect_uri": settings.OPENID_BASE_URI
                    + resolve_url(settings.OPENID_REDIRECT_URI),
                    "response_type": "code",
                    "scope": settings.OPENID_SCOPE,
                }
            )
        ],
        status=302,
        headers={
            "Location": settings.OPENID_BASE_URI
            + resolve_url(settings.OPENID_REDIRECT_URI)
            + "?code=code.foobar123"
        },
    )
    response_mock.post(
        url="https://provider.example.com/token",
        match=[
            matchers.urlencoded_params_matcher(
                {
                    "client_id": settings.OPENID_CLIENT_ID,
                    "code": "code.foobar123",
                    "grant_type": "authorization_code",
                    "redirect_uri": settings.OPENID_BASE_URI
                    + resolve_url(settings.OPENID_REDIRECT_URI),
                }
            ),
            matchers.header_matcher(
                {
                    "Authorization": f"Basic {client_auth}",
                }
            ),
        ],
        json={
            "access_token": "access_token.foobar123",
            "token_type": "Bearer",
            "id_token": JWS(
                json.dumps(
                    {
                        "iss": "https://provider.example.com",
                        "sub": "user1",
                        "aud": settings.OPENID_CLIENT_ID,
                        "iat": 0,
                        "exp": sys.maxsize,
                    }
                )
            ).sign_compact(jwks),
        },
    )

    # act
    response = dyn_client.get(
        "https://app.example.com" + resolve_url("simple_openid_connect:login"),
        follow=True,
    )

    # assert
    assert response.status_code == 200
    assert response.wsgi_request.path == resolve_url("default-after-login")
    assert response.content == b"default login redirect view"


@pytest.mark.django_db
def test_directly_accessing_protected_resource(
    dyn_client, dummy_provider_config, dummy_provider_settings, response_mock, jwks
):
    # arrange
    settings = OpenidAppConfig.get_instance().safe_settings
    client_auth = b64encode(
        f"{settings.OPENID_CLIENT_ID}:{settings.OPENID_CLIENT_SECRET}".encode()
    ).decode()
    response_mock.get(
        url="https://provider.example.com/auth",
        match=[
            matchers.query_param_matcher(
                {
                    "client_id": settings.OPENID_CLIENT_ID,
                    "redirect_uri": settings.OPENID_BASE_URI
                    + resolve_url(settings.OPENID_REDIRECT_URI),
                    "response_type": "code",
                    "scope": settings.OPENID_SCOPE,
                }
            )
        ],
        status=302,
        headers={
            "Location": settings.OPENID_BASE_URI
            + resolve_url(settings.OPENID_REDIRECT_URI)
            + "?code=code.foobar123"
        },
    )
    response_mock.post(
        url="https://provider.example.com/token",
        match=[
            matchers.urlencoded_params_matcher(
                {
                    "client_id": settings.OPENID_CLIENT_ID,
                    "code": "code.foobar123",
                    "grant_type": "authorization_code",
                    "redirect_uri": settings.OPENID_BASE_URI
                    + resolve_url(settings.OPENID_REDIRECT_URI),
                }
            ),
            matchers.header_matcher(
                {
                    "Authorization": f"Basic {client_auth}",
                }
            ),
        ],
        json={
            "access_token": "access_token.foobar123",
            "token_type": "Bearer",
            "id_token": JWS(
                json.dumps(
                    {
                        "iss": "https://provider.example.com",
                        "sub": "user1",
                        "aud": settings.OPENID_CLIENT_ID,
                        "iat": 0,
                        "exp": sys.maxsize,
                    }
                )
            ).sign_compact(jwks),
        },
    )

    # act
    response = dyn_client.get(
        "https://app.example.com" + resolve_url("test-protected-view"), follow=True
    )

    # assert
    assert response.status_code == 200
    assert response.wsgi_request.path == resolve_url("test-protected-view")
    assert response.content == b"hello user user1"
