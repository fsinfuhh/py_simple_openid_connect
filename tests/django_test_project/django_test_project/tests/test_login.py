import json
import secrets
import sys
from base64 import b64encode

import pytest
from pytest_django.asserts import assertContains, assertInHTML
from cryptojwt import JWS
from django.shortcuts import resolve_url
from django.utils.http import quote
from responses import matchers

from simple_openid_connect.data import TokenErrorResponse
from simple_openid_connect.integrations.django.apps import OpenidAppConfig


@pytest.mark.django_db
def test_directly_calling_login_endpoint(
    dyn_client,
    dummy_provider_config,
    dummy_provider_settings,
    response_mock,
    jwks,
    monkeypatch,
):
    # arrange
    settings = OpenidAppConfig.get_instance().safe_settings
    SECRET_CONSTANT = "42"
    monkeypatch.setattr(secrets, "token_urlsafe", lambda len: SECRET_CONSTANT)
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
                    "nonce": SECRET_CONSTANT,
                    "state": SECRET_CONSTANT,
                }
            )
        ],
        status=302,
        headers={
            "Location": settings.OPENID_BASE_URI
            + resolve_url(settings.OPENID_REDIRECT_URI)
            + "?code=code.foobar123"
            + f"&state={SECRET_CONSTANT}"
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
                        "nonce": SECRET_CONSTANT,
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
    dyn_client,
    dummy_provider_config,
    dummy_provider_settings,
    response_mock,
    jwks,
    monkeypatch,
):
    # arrange
    settings = OpenidAppConfig.get_instance().safe_settings
    SECRET_CONSTANT = "42"
    monkeypatch.setattr(secrets, "token_urlsafe", lambda len: SECRET_CONSTANT)
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
                    "nonce": SECRET_CONSTANT,
                    "state": SECRET_CONSTANT,
                }
            )
        ],
        status=302,
        headers={
            "Location": settings.OPENID_BASE_URI
            + resolve_url(settings.OPENID_REDIRECT_URI)
            + "?code=code.foobar123"
            + f"&state={SECRET_CONSTANT}"
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
                        "nonce": SECRET_CONSTANT,
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


@pytest.mark.django_db
def test_unsolicited_callback_csrf(
    dyn_client, dummy_provider_config, dummy_provider_settings, response_mock, jwks
):
    # arrange
    settings = OpenidAppConfig.get_instance().safe_settings

    # act
    # renders an error html page
    response = dyn_client.get(
        "https://app.example.com"
        + resolve_url(settings.OPENID_REDIRECT_URI)
        + "?code=code.foobar123"
    )

    # assert
    assertContains(response, "<h2>Invalid state</h2>", status_code=401, html=True)


@pytest.mark.django_db
def test_redirect_to_callback_with_error(
    monkeypatch,
    dyn_client,
    dummy_provider_config,
    dummy_provider_settings,
    response_mock,
):
    # arrange
    settings = OpenidAppConfig.get_instance().safe_settings
    SECRET_CONSTANT = "42"
    monkeypatch.setattr(secrets, "token_urlsafe", lambda len: SECRET_CONSTANT)
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
                    "nonce": SECRET_CONSTANT,
                    "state": SECRET_CONSTANT,
                }
            )
        ],
        status=302,
        headers={
            "Location": settings.OPENID_BASE_URI
            + resolve_url(settings.OPENID_REDIRECT_URI)
            + f"?error=unauthorized_client&error_description={quote('Client is currently disabled')}&error_uri={quote('https://provider.example/error.html')}"
            + f"&state={SECRET_CONSTANT}"
        },
    )

    # act
    response = dyn_client.get(
        "https://app.example.com" + resolve_url("simple_openid_connect:login"),
        follow=True,
    )

    # assert
    assert response.status_code == 401
    response_html = response.content.decode("UTF-8")
    assertInHTML("<h1>Could not log you in</h1>", response_html)
    assertInHTML("<p>Client is currently disabled</p>", response_html)
    assertInHTML("<i>https://provider.example/error.html</i>", response_html)


@pytest.mark.django_db
def test_error_during_code_exchange(
    dyn_client,
    dummy_provider_config,
    dummy_provider_settings,
    response_mock,
    monkeypatch,
):
    # arrange
    settings = OpenidAppConfig.get_instance().safe_settings
    SECRET_CONSTANT = "42"
    monkeypatch.setattr(secrets, "token_urlsafe", lambda len: SECRET_CONSTANT)
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
                    "nonce": SECRET_CONSTANT,
                    "state": SECRET_CONSTANT,
                }
            )
        ],
        status=302,
        headers={
            "Location": settings.OPENID_BASE_URI
            + resolve_url(settings.OPENID_REDIRECT_URI)
            + "?code=code.foobar123"
            + f"&state={SECRET_CONSTANT}"
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
        status=400,
        json=TokenErrorResponse(
            error=TokenErrorResponse.ErrorType.unsupported_grant_type,
            error_description="Grant is dummy disabled",
            error_uri="https://provider.example.com/error.html",
        ).model_dump(),
    )

    # act
    response = dyn_client.get(
        "https://app.example.com" + resolve_url("simple_openid_connect:login"),
        follow=True,
    )

    # assert
    assert response.status_code == 401
    response_html = response.content.decode("UTF-8")
    assertInHTML("<h1>Could not log you in</h1>", response_html)
    assertInHTML("<h2>unsupported_grant_type</h2>", response_html)
    assertInHTML("<p>Grant is dummy disabled</p>", response_html)
    assertInHTML("<i>https://provider.example.com/error.html</i>", response_html)
