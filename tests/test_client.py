import pickle
import re
from base64 import b64encode

from responses import matchers

from simple_openid_connect.client import OpenidClient
from simple_openid_connect.data import (
    RpInitiatedLogoutRequest,
    TokenIntrospectionSuccessResponse,
    UserinfoSuccessResponse,
)


def make_client() -> OpenidClient:
    return OpenidClient.from_issuer_url(
        url="https://provider.example.com",
        authentication_redirect_uri="https://app.example.com/login-callback",
        client_id="client-id",
        client_secret="client-secret",
    )


def test_full_authorization_code_flow(
    user_agent, dummy_provider_config, dummy_auth_response, dummy_token_response
):
    # act
    client = make_client()
    response = user_agent.naviagte_to(
        client.authorization_code_flow.start_authentication()
    )
    result = client.authorization_code_flow.handle_authentication_result(response.url)

    # assert
    assert result.access_token
    assert result.id_token


def test_additional_redirect_args(
    user_agent,
    response_mock,
    dummy_provider_config,
):
    # arrange
    client = make_client()
    response_mock.get(
        url="https://provider.example.com/auth",
        match=[
            matchers.query_param_matcher(
                {
                    "client_id": "client-id",
                    "redirect_uri": "https://app.example.com/login-callback?foo=bar",
                    "response_type": "code",
                    "scope": "openid",
                }
            )
        ],
        status=302,
        headers={
            "Location": "https://app.example.com/login-callback?code=code.foobar123&foo=bar"
        },
    )
    response_mock.post(
        url="https://provider.example.com/token",
        match=[
            matchers.urlencoded_params_matcher(
                {
                    "client_id": "client-id",
                    "code": "code.foobar123",
                    "grant_type": "authorization_code",
                    "redirect_uri": "https://app.example.com/login-callback?foo=bar",
                }
            ),
            matchers.header_matcher(
                {
                    "Authorization": f"Basic {b64encode(b'client-id:client-secret').decode()}"
                }
            ),
        ],
        json={
            "access_token": "access_token.foobar123",
            "token_type": "Bearer",
            "id_token": "id_token.user1",
        },
    )

    # act
    auth_response = user_agent.naviagte_to(
        client.authorization_code_flow.start_authentication(
            additional_redirect_args={"foo": "bar"}
        )
    )
    _code_response = client.authorization_code_flow.handle_authentication_result(
        auth_response.url, additional_redirect_args={"foo": "bar"}
    )

    # assert
    assert "foo=bar" in auth_response.url
    assert any(
        call.request.body and re.search(r"redirect_uri=.*foo%3Dbar", call.request.body)
        for call in response_mock.calls
    )


def test_client_type(dummy_provider_config):
    # arrange
    public_client = OpenidClient.from_issuer_url(
        url="https://provider.example.com",
        authentication_redirect_uri="",
        client_id="test",
    )
    confidential_client = OpenidClient.from_issuer_url(
        url="https://provider.example.com",
        authentication_redirect_uri="",
        client_id="test",
        client_secret="test",
    )

    # assert
    assert public_client.client_type == "public"
    assert confidential_client.client_type == "confidential"


def test_fetch_userinfo(user_agent, dummy_provider_config, dumm_userinfo_response):
    # arrange
    client = make_client()

    # act
    response = client.fetch_userinfo("access_token.foobar123")

    # assert
    assert isinstance(response, UserinfoSuccessResponse)
    assert response.sub == "1"
    assert response.username == "user1"


def test_rp_initiated_logout(
    user_agent, dummy_provider_config, dummy_end_session_response
):
    # arrange
    client = make_client()

    # act
    plain_url = client.initiate_logout()
    advanced_url = client.initiate_logout(
        RpInitiatedLogoutRequest(
            post_logout_redirect_uri="https://app.example.com/logout-callback"
        )
    )
    nav_response = user_agent.naviagte_to(advanced_url)

    # assert
    assert plain_url == "https://provider.example.com/end-session"
    assert (
        advanced_url
        == "https://provider.example.com/end-session?post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2Flogout-callback"
    )
    assert nav_response.url == "https://app.example.com/logout-callback"


def test_token_introspection(dummy_provider_config, dummy_token_introspection_response):
    # arrange
    client = make_client()

    # act
    response = client.introspect_token("access_token.foobar123")

    # assert
    assert isinstance(response, TokenIntrospectionSuccessResponse)
    assert response.active


def test_pickling(dummy_provider_config):
    # arrange
    client = make_client()

    # act (assert not throwing)
    enc = pickle.dumps(client)
    _ = pickle.loads(enc)
