import pickle


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
        client_id="test-client-id",
        client_secret="test-client-secret",
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
