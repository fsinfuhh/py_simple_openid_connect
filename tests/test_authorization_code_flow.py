from simple_openid_connect.client_authentication import ClientSecretBasicAuth
from simple_openid_connect.flows import authorization_code_flow
from simple_openid_connect.flows.authorization_code_flow import (
    AuthenticationSuccessResponse,
)


def test_authorization_request(user_agent, dummy_auth_response):
    # act
    url = authorization_code_flow.start_authentication(
        "https://provider.example.com/auth",
        "openid",
        "test-client-id",
        "https://app.example.com/login-callback",
    )
    response = user_agent.naviagte_to(url)
    response_msg = authorization_code_flow.AuthenticationSuccessResponse.parse_url(
        response.url
    )

    # assert
    assert response_msg.code == "code.foobar123"


def test_token_exchange(user_agent, dummy_token_response):
    # act
    response = authorization_code_flow.exchange_code_for_tokens(
        "https://provider.example.com/token",
        AuthenticationSuccessResponse(code="code.foobar123"),
        "https://app.example.com/login-callback",
        ClientSecretBasicAuth(
            "test-client-id",
            "test-client-secret",
        ),
    )

    # assert
    assert response.access_token
    assert response.id_token


def test_handle_authentication_result(user_agent, dummy_token_response):
    # act
    response = authorization_code_flow.handle_authentication_result(
        "https://app.example.com/login-callback?code=code.foobar123",
        "https://provider.example.com/token",
        ClientSecretBasicAuth("test-client-id", "test-client-secret"),
    )

    # assert
    assert response.access_token == "access_token.foobar123"
    assert response.id_token == "id_token.user1"
