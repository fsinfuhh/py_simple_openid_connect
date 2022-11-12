from simple_openid_connect.client_authentication import ClientSecretBasicAuth
from simple_openid_connect.flows import authorization_code_flow
from simple_openid_connect.flows.authorization_code_flow import (
    AuthenticationSuccessResponse,
)


def test_authorization_request(dummy_ua, dummy_openid_provider, dummy_app_server):
    # act
    url = authorization_code_flow.start_authentication(
        dummy_openid_provider.endpoints["authorization"],
        "openid",
        dummy_openid_provider.test_client_id,
        dummy_app_server.callback_url,
    )
    response = dummy_ua.naviagte_to(url)

    # assert
    response_msg = authorization_code_flow.AuthenticationSuccessResponse.parse_url(
        response.url
    )
    assert response_msg.code is not None
    assert response_msg.code != ""


def test_handle_authentication_result(
    dummy_ua, dummy_openid_provider, dummy_app_server
):
    # arrange
    url = authorization_code_flow.start_authentication(
        dummy_openid_provider.endpoints["authorization"],
        "openid",
        dummy_openid_provider.test_client_id,
        dummy_app_server.callback_url,
    )
    response = dummy_ua.naviagte_to(url)

    # act
    response = authorization_code_flow.handle_authentication_result(
        response.url,
        dummy_openid_provider.endpoints["token"],
        ClientSecretBasicAuth(
            dummy_openid_provider.test_client_id,
            dummy_openid_provider.test_client_secret,
        ),
    )

    # assert
    assert response.access_token
    assert response.id_token


def test_token_exchange(dummy_ua, dummy_openid_provider, dummy_app_server):
    # act
    response = authorization_code_flow.exchange_code_for_tokens(
        dummy_openid_provider.endpoints["token"],
        AuthenticationSuccessResponse(code=dummy_openid_provider.cheat_code),
        dummy_app_server.callback_url,
        ClientSecretBasicAuth(
            dummy_openid_provider.test_client_id,
            dummy_openid_provider.test_client_secret,
        ),
    )

    # assert
    assert response.access_token
    assert response.id_token
