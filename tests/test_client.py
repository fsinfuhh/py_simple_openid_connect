import re
from urllib.parse import quote as urlquote

from simple_openid_connect.client import OpenidClient
from simple_openid_connect.data import UserinfoSuccessResponse


def test_full_authorization_code_flow(
    mock_known_provider_configs, dummy_openid_provider, dummy_ua, dummy_app_server
):
    # act
    client = OpenidClient.from_issuer_url(
        url="https://provider.example.com/openid-connect",
        authentication_redirect_uri=dummy_app_server.callback_url,
        client_id=dummy_openid_provider.test_client_id,
        client_secret=dummy_openid_provider.test_client_secret,
    )
    response = dummy_ua.naviagte_to(
        client.authorization_code_flow.start_authentication()
    )
    result = client.authorization_code_flow.handle_authentication_result(response.url)

    # assert
    assert result.access_token
    assert result.id_token


def test_additional_redirect_args(
    mocked_responses,
    mock_known_provider_configs,
    dummy_openid_provider,
    dummy_ua,
    dummy_app_server,
):
    # arrange
    client = OpenidClient.from_issuer_url(
        url="https://provider.example.com/openid-connect",
        authentication_redirect_uri=dummy_app_server.callback_url,
        client_id=dummy_openid_provider.test_client_id,
        client_secret=dummy_openid_provider.test_client_secret,
    )

    # act
    auth_response = dummy_ua.naviagte_to(
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
        for call in mocked_responses.calls
    )


def test_client_type(mock_known_provider_configs):
    # arrange
    public_client = OpenidClient.from_issuer_url(
        url="https://provider.example.com/openid-connect",
        authentication_redirect_uri="",
        client_id="test",
    )
    confidential_client = OpenidClient.from_issuer_url(
        url="https://provider.example.com/openid-connect",
        authentication_redirect_uri="",
        client_id="test",
        client_secret="test",
    )

    # assert
    assert public_client.client_type == "public"
    assert confidential_client.client_type == "confidential"


def test_fetch_userinfo(
    mock_known_provider_configs, dummy_openid_provider, dummy_app_server, dummy_ua
):
    # arrange
    client = OpenidClient.from_issuer_url(
        url="https://provider.example.com/openid-connect",
        authentication_redirect_uri=dummy_app_server.callback_url,
        client_id=dummy_openid_provider.test_client_id,
        client_secret=dummy_openid_provider.test_client_secret,
    )

    # act
    response = client.fetch_userinfo(dummy_openid_provider.cheat_token)

    # assert
    assert isinstance(response, UserinfoSuccessResponse)
    assert response.sub == "abc123"
    assert response.username == "test-user"
