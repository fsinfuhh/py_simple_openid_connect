import logging
from http import HTTPStatus
from typing import Mapping, Tuple

import pytest
from furl import furl

from simple_openid_connect.client import OpenidClient
from simple_openid_connect.data import (
    IdToken,
    TokenIntrospectionErrorResponse,
    TokenIntrospectionSuccessResponse,
    UserinfoSuccessResponse,
)
from simple_openid_connect.flows.authorization_code_flow import TokenSuccessResponse

logger = logging.getLogger(__name__)


@pytest.mark.interactive()
def test_public_client(real_app_server, secrets):
    # arrange
    oidc_client = OpenidClient.from_issuer_url(
        "https://identity.mafiasi.de/auth/realms/simple_openid_test",
        real_app_server.callback_url,
        client_id=secrets["mafiasi_identity_public_client_id"],
    )
    token_response: TokenSuccessResponse

    def on_login(_url: furl) -> Tuple[int, Mapping[str, str], str]:
        url = oidc_client.authorization_code_flow.start_authentication()
        return (
            HTTPStatus.FOUND,
            {
                "Location": url,
            },
            f"Go to {url}",
        )

    def on_login_callback(url: furl) -> Tuple[int, Mapping[str, str], str]:
        nonlocal token_response
        response = oidc_client.authorization_code_flow.handle_authentication_result(
            str(url)
        )
        assert isinstance(response, TokenSuccessResponse)
        token_response = response
        real_app_server.done()
        return HTTPStatus.OK, {}, f"Success. You can close this tab."

    # act (login)
    logger.info(f"Visit {real_app_server.login_url}")
    real_app_server.serve_until_done(on_login, on_login_callback)

    # act (decode id token)
    id_token = oidc_client.decode_id_token(token_response.id_token)
    assert isinstance(id_token, IdToken)
    id_token.validate_extern(
        oidc_client.provider_config.issuer, oidc_client.client_auth.client_id
    )

    # act (get userinfo)
    response = oidc_client.fetch_userinfo(token_response.access_token)
    assert isinstance(response, UserinfoSuccessResponse)
    assert response.sub != ""

    # act (introspect access token). This fails because te public client cannot authenticate itself
    response = oidc_client.introspect_token(token_response.access_token, "access_token")
    assert isinstance(response, TokenIntrospectionErrorResponse)
    assert response.error == "invalid_request"
    assert response.error_description == "Authentication failed."

    # act (refresh tokens)
    response = oidc_client.exchange_refresh_token(token_response.refresh_token)
    assert isinstance(response, TokenSuccessResponse)


@pytest.mark.interactive()
def test_confidential_client(real_app_server, secrets):
    # arrange
    oidc_client = OpenidClient.from_issuer_url(
        "https://identity.mafiasi.de/auth/realms/simple_openid_test",
        real_app_server.callback_url,
        client_id=secrets["mafiasi_identity_confidential_client_id"],
        client_secret=secrets["mafiasi_identity_confidential_client_secret"],
    )
    token_response: TokenSuccessResponse

    def on_login(_url: furl) -> Tuple[int, Mapping[str, str], str]:
        url = oidc_client.authorization_code_flow.start_authentication()
        return (
            HTTPStatus.FOUND,
            {
                "Location": url,
            },
            f"Go to {url}",
        )

    def on_login_callback(url: furl) -> Tuple[int, Mapping[str, str], str]:
        nonlocal token_response
        response = oidc_client.authorization_code_flow.handle_authentication_result(
            str(url)
        )
        assert isinstance(response, TokenSuccessResponse)
        token_response = response
        real_app_server.done()
        return HTTPStatus.OK, {}, f"Success. You can close this tab."

    # act (login)
    logger.info(f"Visit {real_app_server.login_url}")
    real_app_server.serve_until_done(on_login, on_login_callback)

    # act (decode id token)
    id_token = oidc_client.decode_id_token(token_response.id_token)
    assert isinstance(id_token, IdToken)
    id_token.validate_extern(
        oidc_client.provider_config.issuer, oidc_client.client_auth.client_id
    )

    # act (get userinfo)
    response = oidc_client.fetch_userinfo(token_response.access_token)
    assert isinstance(response, UserinfoSuccessResponse)
    assert response.sub != ""

    # act (introspect access token)
    response = oidc_client.introspect_token(token_response.access_token, "access_token")
    assert isinstance(response, TokenIntrospectionSuccessResponse)

    # act (introspect access token)
    response = oidc_client.introspect_token(
        token_response.refresh_token, "refresh_token"
    )
    assert isinstance(response, TokenIntrospectionSuccessResponse)

    # act (refresh tokens)
    response = oidc_client.exchange_refresh_token(token_response.refresh_token)
    assert isinstance(response, TokenSuccessResponse)
