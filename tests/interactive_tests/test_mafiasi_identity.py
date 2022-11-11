import logging
from http import HTTPStatus
from typing import Mapping, Tuple

import pytest
from furl import furl

from simple_openid.client import OpenidClient
from simple_openid.data import IdToken, UserinfoSuccessResponse
from simple_openid.flows.authorization_code_flow import TokenSuccessResponse

logger = logging.getLogger(__name__)


@pytest.mark.interactive()
def test_complete_login(real_app_server):
    # arrange
    oidc_client = OpenidClient.from_issuer_url(
        "https://identity.mafiasi.de/auth/realms/mafiasi/",
        real_app_server.login_callback_url,
        "dev-client",
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

    # act (get userinfo)
    response = oidc_client.fetch_userinfo(token_response.access_token)
    assert isinstance(response, UserinfoSuccessResponse)
    assert response.sub != ""
