import logging
from http import HTTPStatus
from typing import Mapping, Tuple

import pytest
from furl import furl

from simple_openid.client import OpenidClient
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

    def on_login(url: furl) -> Tuple[int, Mapping[str, str], str]:
        url = oidc_client.authorization_code_flow.start_authentication()
        return (
            HTTPStatus.FOUND,
            {
                "Location": url,
            },
            f"Go to {url}",
        )

    def on_login_callback(url: furl) -> Tuple[int, Mapping[str, str], str]:
        response = oidc_client.authorization_code_flow.handle_authentication_result(
            str(url)
        )
        assert isinstance(response, TokenSuccessResponse)
        real_app_server.done()
        return HTTPStatus.OK, {}, f"Success. You can close this tab."

    # act (login)
    logger.info(f"Visit {real_app_server.login_url}")
    real_app_server.serve_until_done(on_login, on_login_callback)

    # act (get userinfo)
    # TODO Implement test for getting userinfo
