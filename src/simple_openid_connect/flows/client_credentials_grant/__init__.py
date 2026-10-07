"""
The `*Client Credentials Grant* <https://oauth.net/2/grant-types/client-credentials/>`_ (sometimes called Service Account Authentication) implementation.

This grant enables a client to retrieve tokens dedicated to the client and not to a specific user.
"""

import logging

import requests

from simple_openid_connect.client_authentication import ClientAuthenticationMethod
from simple_openid_connect.data import (
    OauthTokenSuccessResponse,
    TokenErrorResponse,
    TokenRequest,
    TokenSuccessResponse,  # noqa: F401 to preserve legacy import-compatibility
)

logger = logging.getLogger(__name__)


def authenticate(
    token_endpoint: str,
    scope: str,
    client_authentication: ClientAuthenticationMethod,
    session: requests.Session | None = None,
) -> OauthTokenSuccessResponse | TokenErrorResponse:
    """
    Retrieve a token that is dedicated to the authenticated client from the provider.

    :param token_endpoint: The endpoint of the OP at which tokens can be exchanged.
        Corresponds to :data:`ProviderMetadata.token_endpoint <simple_openid_connect.data.ProviderMetadata.token_endpoint>`.
    :param scope: The scope requested by the application.
    :param client_authentication: A way for the client to authenticate itself.
    :param session: a `requests.Session` object used to perform all HTTP requests. It can be used to customize certificate verification for example.

    :returns: The result of the exchange
    """
    logger.debug(
        f"requesting access via client credentials grant as client {client_authentication.client_id}"
    )
    session = session or requests.Session()
    request_msg = TokenRequest(
        grant_type="client_credentials",
        scope=scope,
    )
    response = session.post(
        token_endpoint,
        data=request_msg.encode_x_www_form_urlencoded(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        auth=client_authentication,
    )

    if response.status_code == 200:
        return OauthTokenSuccessResponse.model_validate_json(response.content)
    else:
        return TokenErrorResponse.model_validate_json(response.content)
