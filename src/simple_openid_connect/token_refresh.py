"""
Refresh token exchange implementation.
"""

import logging
from typing import Union

import requests

from simple_openid_connect.client_authentication import ClientAuthenticationMethod
from simple_openid_connect.data import (
    TokenErrorResponse,
    TokenRequest,
    TokenSuccessResponse,
)

logger = logging.getLogger(__name__)


def exchange_refresh_token(
    token_endpoint: str,
    refresh_token: str,
    client_authentication: ClientAuthenticationMethod,
) -> Union[TokenSuccessResponse, TokenErrorResponse]:
    """
    Exchange a refresh token for new tokens

    :param token_endpoint: The endpoint of the OP at which tokens can be exchanged.
        Corresponds to :data:`ProviderMetadata.token_endpoint <simple_openid_connect.data.ProviderMetadata.token_endpoint>`
    :param refresh_token: The refresh token to use
    :param client_authentication: A way for the client to authenticate itself
    """
    logger.debug("exchanging refresh token for new tokens")
    request_msg = TokenRequest(
        grant_type="refresh_token",
        refresh_token=refresh_token,
        client_id=client_authentication.client_id,
    )
    response = requests.post(
        token_endpoint,
        data=request_msg.encode_x_www_form_urlencoded(),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
        },
        auth=client_authentication,
    )

    if response.status_code == 200:
        return TokenSuccessResponse.model_validate_json(response.content)
    else:
        return TokenErrorResponse.model_validate_json(response.content)
