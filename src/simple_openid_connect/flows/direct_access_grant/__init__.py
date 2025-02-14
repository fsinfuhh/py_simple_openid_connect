"""
The *Direct Access Grant* (or *Resource Owner Password Credentials Grant*).

Using this flow, a users credentials (i.e. username and password) are directly sent to the OpenId issuer.

.. warning::
    This way of exchanging credentials for tokens is considered legacy and not recommended but some app designs may still require it.
    The latest `OAuth 2.0 Security Best Current Practices <https://oauth.net/2/oauth-best-practice/>`_ even disallows the password grant entirely.
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


def authenticate(
    token_endpoint: str,
    scope: str,
    username: str,
    password: str,
    client_authentication: ClientAuthenticationMethod,
) -> Union[TokenSuccessResponse, TokenErrorResponse]:
    """
    Exchange a given username and password for access, refresh and id tokens.

    :param token_endpoint: The endpoint of the OP at which tokens can be exchanged.
        Corresponds to :data:`ProviderMetadata.token_endpoint <simple_openid_connect.data.ProviderMetadata.token_endpoint>`.
    :param scope: The scope requested by the application
    :param username: Username of the user who should be authenticated.
    :param password: Password of the user who should be authenticated.
    :param client_authentication: A way for the client to authenticate itself

    :returns: The result of the exchange
    """
    logger.debug("exchanging username/password for tokens")
    request_msg = TokenRequest(
        grant_type="password",
        scope=scope,
        username=username,
        password=password,
    )
    response = requests.post(
        token_endpoint,
        data=request_msg.encode_x_www_form_urlencoded(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        auth=client_authentication,
    )

    if response.status_code == 200:
        return TokenSuccessResponse.model_validate_json(response.content)
    else:
        return TokenErrorResponse.model_validate_json(response.content)
