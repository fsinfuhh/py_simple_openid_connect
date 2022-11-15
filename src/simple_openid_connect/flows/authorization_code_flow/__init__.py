"""
The Authorization Code Flow returns an Authorization Code to the Client, which can then exchange it for an ID Token and an Access Token.
This provides the benefit of not exposing any tokens to the User Agent and possibly other malicious applications with access to the User Agent.
The Authorization Server can also authenticate the Client before exchanging the Authorization Code for an Access Token.

**The Authorization Code flow is suitable for Clients that can securely maintain a Client Secret between themselves and the Authorization Server.**
"""
import copy
import logging
from typing import Literal, Union

import requests
from furl import furl

from simple_openid_connect.client_authentication import ClientAuthenticationMethod
from simple_openid_connect.data import (
    AuthenticationErrorResponse,
    AuthenticationRequest,
    AuthenticationSuccessResponse,
    TokenErrorResponse,
    TokenRequest,
    TokenSuccessResponse,
)
from simple_openid_connect.exceptions import AuthenticationFailedError

logger = logging.getLogger(__name__)


def start_authentication(
    authorization_endpoint: str, scope: str, client_id: str, redirect_uri: str
) -> str:
    """
    Start the authentication process by constructing an appropriate :class:`AuthenticationRequest`, serializing it and
    returning a which the end user now needs to visit.

    :returns: A URL to which the user agent should be redirected
    """
    request = AuthenticationRequest(
        scope=scope,
        client_id=client_id,
        redirect_uri=redirect_uri,
        response_type="code",
    )
    return request.encode_url(authorization_endpoint)


def handle_authentication_result(
    current_url: str,
    token_endpoint: str,
    client_authentication: ClientAuthenticationMethod,
    redirect_uri: Union[Literal["auto"], str] = "auto",
) -> Union[TokenSuccessResponse, TokenErrorResponse]:
    """
    Handle an authentication result that is communicated to the RP in form of the user agents current url after having started an authentication process via :func:`start_authentication`.

    :param current_url: The current URL which the user is visiting.
        The authentication result should be encoded into this url by the authorization server.
    :param token_endpoint: The endpoint of the OP at which tokens can be exchanged.
        Corresponds to :data:`ProviderMetadata.token_endpoint <simple_openid_connect.data.ProviderMetadata.token_endpoint>`
    :param client_authentication: A way for the client to authenticate itself
    :param redirect_uri: The `redirect_uri` that was specified during the authentication initiation.
        If the special value `auto` is used, it is assumed that `current_url` is the that callback and it is stripped of query parameters and fragments to reproduce the originally supplied one.

    :raises AuthenticationFailedError: If the current url indicates an authentication failure that prevents an access token from being retrieved.

    :returns: The result of the token exchange
    """
    current_furl = furl(current_url)
    if "error" in current_furl.query.params.keys():
        raise AuthenticationFailedError(
            AuthenticationErrorResponse.parse_url(str(current_furl))
        )

    if redirect_uri == "auto":
        redirect_uri = str(
            copy.deepcopy(current_furl).remove(fragment=True, query=True)
        )
        logger.debug(
            f"a redirect_uri value of 'auto' was specified. Reproducing redirect_uri (%s) from current_url (%s)",
            redirect_uri,
            current_furl,
        )

    auth_response_msg = AuthenticationSuccessResponse.parse_url(str(current_furl))
    return exchange_code_for_tokens(
        token_endpoint=token_endpoint,
        authentication_response=auth_response_msg,
        redirect_uri=redirect_uri,
        client_authentication=client_authentication,
    )


def exchange_code_for_tokens(
    token_endpoint: str,
    authentication_response: AuthenticationSuccessResponse,
    redirect_uri: str,
    client_authentication: ClientAuthenticationMethod,
) -> Union[TokenSuccessResponse, TokenErrorResponse]:
    """
    Exchange a received code for access, refresh and id tokens.

    You might want to use :func:`handle_authentication_result` if you don't want to parse an authentication result from the users current url yourself.

    :param token_endpoint: The endpoint of the OP at which tokens can be exchanged.
        Corresponds to :data:`ProviderMetadata.token_endpoint <simple_openid_connect.data.ProviderMetadata.token_endpoint>`
    :param authentication_response: The (successful) response which this app received after the user has come back from
        the OP.
    :param redirect_uri: The callback URI that was specified during the authentication initiation.
    :param client_authentication: A way for the client to authenticate itself

    :returns: The result of the token exchange
    """
    logger.debug("exchanging authentication code for tokens")
    request_msg = TokenRequest(
        code=authentication_response.code,
        redirect_uri=redirect_uri,
        client_id=client_authentication.client_id,
        grant_type="authorization_code",
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
        return TokenSuccessResponse.parse_raw(response.content)
    else:
        return TokenErrorResponse.parse_raw(response.content)
