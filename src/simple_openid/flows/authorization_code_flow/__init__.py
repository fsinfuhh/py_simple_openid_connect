import requests

from simple_openid.client_authentication import ClientAuthenticationMethod

from .data import (
    AuthenticationErrorResponse,
    AuthenticationRequest,
    AuthenticationSuccessResponse,
    TokenErrorResponse,
    TokenRequest,
    TokenSuccessResponse,
)


def start_authentication(
    authorization_endpoint: str, scope: str, client_id: str, redirect_uri: str
) -> str:
    """
    Start the authentication process by constructing an appropriate :class:`AuthenticationRequest`, serializing it and
    returning a which the end user now needs to visit.

    :returns: A URL to which the user agent should be redirected
    """
    request = AuthenticationRequest(
        scope=scope, client_id=client_id, redirect_uri=redirect_uri
    )
    return request.encode_url(authorization_endpoint)


def exchange_code_for_tokens(
    token_endpoint: str,
    authentication_response: AuthenticationSuccessResponse,
    redirect_uri: str,
    client_authentication: ClientAuthenticationMethod,
) -> TokenSuccessResponse | TokenErrorResponse:
    """
    Exchange a received code for access, refresh and id tokens.

    :param token_endpoint: The endpoint of the OP at which tokens can be exchanged.
        Corresponds to :data:`ProviderMetadata.token_endpoint <simple_openid.data.ProviderMetadata.token_endpoint>`
    :param authentication_response: The (successful) response which this app received after the user has come back from
        the OP.
    :param redirect_uri: The callback URI that was specified during the authentication initiation.
    :param client_authentication: A way for the client to authenticate itself

    :return: The result of the token exchange
    """
    request_msg = TokenRequest(
        code=authentication_response.code,
        redirect_uri=redirect_uri,
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
        response_msg = TokenSuccessResponse.parse_raw(response.content)
        return response_msg
    else:
        response_msg = TokenErrorResponse.parse_raw(response.content)
        return response_msg
