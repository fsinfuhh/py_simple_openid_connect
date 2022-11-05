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
