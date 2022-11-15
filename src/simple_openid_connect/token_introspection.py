"""
`OAuth 2.0 Token Introspection <https://www.rfc-editor.org/rfc/rfc7662>`_ implementation.
"""

from typing import Union

import requests

from simple_openid_connect.client_authentication import ClientAuthenticationMethod
from simple_openid_connect.data import (
    TokenIntrospectionErrorResponse,
    TokenIntrospectionRequest,
    TokenIntrospectionSuccessResponse,
)


def introspect_token(
    introspection_endpoint: str,
    token: str,
    auth: ClientAuthenticationMethod,
    token_type_hint: Union[str, None] = None,
) -> Union[TokenIntrospectionSuccessResponse, TokenIntrospectionErrorResponse]:
    """
    Introspect the given token at the OP.

    :param introspection_endpoint: The token introspection endpoint of the OP.
    :param token: The token to introspect.
    :param auth: Method with which this request is authenticated to the OP.
    :param token_type_hint: Which type of token this is e.g. `refresh_token` or `access_token`.
    :return: The OPs response
    """
    request = TokenIntrospectionRequest(token=token, token_type_hint=token_type_hint)
    response = requests.post(
        introspection_endpoint,
        request.encode_x_www_form_urlencoded(),
        auth=auth,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )

    if response.status_code == 200:
        return TokenIntrospectionSuccessResponse.parse_raw(response.content)
    else:
        return TokenIntrospectionErrorResponse.parse_raw(response.content)
