"""
JSON-Web-Key handling code
"""

from typing import List, cast

from cryptojwt import JWK, KeyBundle

from simple_openid_connect.exceptions import OpenidProtocolError


def fetch_jwks(jwks_uri: str) -> List[JWK]:
    """
    Fetch JSON web keys from the given jwks_uri.
    This uri is part of the provider configuration and used to validate responses and tokens sent by the provider.

    :raises OpenidProtocolError: If fetching the keys fails
    """
    bundle = KeyBundle(source=jwks_uri)
    keys = cast(List[JWK], bundle.keys())
    if not keys:
        raise OpenidProtocolError("Failed to fetch keys")
    return keys
