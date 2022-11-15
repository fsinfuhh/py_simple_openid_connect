"""
JSON-Web-Key handling code
"""

from typing import List

from cryptojwt import JWK, KeyBundle


def fetch_jwks(jwks_uri: str) -> List[JWK]:
    """
    Fetch JSON web keys from the given jwks_uri.
    This uri is part of the provider configuration and used to validate responses and tokens sent by the provider.
    """
    bundle = KeyBundle(source=jwks_uri)
    return bundle.keys()  # type: ignore # because cryptojwk has no typedefs, but we know what this returns
