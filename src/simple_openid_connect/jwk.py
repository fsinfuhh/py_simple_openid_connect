"""
JSON-Web-Key handling code
"""

from typing import List, cast, Tuple, Any

from cryptojwt import JWK, KeyBundle

from simple_openid_connect.exceptions import OpenidProtocolError
import requests

requests.request


class _Httpc:
    max_age = 0

    def __call__(self, *args: Any, **kwargs: Any) -> requests.Response:
        """Wrapper around requests.request to allow mocking in tests."""

        response = requests.request(*args, **kwargs)
        cache_control = response.headers.get("Cache-Control")
        if cache_control and "max-age" in cache_control:
            self.max_age = int(cache_control.split("max-age=")[1].split(",")[0])
        return response


def fetch_jwks_max_age(jwks_uri: str) -> Tuple[List[JWK], int]:
    """
    Fetch JSON web keys from the given jwks_uri.
    This uri is part of the provider configuration and used to validate responses and tokens sent by the provider.

    :raises OpenidProtocolError: If fetching the keys fails
    """
    httpc = _Httpc()
    bundle = KeyBundle(source=jwks_uri, httpc=httpc)
    keys = cast(List[JWK], bundle.keys())
    if not keys:
        raise OpenidProtocolError("Failed to fetch keys")
    return keys, httpc.max_age


def fetch_jwks(jwks_uri: str) -> List[JWK]:
    """
    Fetch JSON web keys from the given jwks_uri.
    This uri is part of the provider configuration and used to validate responses and tokens sent by the provider.

    :raises OpenidProtocolError: If fetching the keys fails
    """
    keys, _ = fetch_jwks_max_age(jwks_uri)
    return keys
