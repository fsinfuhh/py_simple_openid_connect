"""
JSON-Web-Key handling code
"""

from typing import List, cast, Tuple, Any, Optional
from datetime import datetime, timedelta, timezone

from cryptojwt import JWK, KeyBundle

from simple_openid_connect.exceptions import OpenidProtocolError
import requests

requests.request


class _Httpc:
    """
    A wrapper around ``requests.request`` which assigns a max_age parameter as instance variable for later retrieval
    """

    max_age: Optional[datetime] = None

    def __call__(self, *args: Any, **kwargs: Any) -> requests.Response:
        now = datetime.now(timezone.utc)
        response = requests.request(*args, **kwargs)

        # extract Cache-Control header and save its value for later
        cache_control = response.headers.get("Cache-Control")
        if cache_control and "max-age" in cache_control:
            http_max_age = int(cache_control.split("max-age=")[1].split(",")[0])
            self.max_age = now + timedelta(seconds=http_max_age)

        return response


def fetch_jwks_max_age(jwks_uri: str) -> Tuple[List[JWK], Optional[datetime]]:
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
