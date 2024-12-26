"""
Implementation of `PKCE <https://datatracker.ietf.org/doc/html/rfc7636>`_ code challenge and verifier generation.

Original code from `@RomeoDespres <https://github.com/RomeoDespres/>`_ in their `pkce repository <https://github.com/RomeoDespres/pkce/blob/b74b1864dc8a2018ca86566a5cfa2fd9fe751c4d/pkce/__init__.py>`_:


Examples
--------

>>> from simple_openid_connect import pkce
>>> code_verifier, code_challenge = pkce.generate_pkce_pair()

>>> from simple_openid_connect import pkce
>>> code_verifier = pkce.generate_code_verifier(length=128)
>>> code_challenge = pkce.get_code_challenge(code_verifier)
"""

import base64
import hashlib
import secrets
from typing import Tuple


def generate_code_verifier(length: int = 128) -> str:
    """
    Return a random PKCE-compliant code verifier.

    :param length: Code verifier length. Must be betwen 43 and 128.
    :raises ValueError: When `length` is not between 43 and 128.
    :returns: A url-safe string ready to be used as a code verifier.
    """
    if not 43 <= length <= 128:
        msg = "Parameter `length` must verify `43 <= length <= 128`."
        raise ValueError(msg)
    code_verifier = secrets.token_urlsafe(96)[:length]
    return code_verifier


def generate_pkce_pair(code_verifier_length: int = 128) -> Tuple[str, str]:
    """
    Return random PKCE-compliant code verifier and its corresponding code challenge.

    :param code_verifier_length: Length of the generated code verifier. Must be between 43 and 128.
    :raises ValueError: When `code_verifier_length` is not between 43 and 128.
    :returns code_verifier, code_challenge: A tuple containing the code verifier along with its corresponding challenge.
    """
    if not 43 <= code_verifier_length <= 128:
        msg = "Parameter `code_verifier_length` must verify "
        msg += "`43 <= code_verifier_length <= 128`."
        raise ValueError(msg)
    code_verifier = generate_code_verifier(code_verifier_length)
    code_challenge = get_code_challenge(code_verifier)
    return code_verifier, code_challenge


def get_code_challenge(code_verifier: str) -> str:
    """
    Generate the corresponding code challenge for a given verifier.

    :param code_verifier: The code verifier from which a challenge should be derived.
    :raises ValueError: When `code_verifier` is not bettween 43 and 128 long.
    :returns: The url-safe challenge string that corresponds to the given verifier.
    """
    if not 43 <= len(code_verifier) <= 128:
        msg = "Parameter `code_verifier` must verify "
        msg += "`43 <= len(code_verifier) <= 128`."
        raise ValueError(msg)
    hashed = hashlib.sha256(code_verifier.encode("ascii")).digest()
    encoded = base64.urlsafe_b64encode(hashed)
    code_challenge = encoded.decode("ascii")[:-1]
    return code_challenge
