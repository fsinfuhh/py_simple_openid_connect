"""
Exceptions that are raised at various parts of this library.
"""
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from simple_openid_connect.data import AuthenticationErrorResponse


class OpenidProtocolError(Exception):
    """
    A generic error that is raised when the OpenID protocol was irrecoverably violated
    """

    def __init__(self, msg: str, *data: Any) -> None:
        super().__init__(msg, *data)


class ImpossibleOperationError(OpenidProtocolError):
    """
    This error indicates that an intended operation could not be performed because it is not possible under the current
    configuration
    """

    pass


class UnsupportedByProviderError(OpenidProtocolError):
    """
    This error indicates that a desired feature is not supported by the OpenID Provider
    """

    pass


class AuthenticationFailedError(Exception):
    """
    A previous authentication attempt has failed
    """

    def __init__(self, error: "AuthenticationErrorResponse"):
        super().__init__(error)


class ValidationError(AssertionError):
    """
    A validation failed
    """

    def __init__(self, msg: str):
        super().__init__(msg)
