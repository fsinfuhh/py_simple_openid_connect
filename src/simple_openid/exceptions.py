from simple_openid.data import AuthenticationErrorResponse


class OpenidProtocolError(Exception):
    """
    A generic error that is raised when the OpenID protocol was irrecoverably violated
    """

    def __init__(self, msg: str, *data) -> None:
        super().__init__(msg, *data)


class AuthenticationFailedError(Exception):
    """
    A previous authentication attempt has failed
    """

    def __init__(self, error: AuthenticationErrorResponse):
        super().__init__(error)
