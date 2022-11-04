class OpenidProtocolError(Exception):
    """
    A generic error that is raised when the OpenID protocol was irrecoverably violated
    """

    def __init__(self, msg: str, *data) -> None:
        super().__init__(msg, *data)
