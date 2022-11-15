"""
Utilities and data types used when authenticating the relying party (client).

This should not be confused with authenticating a user as the user authentication at the OP is of no concern to us.
Instead, these authenticate the relying party when e.g. exchanging tokens or requesting user information.
It is a necessary process because while access tokens grant a relying party access to certain user information, the
relying party must still identify itself to the OP when accessing that information.

For more information visit `Section 9 of OpenID Connect Core 1.0 <https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication>`_ and `Section 2.3 of OAuth 2.0 [RFC6749] <https://www.rfc-editor.org/rfc/rfc6749#section-2.3>`_.
"""

import abc
from typing import Any

from requests import models
from requests.auth import AuthBase, HTTPBasicAuth

# TODO Implement more client authentication methods


class ClientAuthenticationMethod(AuthBase, metaclass=abc.ABCMeta):
    """
    A base class for client authentication methods which describes the interface that each method implements to authenticate requests.

    This class also extends requests :class:`AuthBase` so that all derived implementations can directly be used with requests to authenticate something.
    """

    NAME: str
    "How this authentication method is called in the Openid spec"

    @property
    @abc.abstractmethod
    def client_id(self) -> str:
        """
        The client id which is assigned to this app
        """
        raise NotImplementedError()


class NoneAuth(ClientAuthenticationMethod):
    """
    The Client does not authenticate itself at the Token Endpoint, either because it uses only the Implicit Flow (and so does not use the Token Endpoint) or because it is a Public Client with no Client Secret or other authentication mechanism.
    """

    NAME = "none"

    def __init__(self, client_id: str):
        self._client_id = client_id

    def __call__(self, r: models.PreparedRequest) -> models.PreparedRequest:
        return r

    @property
    def client_id(self) -> str:
        return self._client_id


class ClientSecretBasicAuth(ClientAuthenticationMethod, HTTPBasicAuth):
    """
    Clients that have received a `client_secret` value from the Authorization Server authenticate with the Authorization Server using the HTTP Basic authentication scheme.
    """

    NAME = "client_secret_basic"

    @property
    def client_id(self) -> str:
        return str(self.username)

    def __init__(self, client_id: str, client_secret: str):
        """
        :param client_id: The client id which was set or issued during client registration
        :param client_secret: The client secret which was issued during client registration
        """
        super().__init__(username=client_id, password=client_secret)


class AccessTokenBearerAuth(AuthBase):
    """
    Authenticate requests using a given bearer token
    """

    access_token: str

    def __init__(self, access_token: str):
        super().__init__()
        self.access_token = access_token

    def __eq__(self, other: Any) -> bool:
        return self.access_token == getattr(other, "access_token", None)

    def __ne__(self, other: Any) -> bool:
        return not self == other

    def __call__(self, r: models.PreparedRequest) -> models.PreparedRequest:
        r.headers["Authorization"] = f"Bearer {self.access_token}"
        return r
