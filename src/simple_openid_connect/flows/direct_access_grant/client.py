from typing import TYPE_CHECKING, Union

from simple_openid_connect.data import TokenErrorResponse, TokenSuccessResponse
from simple_openid_connect.exceptions import UnsupportedByProviderError
from simple_openid_connect.flows import direct_access_grant as impl

if TYPE_CHECKING:
    from simple_openid_connect.client import OpenidClient


class DirectAccessGrantClient:
    """
    A client that implements *Direct Access Grant* (or *Resource Owner Password Credentials Grant*) functionality.

    It is exposed via :data:`OpenidClient.authorization_code_flow <simple_openid_connect.client.OpenidClient.direct_access_grant>`.
    """

    def __init__(self, base_client: "OpenidClient"):
        self._base_client = base_client

    def authenticate(
        self, username: str, password: str
    ) -> Union[TokenSuccessResponse, TokenErrorResponse]:
        """
        Exchange a given username and password for access, refresh and id tokens.

        :returns: The result of the exchange
        """
        if self._base_client.provider_config.token_endpoint is None:
            raise UnsupportedByProviderError(
                f"The OpenID provider {self._base_client.provider_config.issuer} only seems to support the implicit flow and does not have a token endpoint"
            )

        return impl.authenticate(
            token_endpoint=self._base_client.provider_config.token_endpoint,
            scope=self._base_client.scope,
            username=username,
            password=password,
            client_authentication=self._base_client.client_auth,
        )
