from typing import TYPE_CHECKING, Union

from simple_openid_connect.data import TokenErrorResponse, TokenSuccessResponse
from simple_openid_connect.exceptions import UnsupportedByProviderError
from simple_openid_connect.flows import client_credentials_grant as impl

if TYPE_CHECKING:
    from simple_openid_connect.client import OpenidClient


class ClientCredentialsGrantClient:
    """
    A client that implements `*Client Credentials Grant* <https://oauth.net/2/grant-types/client-credentials/>`_ (sometimes called Service Account Authentication).

    It is exposed via :data:`OpenidClient.client_credentials_grant <simple_openid_connect.client.OpenidClient.client_credentials_grant>`
    """

    def __init__(self, base_client: "OpenidClient"):
        self._base_client = base_client

    def authenticate(self) -> Union[TokenSuccessResponse, TokenErrorResponse]:
        """
        Retrieve a token that is dedicated to the authenticated client from the provider.

        :returns: The result of the exchange
        """
        if self._base_client.provider_config.token_endpoint is None:
            raise UnsupportedByProviderError(
                f"The OpenID provider {self._base_client.provider_config.issuer} only seems to support the implicit flow and does not have a token endpoint"
            )

        return impl.authenticate(
            token_endpoint=self._base_client.provider_config.token_endpoint,
            scope=self._base_client.scope,
            client_authentication=self._base_client.client_auth,
        )
