from typing import TYPE_CHECKING, List, Mapping, Optional, Union

from furl import furl

from simple_openid_connect.data import (
    AuthenticationSuccessResponse,
    TokenErrorResponse,
    TokenSuccessResponse,
)
from simple_openid_connect.exceptions import (
    ImpossibleOperationError,
    UnsupportedByProviderError,
)
from simple_openid_connect.flows import authorization_code_flow as impl

if TYPE_CHECKING:
    from simple_openid_connect.client import OpenidClient


class AuthorizationCodeFlowClient:
    """
    A client that implements *authorization code flow* related functionality.

    It is exposed via :data:`OpenidClient.authorization_code_flow <simple_openid_connect.client.OpenidClient.authorization_code_flow>`.
    """

    def __init__(self, base_client: "OpenidClient"):
        self._base_client = base_client

    def start_authentication(self) -> str:
        """
        Start the authentication process by constructing an appropriate :class:`AuthenticationRequest`, serializing it and
        returning a which the end user now needs to visit.

        :raises ImpossibleOperationError: If the client has no redirect_uri configured and therefore cannot perform this operation.

        :returns: A URL to which the user agent should be redirected
        """
        if self._base_client.authentication_redirect_uri is None:
            raise ImpossibleOperationError(
                "The client has no redirect_uri configured so no authentication flow can be started"
            )

        redirect_uri = furl(self._base_client.authentication_redirect_uri)

        return impl.start_authentication(
            self._base_client.provider_config.authorization_endpoint,
            self._base_client.scope,
            self._base_client.client_auth.client_id,
            redirect_uri.tostr(),
        )

    def handle_authentication_result(
        self,
        current_url: str,
        additional_redirect_args: Optional[Mapping[str, str]] = None,
    ) -> Union[TokenSuccessResponse, TokenErrorResponse]:
        """
        Handle an authentication result that is communicated to the RP in form of the user agents current url after having started an authentication process via :func:`start_authentication`.

        :param current_url: The current URL which the user is visiting.
            The authentication result should be encoded into this url by the authorization server.
        :param additional_redirect_args: Additional URL parameters that were added to the redirect uri.
            They are probably still present in `current_url` but since they could be of any shape, no attempt is made here to automatically reconstruct them.

        :raises AuthenticationFailedError: If the current url indicates an authentication failure that prevents an access token from being retrieved.
        :raises UnsupportedByProviderError: If the provider only supports implicit flow and has no token endpoint.
        :raises ImpossibleOperationError: If the client has no redirect_uri configured and therefore cannot perform this operation.

        :returns: The result of the token exchange
        """
        if self._base_client.provider_config.token_endpoint is None:
            raise UnsupportedByProviderError(
                f"The OpenID provider {self._base_client.provider_config.issuer} only supports the implicit flow and does not have a token endpoint"
            )

        if self._base_client.authentication_redirect_uri is None:
            raise ImpossibleOperationError(
                "The client has no redirect_uri configured so the authentication result cannot be handled correctly"
            )

        redirect_uri = furl(self._base_client.authentication_redirect_uri)
        if additional_redirect_args is not None:
            redirect_uri.args.update(additional_redirect_args)

        return impl.handle_authentication_result(
            current_url=current_url,
            token_endpoint=self._base_client.provider_config.token_endpoint,
            client_authentication=self._base_client.client_auth,
            redirect_uri=redirect_uri.tostr(),
        )

    def exchange_code_for_tokens(
        self, authentication_response: AuthenticationSuccessResponse
    ) -> Union[TokenSuccessResponse, TokenErrorResponse]:
        """
        Exchange a received code for access, refresh and id tokens.

        You might want to use :func:`handle_authentication_result` if you don't want to parse an authentication result from the users current url yourself.

        :param authentication_response: The (successful) response which this app received after the user has come back from the OP.

        :raises UnsupportedByProviderError: If the provider only supports implicit flow and has no token endpoint.
        :raises ImpossibleOperationError: If the client has no redirect_uri configured and therefore cannot perform this operation.

        :returns: The result of the token exchange
        """
        if self._base_client.provider_config.token_endpoint is None:
            raise UnsupportedByProviderError(
                f"The OpenID provider {self._base_client.provider_config.issuer} only supports the implicit flow and does not have a token endpoint"
            )
        if self._base_client.authentication_redirect_uri is None:
            raise ImpossibleOperationError(
                "The client has no redirect_uri configured so the code cannot be exchanged for a token"
            )

        return impl.exchange_code_for_tokens(
            token_endpoint=self._base_client.provider_config.token_endpoint,
            authentication_response=authentication_response,
            redirect_uri=self._base_client.authentication_redirect_uri,
            client_authentication=self._base_client.client_auth,
        )
