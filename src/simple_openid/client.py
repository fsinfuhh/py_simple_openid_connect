from typing import List, Literal, Optional, Type, TypeVar

from cryptojwt import JWK

from simple_openid import jwk, userinfo
from simple_openid.client_authentication import (
    ClientAuthenticationMethod,
    ClientSecretBasicAuth,
    NoneAuth,
)
from simple_openid.data import (
    IdToken,
    ProviderMetadata,
    UserinfoErrorResponse,
    UserinfoSuccessResponse,
)
from simple_openid.discovery import discover_configuration_from_issuer
from simple_openid.flows.authorization_code_flow.client import (
    AuthorizationCodeFlowClient,
)

Self = TypeVar("Self", bound="OpenidClient")


class OpenidClient:
    """
    A more contiguous client implementation of the Openid-Connect protocol that offers simpler APIs at the cost of losing some flexibility.
    """

    provider_config: ProviderMetadata
    provider_keys: List[JWK]
    client_auth: ClientAuthenticationMethod
    scope: str

    authorization_code_flow: AuthorizationCodeFlowClient
    "*authorization code flow* related functionality"

    def __init__(
        self,
        provider_config: ProviderMetadata,
        provider_keys: List[JWK],
        authentication_redirect_uri: str,
        client_id: str,
        client_secret: Optional[str] = None,
        scope: str = "openid",
    ):
        self.provider_config = provider_config
        self.provider_keys = provider_keys
        self.authorization_code_flow = AuthorizationCodeFlowClient(self)
        self.scope = scope
        self.authentication_redirect_uri = authentication_redirect_uri

        if client_secret is None:
            self.client_auth = NoneAuth(client_id)
        else:
            if (
                ClientSecretBasicAuth.NAME
                in provider_config.token_endpoint_auth_methods_supported
            ):
                self.client_auth = ClientSecretBasicAuth(client_id, client_secret)
            else:
                raise NotImplementedError(
                    f"a client secret was given but the issuer does not support client_secret_basic authentication which is the only supported method"
                )

    @classmethod
    def from_issuer_url(
        cls: Type[Self],
        url: str,
        authentication_redirect_uri: str,
        client_id: str,
        client_secret: str = None,
        scope: str = "openid",
    ) -> Self:
        """
        Create a new client instance with an issuer url as base, automatically discovering information about the issuer in the process.

        :param url: The url to an Openid issuer
        :param authentication_redirect_uri: URI that is used during the authentication flow to redirect back to this application.
        :param client_id: The already known client id of your application.
            It must be already registered with the issuer.
        :param client_secret: Optionally a client secret which has been assigned to your client from the issuer.
            If not supplied, this client is assumed to be *public* which means it has not client secret because it cannot be kept safe (e.g. a web-app).
        :param scope: Which scopes to request from the OP
        """

        config = discover_configuration_from_issuer(url)
        return cls.from_issuer_config(
            config, authentication_redirect_uri, client_id, client_secret, scope
        )

    @classmethod
    def from_issuer_config(
        cls: Type[Self],
        config: ProviderMetadata,
        authentication_redirect_uri: str,
        client_id: str,
        client_secret: str = None,
        scope: str = "openid",
    ) -> Self:
        """
        Create a new client instance with a resolved issuer configuration as base.

        If you don't have a configuration, use :func:`from_issuer_url` to automatically retrieve it.

        :param config: The configuration of the used issuer.
        :param authentication_redirect_uri: URI that is used during the authentication flow to redirect back to this application.
        :param client_id: The already known client id of your application.
            It must be already registered with the issuer.
        :param client_secret: Optionally a client secret which has been assigned to your client from the issuer.
            If not supplied, this client is assumed to be *public* which means it has not client secret because it cannot be kept safe (e.g. a web-app).
        :param scope: Which scopes to request from the OP
        """
        keys = jwk.fetch_jwks(config.jwks_uri)
        return cls(
            config, keys, authentication_redirect_uri, client_id, client_secret, scope
        )

    @property
    def client_type(self) -> Literal["public", "confidential"]:
        """
        Which type of client behavior is used.

        This is based on whether a client secret has been passed during client construction
        """
        if isinstance(self.client_auth, NoneAuth):
            return "public"
        else:
            return "confidential"

    def fetch_userinfo(
        self, access_token: str
    ) -> UserinfoSuccessResponse | UserinfoErrorResponse:
        """
        Fetch user information from the OP by doing a userinfo request.

        Which users information is fetched is determined by the OP directly from the used access token.

        :param access_token: An access token which grants access to user information.
        :return: The OPs response
        """
        return userinfo.fetch_userinfo(
            self.provider_config.userinfo_endpoint, access_token
        )

    def decode_id_token(self, raw_token: str) -> IdToken:
        """
        Decode and verify an encoded and signed id token

        :param raw_token: The encoded and signed id token.
            This could e.g. be retrieved as part of the authentication process and returned by the OP in :data:`TokenSuccessResponse.id_token <simple_openid.flows.authorization_code_flow.data.TokenSuccessResponse.id_token>`.
        """
        return IdToken.parse_jwt(raw_token, self.provider_keys)
