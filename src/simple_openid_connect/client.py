"""
A more contiguous client implementation of the Openid-Connect protocol that offers simpler APIs at the cost of losing some flexibility.
"""

from typing import (
    Any,
    Callable,
    Dict,
    List,
    Literal,
    Mapping,
    Optional,
    Type,
    TypeVar,
    Union,
)

from cryptojwt import JWK
from cryptojwt.jwk.jwk import key_from_jwk_dict

from simple_openid_connect import (
    jwk,
    rp_initiated_logout,
    token_introspection,
    token_refresh,
    userinfo,
)
from simple_openid_connect.client_authentication import (
    ClientAuthenticationMethod,
    ClientSecretBasicAuth,
    NoneAuth,
)
from simple_openid_connect.data import (
    IdToken,
    ProviderMetadata,
    RpInitiatedLogoutRequest,
    TokenErrorResponse,
    TokenIntrospectionErrorResponse,
    TokenIntrospectionSuccessResponse,
    TokenSuccessResponse,
    UserinfoErrorResponse,
    UserinfoSuccessResponse,
)
from simple_openid_connect.discovery import discover_configuration_from_issuer
from simple_openid_connect.exceptions import UnsupportedByProviderError
from simple_openid_connect.flows.authorization_code_flow.client import (
    AuthorizationCodeFlowClient,
)
from simple_openid_connect.flows.client_credentials_grant.client import (
    ClientCredentialsGrantClient,
)
from simple_openid_connect.flows.direct_access_grant.client import (
    DirectAccessGrantClient,
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

    direct_access_grant: DirectAccessGrantClient
    "*Direct Access Grant* (or *Resource Owner Password Credentials Grant*) functionality"

    client_credentials_grant: ClientCredentialsGrantClient
    "*Client Credentials Grant* (or *Service Account Authentication*) functionality"

    def __init__(
        self,
        provider_config: ProviderMetadata,
        provider_keys: List[JWK],
        authentication_redirect_uri: Optional[str],
        client_id: str,
        client_secret: Optional[str] = None,
        scope: str = "openid",
    ):
        self.provider_config = provider_config
        self.provider_keys = provider_keys
        self.authorization_code_flow = AuthorizationCodeFlowClient(self)
        self.direct_access_grant = DirectAccessGrantClient(self)
        self.client_credentials_grant = ClientCredentialsGrantClient(self)
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
        authentication_redirect_uri: Optional[str],
        client_id: str,
        client_secret: Union[str, None] = None,
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
        authentication_redirect_uri: Optional[str],
        client_id: str,
        client_secret: Union[str, None] = None,
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
    ) -> Union[UserinfoSuccessResponse, UserinfoErrorResponse]:
        """
        Fetch user information from the OP by doing a userinfo request.

        Which users information is fetched is determined by the OP directly from the used access token.

        :param access_token: An access token which grants access to user information.

        :raises UnsupportedByProviderError: If the provider does not support userinfo requests or the userinfo endpoint is not known.

        :returns: The OPs response
        """
        if self.provider_config.userinfo_endpoint is None:
            raise UnsupportedByProviderError(
                f"The OpenID provider {self.provider_config.issuer} does not support userinfo requests or does not advertise its userinfo endpoint"
            )

        return userinfo.fetch_userinfo(
            self.provider_config.userinfo_endpoint, access_token
        )

    def decode_id_token(
        self,
        raw_token: str,
        nonce: Union[str, None] = None,
        extra_trusted_audiences: List[str] = [],
        min_iat: float = 0,
        validate_acr: Union[Callable[[str], None], None] = None,
        min_auth_time: float = 0,
    ) -> IdToken:
        """
        Decode and verify an encoded and signed id token.

        Issuer and client id for validation are taken from the client configuration but extra optional validation
        information can be supplied as well.

        :param raw_token: The encoded and signed id token.
            This could e.g. be retrieved as part of the authentication process and returned by the OP in :data:`TokenSuccessResponse.id_token <simple_openid_connect.flows.authorization_code_flow.data.TokenSuccessResponse.id_token>`.
        :param nonce: The nonce that was used during authentication.
            It is carried over by the OP into ID-Tokens and must now match.
        :param extra_trusted_audiences: Which token audiences (client ids) to consider trusted beside this client's own client_id.
            This is usually an empty list but if the token is intended to be used by more than one client, all of these need to be listed in the tokens :data:`IdToken.aud` field, and they all need to be known and trusted by this client.
        :param min_iat: Minimum value that the tokens :data:`IdToken.iat` claim must be.
            This value is a posix timestamp and defaults to 0 which allows arbitrarily old `iat` dates.
        :param validate_acr: A callable that receives this tokens :data:`IdToken.acr` value and must perform its own validation.
            This is necessary because the value of acr is outside OpenId-Connect specification and usage specific.
            If not given, acr is assumed to always be valid.
        :param min_auth_time: The point in time which is considered the minimum at which a user should have authenticated.
            It basically means that if the user was authenticated very far in the past and reused their session, the time at which the original authentication took place must be greater than this value.
            This is only validated if the :data:`IdToken.auth_time` is present in the token.
            This value is a posix timestamp and default to 0 which allows arbitrarily old `auth_time` dates.

        :raises ValidationError: if the validation fails
        """
        token = IdToken.parse_jws(raw_token, self.provider_keys)
        token.validate_extern(
            issuer=self.provider_config.issuer,
            client_id=self.client_auth.client_id,
            nonce=nonce,
            extra_trusted_audiences=extra_trusted_audiences,
            min_iat=min_iat,
            validate_acr=validate_acr,
            min_auth_time=min_auth_time,
        )
        return token

    def exchange_refresh_token(
        self, refresh_token: str
    ) -> Union[TokenSuccessResponse, TokenErrorResponse]:
        """
        Exchange a refresh token for new tokens

        :param refresh_token: The refresh token to use

        :raise UnsupportedByProviderError: If the provider only supports implicit flow and has no token endpoint.
        """
        if self.provider_config.token_endpoint is None:
            raise UnsupportedByProviderError(
                f"The OpenID provider {self.provider_config.issuer} only supports the implicit flow and does not have a token endpoint"
            )

        return token_refresh.exchange_refresh_token(
            token_endpoint=self.provider_config.token_endpoint,
            refresh_token=refresh_token,
            client_authentication=self.client_auth,
        )

    def initiate_logout(
        self, request: Union[RpInitiatedLogoutRequest, None] = None
    ) -> str:
        """
        Initiate user logout as a Relying-Party

        :param request: Additional data pertaining to the logout

        :raises UnsupportedByProviderError: If the provider does not support Relying-Party-Initiated logout.

        :returns: A url to which the user should be redirected
        """
        if self.provider_config.end_session_endpoint is None:
            raise UnsupportedByProviderError(
                f"The OpenID provider {self.provider_config.issuer} does not support RP-initiated logout"
            )

        return rp_initiated_logout.initiate_logout(
            self.provider_config.end_session_endpoint, request
        )

    def introspect_token(
        self, token: str, token_type_hint: Union[str, None] = None
    ) -> Union[TokenIntrospectionSuccessResponse, TokenIntrospectionErrorResponse]:
        """
        Introspect the given token at the OP.

        :param token: The token to introspect.
        :param token_type_hint: Which type of token this is e.g. `refresh_token` or `access_token`.

        :raises UnsupportedByProviderError: If the provider does not support token introspection.

        :returns: The OPs response
        """
        if self.provider_config.introspection_endpoint is None:
            raise UnsupportedByProviderError(
                f"The OpenID provider {self.provider_config.issuer} does not support token introspection"
            )

        return token_introspection.introspect_token(
            introspection_endpoint=self.provider_config.introspection_endpoint,
            token=token,
            auth=self.client_auth,
            token_type_hint=token_type_hint,
        )

    def __getstate__(self) -> Mapping[str, Any]:
        # this implements support for pickling this class
        # it is basically the default pickle behavior but explicitly serializes keys because they are FFI backed and not normally picklable
        result = self.__dict__.copy()
        result["provider_keys"] = [k.serialize() for k in self.provider_keys]
        return result

    def __setstate__(self, state: Dict[str, Any]) -> None:
        # this implements support for unpickling this class
        # it is basically the default pickle behavior but explicitly deserializes keys
        state["provider_keys"] = [key_from_jwk_dict(k) for k in state["provider_keys"]]
        self.__dict__ = state
