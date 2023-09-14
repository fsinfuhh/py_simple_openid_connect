"""
Datatypes and models for various OpenID messages
"""
import enum
import logging
import time
from typing import Any, Callable, List, Literal, Mapping, Optional, Union

from pydantic import AnyHttpUrl, Extra, Field, root_validator

from simple_openid_connect.base_data import OpenidBaseModel
from simple_openid_connect.utils import validate_that

logger = logging.getLogger(__name__)


class ProviderMetadata(OpenidBaseModel):
    """
    OpenID Providers have metadata describing their configuration

    Additional OpenID Provider Metadata parameters MAY also be used. Some are defined by other specifications, such as `OpenID Connect Session Management 1.0 <https://openid.net/specs/openid-connect-session-1_0.html>`_.

    See `OpenID Connect Spec: Provider Metadata <https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata>`_
    """

    class Config:
        extra = Extra.allow
        allow_mutation = False

    issuer: AnyHttpUrl
    "REQUIRED. URL using the https scheme with no query or fragment component that the OP asserts as its Issuer Identifier This MUST be identical to the iss Claim value in ID Tokens issued from this Issuer."

    authorization_endpoint: AnyHttpUrl
    "REQUIRED. URL of the OP's OAuth 2.0 Authorization Endpoint."

    token_endpoint: Optional[AnyHttpUrl]
    "URL of the OP's OAuth 2.0 Token Endpoint. This is REQUIRED unless only the Implicit Flow is used."

    userinfo_endpoint: Optional[AnyHttpUrl]
    "RECOMMENDED. URL of the OP's UserInfo Endpoint. This URL MUST use the https scheme and MAY contain port, path, and query parameter components."

    jwks_uri: AnyHttpUrl
    "REQUIRED. URL of the OP's JSON Web Key Set document This contains the signing key(s) the RP uses to validate signatures from the OP The JWK Set MAY also contain the Server's encryption key(s), which are used by RPs to encrypt requests to the Server When both signing and encryption keys are made available, a use (Key Use) parameter value is REQUIRED for all keys in the referenced JWK Set to indicate each key's intended usage Although some algorithms allow the same key to be used for both signatures and encryption, doing so is NOT RECOMMENDED, as it is less secure The JWK x5c parameter MAY be used to provide X.509 representations of keys provided When used, the bare key values MUST still be present and MUST match those in the certificate. "

    registration_endpoint: Optional[AnyHttpUrl]
    "RECOMMENDED. URL of the OP's Dynamic Client Registration Endpoint"

    scopes_supported: Optional[List[str]]
    "RECOMMENDED. JSON array containing a list of the OAuth 2.0 scope values that this server supports The server MUST support the openid scope value Servers MAY choose not to advertise some supported scope values even when this parameter is used, although those defined in SHOULD be listed, if supported."

    response_types_supported: Optional[List[str]]
    "REQUIRED. JSON array containing a list of the OAuth 2.0 response_type values that this OP supports Dynamic OpenID Providers MUST support the code, id_token, and the token id_token Response Type values."

    response_modes_supported: Optional[List[str]] = ["query", "fragment"]
    "OPTIONAL. JSON array containing a list of the OAuth 2.0 response_mode values that this OP supports, as specified in OAuth 2.0 Multiple Response Type Encoding Practices. " 'If omitted, the default for Dynamic OpenID Providers is ["query", "fragment"].'

    grant_types_supported: Optional[List[str]] = ["authorization_code", "implicit"]
    "OPTIONAL. JSON array containing a list of the OAuth 2.0 Grant Type values that this OP supports Dynamic OpenID Providers MUST support the authorization_code and implicit Grant Type values and MAY support other Grant Types. " 'If omitted, the default value is ["authorization_code", "implicit"].'

    acr_values_supported: Optional[List[str]]
    "OPTIONAL. JSON array containing a list of the Authentication Context Class References that this OP supports."

    subject_types_supported: List[str]
    "REQUIRED. JSON array containing a list of the Subject Identifier types that this OP supports Valid types include pairwise and public."

    id_token_signing_alg_values_supported: List[str]
    "REQUIRED. JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for the ID Token to encode the Claims in a JWT The algorithm RS256 MUST be included The value none MAY be supported, but MUST NOT be used unless the Response Type used returns no ID Token from the Authorization Endpoint (such as when using the Authorization Code Flow)."

    id_token_encryption_alg_values_supported: Optional[List[str]]
    "OPTIONAL. JSON array containing a list of the JWE encryption algorithms (alg values) supported by the OP for the ID Token to encode the Claims in a JWT."

    id_token_encryption_enc_values_supported: Optional[List[str]]
    "OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for the ID Token to encode the Claims in a JWT."

    userinfo_signing_alg_values_supported: Optional[List[str]]
    "OPTIONAL. JSON array containing a list of the JWS signing algorithms (alg values) supported by the UserInfo Endpoint to encode the Claims in a JWT The value none MAY be included."

    userinfo_encryption_alg_values_supported: Optional[List[str]]
    "OPTIONAL. JSON array containing a list of the JWE encryption algorithms (alg values) supported by the UserInfo Endpoint to encode the Claims in a JWT."

    userinfo_encryption_enc_values_supported: Optional[List[str]]
    "OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the UserInfo Endpoint to encode the Claims in a JWT."

    request_object_signing_alg_values_supported: Optional[List[str]]
    "OPTIONAL. JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for Request Objects, which are described in Section 6.1 of OpenID Connect Core 1.0 These algorithms are used both when the Request Object is passed by value (using the request parameter) and when it is passed by reference (using the request_uri parameter) Servers SHOULD support none and RS256."

    request_object_encryption_alg_values_supported: Optional[List[str]]
    "OPTIONAL. JSON array containing a list of the JWE encryption algorithms (alg values) supported by the OP for Request Objects These algorithms are used both when the Request Object is passed by value and when it is passed by reference."

    request_object_encryption_enc_values_supported: Optional[List[str]]
    "OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for Request Objects These algorithms are used both when the Request Object is passed by value and when it is passed by reference."

    token_endpoint_auth_methods_supported: List[str] = Field(
        default=["client_secret_basic"]
    )
    "OPTIONAL. JSON array containing a list of Client Authentication methods supported by this Token Endpoint The options are client_secret_post, client_secret_basic, client_secret_jwt, and private_key_jwt, as described in Section 9 of OpenID Connect Core 1.0 Other authentication methods MAY be defined by extensions. If omitted, the default is client_secret_basic -- the HTTP Basic Authentication Scheme specified in Section 2.3.1 of OAuth 2.0 [RFC6749]."

    token_endpoint_auth_signing_alg_values_supported: Optional[List[str]]
    "OPTIONAL. JSON array containing a list of the JWS signing algorithms (alg values) supported by the Token Endpoint for the signature on the JWT used to authenticate the Client at the Token Endpoint for the private_key_jwt and client_secret_jwt authentication methods Servers SHOULD support RS256 The value none MUST NOT be used."

    display_values_supported: Optional[List[str]]
    "OPTIONAL. JSON array containing a list of the display parameter values that the OpenID Provider supports These values are described in Section 3.1.2.1 of OpenID Connect Core 1.0."

    claim_types_supported: Optional[List[str]]
    "OPTIONAL. JSON array containing a list of the Claim Types that the OpenID Provider supports These Claim Types are described in Section 5.6 of OpenID Connect Core 1.0 Values defined by this specification are normal, aggregated, and distributed If omitted, the implementation supports only normal Claims."

    claims_supported: Optional[List[str]]
    "RECOMMENDED. JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be able to supply values for Note that for privacy or other reasons, this might not be an exhaustive list."

    service_documentation: Optional[AnyHttpUrl]
    "OPTIONAL. URL of a page containing human-readable information that developers might want or need to know when using the OpenID Provider In particular, if the OpenID Provider does not support Dynamic Client Registration, then information on how to register Clients needs to be provided in this documentation."

    claims_locales_supported: Optional[List[str]]
    "OPTIONAL. Languages and scripts supported for values in Claims being returned, represented as a JSON array of BCP47 [RFC5646] language tag values Not all languages and scripts are necessarily supported for all Claim values."

    ui_locales_supported: Optional[List[str]]
    "OPTIONAL. Languages and scripts supported for the user interface, represented as a JSON array of BCP47 [RFC5646] language tag values."

    claims_parameter_supported: Optional[bool] = False
    "OPTIONAL. Boolean value specifying whether the OP supports use of the claims parameter, with true indicating support If omitted, the default value is false."

    request_parameter_supported: Optional[bool] = False
    "OPTIONAL. Boolean value specifying whether the OP supports use of the request parameter, with true indicating support If omitted, the default value is false."

    request_uri_parameter_supported: Optional[bool] = True
    "OPTIONAL. Boolean value specifying whether the OP supports use of the request_uri parameter, with true indicating support. If omitted, the default value is true."

    require_request_uri_registration: Optional[bool] = False
    "OPTIONAL. Boolean value specifying whether the OP requires any request_uri values used to be pre-registered using the request_uris registration parameter Pre-registration is REQUIRED when the value is true. If omitted, the default value is false."

    op_policy_uri: Optional[AnyHttpUrl]
    "OPTIONAL. URL that the OpenID Provider provides to the person registering the Client to read about the OP's requirements on how the Relying Party can use the data provided by the OP The registration process SHOULD display this URL to the person registering the Client if it is given."

    op_tos_uri: Optional[AnyHttpUrl]
    "OPTIONAL. URL that the OpenID Provider provides to the person registering the Client to read about OpenID Provider's terms of service The registration process SHOULD display this URL to the person registering the Client if it is given. "

    end_session_endpoint: Optional[AnyHttpUrl]
    "REQUIRED, if supported by OP. URL at the OP to which an RP can perform a redirect to request that the End-User be logged out at the OP."

    frontchannel_logout_supported: bool = Field(default=False)
    "OPTIONAL. Boolean value specifying whether the OP supports HTTP-based logout, with true indicating support. If omitted, the default value is false."

    frontchannel_logout_session_supported: bool = Field(default=False)
    "OPTIONAL. Boolean value specifying whether the OP can pass iss (issuer) and sid (session ID) query parameters to identify the RP session with the OP when the frontchannel_logout_uri is used. If supported, the sid Claim is also included in ID Tokens issued by the OP. If omitted, the default value is false."

    backchannel_logout_supported: bool = Field(default=False)
    "OPTIONAL. Boolean value specifying whether the OP supports back-channel logout, with true indicating support. If omitted, the default value is false."

    backchannel_logout_session_supported: bool = Field(default=False)
    "OPTIONAL. Boolean value specifying whether the OP can pass a sid (session ID) Claim in the Logout Token to identify the RP session with the OP. If supported, the sid Claim is also included in ID Tokens issued by the OP. If omitted, the default value is false. "

    introspection_endpoint: Optional[AnyHttpUrl]
    "OPTIONAL. URL that the OpenID Provider provides to resource servers to introspect access tokens in accordance to `RFC7662: OAuth 2.0 Token Introspection <https://www.rfc-editor.org/rfc/rfc7662>`_."


class IdToken(OpenidBaseModel):
    """
    The primary extension that OpenID Connect makes to OAuth 2.0 to enable End-Users to be Authenticated is this ID Token data structure.
    The ID Token is a security token that contains Claims about the Authentication of an End-User by an Authorization Server when using a Client, and potentially other requested Claims.

    ID tokens may contain more claims which may be present in this object.

    See `Section 2 of OpenID Connect Core 1.0 <https://openid.net/specs/openid-connect-core-1_0.html#IDToken>`_
    """

    class Config:
        extra = Extra.allow
        allow_mutation = False

    iss: AnyHttpUrl
    "REQUIRED. Issuer Identifier for the Issuer of the response The iss value is a case sensitive URL using the https scheme that contains scheme, host, and optionally, port number and path components and no query or fragment components."

    sub: str
    "REQUIRED. Subject Identifier A locally unique and never reassigned identifier within the Issuer for the End-User, which is intended to be consumed by the Client, e.g., 24400320 or AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4 It MUST NOT exceed 255 ASCII characters in length The sub value is a case sensitive string."

    aud: Union[str, List[str]]
    "REQUIRED. Audience(s) that this ID Token is intended for It MUST contain the OAuth 2.0 client_id of the Relying Party as an audience value It MAY also contain identifiers for other audiences In the general case, the aud value is an array of case sensitive strings In the common special case when there is one audience, the aud value MAY be a single case sensitive string."

    exp: int
    "REQUIRED. Expiration time on or after which the ID Token MUST NOT be accepted for processing The processing of this parameter requires that the current date/time MUST be before the expiration date/time listed in the value Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time."

    iat: int
    "REQUIRED. Time at which the JWT was issued Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time."

    auth_time: Optional[int]
    "Time when the End-User authentication occurred Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time When a max_age request is made or when auth_time is requested as an Essential Claim, then this Claim is REQUIRED; otherwise, its inclusion is OPTIONAL (The auth_time Claim semantically corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] auth_time response parameter.)"

    nonce: Optional[str]
    "String value used to associate a Client session with an ID Token, and to mitigate replay attacks The value is passed through unmodified from the Authentication Request to the ID Token If present in the ID Token, Clients MUST verify that the nonce Claim Value is equal to the value of the nonce parameter sent in the Authentication Request If present in the Authentication Request, Authorization Servers MUST include a nonce Claim in the ID Token with the Claim Value being the nonce value sent in the Authentication Request Authorization Servers SHOULD perform no other processing on nonce values used The nonce value is a case sensitive string. "

    acr: Optional[str]
    "OPTIONAL. Authentication Context Class Reference String specifying an Authentication Context Class Reference value that identifies the Authentication Context Class that the authentication performed satisfied. The value '0' indicates the End-User authentication did not meet the requirements of ISO/IEC 29115 [ISO29115] level 1. Authentication using a long-lived browser cookie, for instance, is one example where the use of 'level 0' is appropriate. Authentications with level 0 SHOULD NOT be used to authorize access to any resource of any monetary value (This corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] nist_auth_level 0.)  An absolute URI or an RFC 6711 [RFC6711] registered name SHOULD be used as the acr value; registered names MUST NOT be used with a different meaning than that which is registered Parties using this claim will need to agree upon the meanings of the values used, which may be context-specific The acr value is a case sensitive string."

    amr: Optional[List[str]]
    "OPTIONAL. Authentication Methods References JSON array of strings that are identifiers for authentication methods used in the authentication For instance, values might indicate that both password and OTP authentication methods were used The definition of particular values to be used in the amr Claim is beyond the scope of this specification Parties using this claim will need to agree upon the meanings of the values used, which may be context-specific The amr value is an array of case sensitive strings."

    azp: Optional[str]
    "OPTIONAL. Authorized party - the party to which the ID Token was issued If present, it MUST contain the OAuth 2.0 Client ID of this party This Claim is only needed when the ID Token has a single audience value and that audience is different than the authorized party It MAY be included even when the authorized party is the same as the sole audience The azp value is a case sensitive string containing a StringOrURI value."

    sid: Optional[str]
    "OPTIONAL. Session ID - String identifier for a Session. This represents a Session of a User Agent or device for a logged-in End-User at an RP. Different sid values are used to identify distinct sessions at an OP. The sid value need only be unique in the context of a particular issuer. Its contents are opaque to the RP."

    def validate_extern(
        self,
        issuer: str,
        client_id: str,
        nonce: Union[str, None] = None,
        extra_trusted_audiences: List[str] = [],
        min_iat: float = 0,
        validate_acr: Union[Callable[[str], None], None] = None,
        min_auth_time: float = 0,
    ) -> None:
        """
        Validate this ID-Token with external data for consistency

        :param issuer: The issuer that this token is supposed to originate from.
            Should usually be :data:`ProviderMetadata.issuer`
        :param client_id: The client id of this client
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
        # this method implements https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation

        # 2. validate issuer
        validate_that(self.iss == issuer, "ID-Token was issued from unexpected issuer")

        # 3. validate audience
        if isinstance(self.aud, str):
            validate_that(
                self.aud == client_id,
                "ID-Token's audience does not contain own client_id",
            )
        elif isinstance(self.aud, list):
            validate_that(
                client_id in self.aud,
                "ID-Token's audience does not contain own client_id",
            )
            validate_that(
                all(i in extra_trusted_audiences for i in self.aud),
                "Not all of the ID-Token's audience are trusted",
            )

        # 4. validate that an azp claim is present if required
        if isinstance(self.aud, list) and len(self.aud) > 1:
            validate_that(
                self.azp is not None,
                "ID-Token does not contain azp claim but is required to because it is issued to more than 1 audience",
            )

        # 5. validate azp claim value
        if self.azp is not None:
            validate_that(
                self.azp == client_id,
                "The ID-Token was not issued to this client (azp claim mismatch)",
            )

        # 9. validate expiry
        validate_that(self.exp > time.time(), "The ID-Token is expired")

        # 10. validate iat
        validate_that(
            self.iat >= min_iat, "The ID-Token was issued too far in the past"
        )

        # 11. validate nonce
        if self.nonce is not None:
            validate_that(
                self.nonce == nonce,
                "The ID-Token's nonce does not match its expected value",
            )

        # 12. validate acr
        if self.acr is not None and validate_acr is not None:
            validate_acr(self.acr)

        # 13. validate auth_time
        if self.auth_time is not None:
            validate_that(
                self.auth_time >= min_auth_time,
                "The session associated with this ID-Token was authenticated too far in the past",
            )


class UserinfoRequest(OpenidBaseModel):
    """
    A request that can be sent to an OP to request information about a user
    """

    pass


class UserinfoSuccessResponse(OpenidBaseModel):
    """
    A successful response to a userinfo request containing data about the requested user.

    This object might contain additional fields if the access token that was used for the userinfo request allows access
    to more claims.
    """

    class Config:
        extra = Extra.allow
        allow_mutation = False

    sub: str
    "Subject of this response, basically a unique user id."


class UserinfoErrorResponse(OpenidBaseModel):
    """
    An error response that is sent back from an OP after requesting user information
    """

    class Config:
        extra = Extra.allow
        allow_mutation = False

    error: str
    error_description: Optional[str]


class AuthenticationRequest(OpenidBaseModel):
    """
    An Authentication Request requests that the End-User be authenticated by the Authorization Server.
    """

    class Config:
        extra = Extra.allow

    scope: str
    "REQUIRED. OpenID Connect authentication requests MUST contain the openid scope value. Multiple scopes are encoded space separated If the openid scope value is not present, the behavior is entirely unspecified Other scope values MAY be present."

    response_type: str
    "REQUIRED. OAuth 2.0 Response Type value that determines the authorization processing flow to be used, including what parameters are returned from the endpoints used When using the Authorization Code Flow, this value is code. "

    client_id: str
    "REQUIRED. OAuth 2.0 Client Identifier valid at the Authorization Server."

    redirect_uri: str
    "REQUIRED. Redirection URI to which the response will be sent This URI MUST exactly match one of the Redirection URI values for the Client pre-registered at the OpenID Provider When using this flow, the Redirection URI SHOULD use the https scheme; however, it MAY use the http scheme, provided that the Client Type is confidential, as defined in Section 2.1 of OAuth 2.0, and provided the OP allows the use of http Redirection URIs in this case The Redirection URI MAY use an alternate scheme, such as one that is intended to identify a callback into a native application."

    state: Optional[str] = None
    "RECOMMENDED. Opaque value used to maintain state between the request and the callback Typically, Cross-Site Request Forgery (CSRF, XSRF) mitigation is done by cryptographically binding the value of this parameter with a browser cookie."

    response_mode: Optional[str] = None
    "OPTIONAL. Informs the Authorization Server of the mechanism to be used for returning parameters from the Authorization Endpoint. This use of this parameter is NOT RECOMMENDED when the Response Mode that would be requested is the default mode specified for the Response Type."

    nonce: Optional[str] = None
    "OPTIONAL. String value used to associate a Client session with an ID Token, and to mitigate replay attacks The value is passed through unmodified from the Authentication Request to the ID Token Sufficient entropy MUST be present in the nonce values used to prevent attackers from guessing values."

    display: Optional[List[str]] = None
    'OPTIONAL. Space delimited, case sensitive list of ASCII string values that specifies whether the Authorization Server prompts the End-User for reauthentication and consent. The defined values are: "page", "popup", "touch" and "wap"'

    prompt: Optional[List[str]] = None
    'OPTIONAL. Space delimited, case sensitive list of ASCII string values that specifies whether the Authorization Server prompts the End-User for reauthentication and consent. The defined values are: "none", "login", "consent" and "select_account".'

    max_age: Optional[int] = None
    "OPTIONAL. Maximum Authentication Age Specifies the allowable elapsed time in seconds since the last time the End-User was actively authenticated by the OP If the elapsed time is greater than this value, the OP MUST attempt to actively re-authenticate the End-User When max_age is used, the ID Token returned MUST include an auth_time Claim Value."

    ui_locales: Optional[List[str]] = None
    "OPTIONAL. End-User's preferred languages and scripts for the user interface, represented as a space-separated list of BCP47 [RFC5646] language tag values, ordered by preference. " 'For instance, the value "fr-CA fr en" represents a preference for French as spoken in Canada, then French (without a region designation), followed by English (without a region designation). ' "An error SHOULD NOT result if some or all of the requested locales are not supported by the OpenID Provider."

    id_token_hint: Optional[str] = None
    "OPTIONAL. ID Token previously issued by the Authorization Server being passed as a hint about the End-User's current or past authenticated session with the Client If the End-User identified by the ID Token is logged in or is logged in by the request, then the Authorization Server returns a positive response; otherwise, it SHOULD return an error, such as login_required When possible, an id_token_hint SHOULD be present when prompt=none is used and an invalid_request error MAY be returned if it is not; however, the server SHOULD respond successfully when possible, even if it is not present The Authorization Server need not be listed as an audience of the ID Token when it is used as an id_token_hint value. "

    login_hint: Optional[str] = None
    "OPTIONAL. Hint to the Authorization Server about the login identifier the End-User might use to log in (if necessary) This hint can be used by an RP if it first asks the End-User for their e-mail address (or other identifier) and then wants to pass that value as a hint to the discovered authorization service It is RECOMMENDED that the hint value match the value used for discovery (which is not supported by this library) This value MAY also be a phone number in the format specified for the `phone_number` Claim The use of this parameter is left to the OP's discretion."

    acr_values: Optional[List[str]] = None
    "OPTIONAL. Requested Authentication Context Class Reference values Space-separated string that specifies the acr values that the Authorization Server is being requested to use for processing this Authentication Request, with the values appearing in order of preference The Authentication Context Class satisfied by the authentication performed is returned as the acr Claim Value, as specified in Section 2 The acr Claim is requested as a Voluntary Claim by this parameter."


class AuthenticationSuccessResponse(OpenidBaseModel):
    """
    A response that is sent by the Authorization Server if a previous :class:`.AuthenticationRequest` could successfully
    be parsed and handled.

    When using the Authorization Code Flow (this flow), the Authorization Response MUST return the parameters defined by adding them as query parameters to the redirect_uri specified in the Authorization Request using the application/x-www-form-urlencoded format, unless a different Response Mode was specified.
    """

    class Config:
        allow_mutation = False

    code: str
    "REQUIRED. The authorization code generated by the authorization server The authorization code MUST expire shortly after it is issued to mitigate the risk of leaks A maximum authorization code lifetime of 10 minutes is RECOMMENDED The client MUST NOT use the authorization code more than once If an authorization code is used more than once, the authorization server MUST deny the request and SHOULD revoke (when possible) all tokens previously issued based on that authorization code The authorization code is bound to the client identifier and redirect URI."

    state: Optional[str]
    "REQUIRED if the `state` parameter was present in the client authorization request The exact value received from the client."


class AuthenticationErrorResponse(OpenidBaseModel):
    """
    A response that is sent by the Authorization Server if a previous :class:`AuthenticationRequest` could not be
    understood or handled.
    It contains additional information about the error that occurred.

    If the End-User denies the request or the End-User authentication fails, the OP (Authorization Server) informs the RP (Client) by using the Error Response parameters.
    (General HTTP errors are returned to the User Agent using the appropriate HTTP status code.)
    """

    class Config:
        extra = Extra.allow
        allow_mutation = False
        use_enum_values = True

    class ErrorType(enum.Enum):
        """
        Possible values for :data:`error <AuthenticationErrorResponse.error>`.
        """

        invalid_request = "invalid_request"
        "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."

        unauthorized_client = "unauthorized_client"
        "The client is not authorized to request an authorization code using this method."

        access_denied = "access_denied"
        "The resource owner or authorization server denied the request."

        unsupported_response_type = "unsupported_response_type"
        "The authorization server does not support obtaining an authorization code using this method."

        invalid_scope = "invalid_scope"
        "The requested scope is invalid, unknown, or malformed."

        server_error = "server_error"
        "The authorization server encountered an unexpected condition that prevented it from fulfilling the request (This error code is needed because a 500 Internal Server Error HTTP status code cannot be returned to the client via an HTTP redirect.)"

        temporarily_unavailable = "temporarily_unavailable"
        "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server (This error code is needed because a 503 Service Unavailable HTTP status code cannot be returned to the client via an HTTP redirect.)"

        interaction_required = "interaction_required"
        "The Authorization Server requires End-User interaction of some form to proceed This error MAY be returned when the prompt parameter value in the Authentication Request is none, but the Authentication Request cannot be completed without displaying a user interface for End-User interaction."

        login_required = "login_required"
        "The Authorization Server requires End-User authentication This error MAY be returned when the prompt parameter value in the Authentication Request is none, but the Authentication Request cannot be completed without displaying a user interface for End-User authentication."

        account_selection_required = "account_selection_required"
        "The End-User is REQUIRED to select a session at the Authorization Server The End-User MAY be authenticated at the Authorization Server with different associated accounts, but the End-User did not select a session This error MAY be returned when the prompt parameter value in the Authentication Request is none, but the Authentication Request cannot be completed without displaying a user interface to prompt for a session to use."

        consent_required = "consent_required"
        "The Authorization Server requires End-User consent This error MAY be returned when the prompt parameter value in the Authentication Request is none, but the Authentication Request cannot be completed without displaying a user interface for End-User consent."

        invalid_request_uri = "invalid_request_uri"
        "The `request_uri` in the Authorization Request returns an error or contains invalid data."

        invalid_request_object = "invalid_request_object"
        "The request parameter contains an invalid Request Object."

        request_not_supported = "request_not_supported"
        "The OP does not support use of the request parameter."

        request_uri_not_supported = "request_uri_not_supported"
        "The OP does not support use of the request_uri parameter."

        registration_not_supported = "registration_not_supported"
        "The OP does not support use of the registration parameter."

    error: ErrorType
    "REQUIRED.  An error code"

    error_description: Optional[str]
    "OPTIONAL. Human-readable text providing additional information, used to assist the client developer in understanding the error that occurred."

    error_uri: Optional[str]
    "OPTIONAL. A URI identifying a human-readable web page with information about the error, used to provide the client developer with additional information about the error."

    state: Optional[str]
    "REQUIRED if a `state` parameter was present in the client authorization request. The exact value received from the client."


class TokenRequest(OpenidBaseModel):
    """
    A Client makes a Token Request by presenting its Authorization Grant (in the form of an Authorization Code) to the Token Endpoint.
    If the Client is a Confidential Client, then it MUST authenticate to the Token Endpoint using the authentication method registered for its client_id.

    This request MUST be sent to the token endpoint using POST with "application/x-www-form-urlencoded" body.
    """

    class Config:
        extra = Extra.allow

    grant_type: Union[
        Literal[
            "authorization_code", "refresh_token", "password", "client_credentials"
        ],
        str,
    ]
    "REQUIRED. Which type of token exchange this request is."

    code: Optional[str] = None
    "REQUIRED, if grant type is 'code', otherwise optional. The authorization code received from the authorization server."

    redirect_uri: Optional[str] = None
    "REQUIRED, if grant_Type is 'code', otherwise not needed. Must be identical to the value that was included in the :data:`AuthenticationRequest <AuthenticationRequest.redirect_uri>`."

    client_id: Optional[str] = None
    "REQUIRED, if the client is not authenticating with the authorization server. Basically, confidential clients don't need to include it but others do."

    refresh_token: Optional[str] = None
    "REQUIRED, if grant type is 'refresh_token'. The refresh token issued to the client."

    username: Optional[str] = None
    "REQUIRED, if grant type is 'password'"

    password: Optional[str] = None
    "REQUIRED, if grant type is 'password'"

    scope: Optional[str] = None
    "REQUIRED, if grant type is 'password'. The scope requested by the application"

    @root_validator(skip_on_failure=True)
    def _validate_required_based_on_grant_type(
        cls, values: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        if values["grant_type"] == "authorization_code":
            assert (
                values["code"] is not None
            ), "code is required when grant_type is 'authorization_code'"
            assert (
                values["redirect_uri"] is not None
            ), "redirect_uri is required when grant_type is 'authorization_code'"
        elif values["grant_type"] == "refresh_token":
            assert (
                values["refresh_token"] is not None
            ), "refresh_token is required when grant_type is 'refresh_token'"
        elif values["grant_type"] == "password":
            assert (
                values["username"] is not None
            ), "username is required when grant_type is 'password'"
            assert (
                values["password"] is not None
            ), "password is required when grant_type is 'password'"
            assert (
                values["scope"] is not None
            ), "scope is required when grant_type is 'password'"

        return values


class TokenSuccessResponse(OpenidBaseModel):
    """
    After receiving and validating a valid and authorized :class:`TokenRequest <TokenRequest>` from the Client, the Authorization Server returns a successful response that includes an ID Token and an Access Token
    """

    class Config:
        allow_mutation = False

    access_token: str
    "REQUIRED. The access token issued by the authorization server."

    token_type: str
    "REQUIRED. The type of the token issued Value is case insensitive. Usually this is `Bearer` which is a type that MUST be supported by all OPs."

    expires_in: Optional[int]
    'RECOMMENDED.  The lifetime in seconds of the access token. For example, the value "3600" denotes that the access token will expire in one hour from the time the response was generated. If omitted, the authorization server SHOULD provide the expiration time via other means or document the default value.'

    refresh_token: Optional[str]
    "OPTIONAL. The refresh token, which can be used to obtain new access tokens using the same authorization grant as described in `Section 6 of RFC6749 <https://www.rfc-editor.org/rfc/rfc6749#section-6>`_."

    refresh_expires_in: Optional[int]
    "OPTIONAL. The lifetime in seconds of the refresh token."

    scope: Optional[str]
    "OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED. The scope of the access token."

    id_token: str
    "ID Token value associated with the authenticated session."


class TokenErrorResponse(OpenidBaseModel):
    """
    A response that is sent by the Authorization Server if a previous :class:`.TokenRequest` could not be
    understood or handled.
    It contains additional information about the error that occurred.
    """

    class Config:
        extra = Extra.allow
        allow_mutation = False
        use_enum_values = True

    class ErrorType(enum.Enum):
        """
        Possible values for :data:`error <TokenErrorResponse.error>`
        """

        invalid_request = "invalid_request"
        "The request is missing a required parameter, includes an unsupported parameter value (other than grant type), repeats a parameter, includes multiple credentials, utilizes more than one mechanism for authenticating the client, or is otherwise malformed."

        invalid_client = "invalid_client"
        "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The authorization server MAY return an HTTP 401 (Unauthorized) status code to indicate which HTTP authentication schemes are supported. " 'If the client attempted to authenticate via the "Authorization" request header field, the authorization server MUST respond with an HTTP 401 (Unauthorized) status code and include the "WWW-Authenticate" response header field matching the authentication scheme used by the client.'

        invalid_grant = "invalid_grant"
        "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client."

        unauthorized_client = "unauthorized_client"
        "The authenticated client is not authorized to use this authorization grant type."

        unsupported_grant_type = "unsupported_grant_type"
        "The authorization grant type is not supported by the authorization server."

        invalid_scope = "invalid_scope"
        "The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the resource owner."

    error: ErrorType
    "REQUIRED. An error code"

    error_description: Optional[str]
    "OPTIONAL.  Human-readable text providing additional information, used to assist the client developer in understanding the error that occurred."

    error_uri: Optional[str]
    "OPTIONAL.  A URI identifying a human-readable web page with information about the error, used to provide the client developer with additional information about the error."


class RpInitiatedLogoutRequest(OpenidBaseModel):
    """
    Request which a Relying-Party sends to the OP to initiate a user logout
    """

    id_token_hint: Optional[str] = None
    "RECOMMENDED. ID Token previously issued by the OP to the RP passed to the Logout Endpoint as a hint about the End-User's current authenticated session with the Client. This is used as an indication of the identity of the End-User that the RP is requesting be logged out by the OP. "

    logout_hint: Optional[str] = None
    "OPTIONAL. Hint to the Authorization Server about the End-User that is logging out. The value and meaning of this parameter is left up to the OP's discretion. For instance, the value might contain an email address, phone number, username, or session identifier pertaining to the RP's session with the OP for the End-User."

    client_id: Optional[str] = None
    "OPTIONAL. Client Identifier valid at the Authorization Server. When both client_id and id_token_hint are present, the id token MUST have been issued to this client. The most common use case for this parameter is to specify the Client Identifier when post_logout_redirect_uri is used but id_token_hint is not. Another use is for symmetrically encrypted ID Tokens used as id_token_hint values that require the Client Identifier to be specified by other means, so that the ID Tokens can be decrypted by the OP. "

    post_logout_redirect_uri: Optional[str] = None
    "OPTIONAL. URI to which the RP is requesting that the End-User's User Agent be redirected after a logout has been performed. This URI SHOULD use the https scheme; however, it MAY use the http scheme, provided that the Client Type is confidential, and provided the OP allows the use of http RP URIs. The URI MAY use an alternate scheme, such as one that is intended to identify a callback into a native application. The value MUST have been previously registered with the OP, either using the post_logout_redirect_uris Registration parameter or via another mechanism. An id_token_hint is also RECOMMENDED when this parameter is included."

    state: Optional[str] = None
    "OPTIONAL. Opaque value used by the RP to maintain state between the logout request and the callback to the endpoint specified by the post_logout_redirect_uri parameter. If included in the logout request, the OP passes this value back to the RP using the state parameter when redirecting the User Agent back to the RP."

    ui_locales: Optional[List[str]] = None
    'OPTIONAL. End-User\'s preferred languages and scripts for the user interface, represented as a space-separated list of BCP47 [RFC5646] language tag values, ordered by preference. For instance, the value "fr-CA fr en" represents a preference for French as spoken in Canada, then French (without a region designation), followed by English (without a region designation). An error SHOULD NOT result if some or all of the requested locales are not supported by the OpenID Provider. '


class FrontChannelLogoutNotification(OpenidBaseModel):
    """
    A notification which the Relying-Party receives when a user logs out.

    This message is encoded as a url which is served by the Relying-Party and accessed by the user agent of the user
    when they log out at the OP.
    """

    class Config:
        allow_mutation = False

    iss: Optional[str]
    "Issuer Identifier for the OP issuing the front-channel logout request."

    sid: Optional[str]
    "Identifier for the Session."


class BackChannelLogoutNotification(OpenidBaseModel):
    """
    A notification which the Relying-Party receives from the OP when a user logs out.

    This message is sent directly by the OP to the Relying-Party without involving the user agent.
    """

    logout_token: str
    "A signed JWT containing a :class:`BackChannelLogoutToken`"


class BackChannelLogoutToken(OpenidBaseModel):
    """
    OPs send a JWT similar to an ID Token to RPs called a Logout Token to request that they log out.
    This token is sent as part of a :class:`BackChannelLogoutNotification`.

    A Logout Token MUST contain either a sub or a sid Claim, and MAY contain both.
    If a sid Claim is not present, the intent is that all sessions at the RP for the End-User identified by the iss and sub Claims be logged out.
    """

    class Events(OpenidBaseModel):
        x: Mapping[str, Any] = Field(
            alias="http://schemas.openid.net/event/backchannel-logout",
            default={},
            const=True,
        )

    iss: str
    "REQUIRED. Issuer Identifier"

    sub: Optional[str]
    "OPTIONAL. Subject Identifier (user id)"

    aud: str
    "REQUIRED. Audience(s)"

    iat: int
    "REQUIRED. Issued at time"

    jti: str
    "REQUIRED. Unique identifier for the token"

    events: Events
    "REQUIRED. Claim whose value is a JSON object containing the member name http://schemas.openid.net/event/backchannel-logout. This declares that the JWT is a Logout Token. The corresponding member value MUST be a JSON object and SHOULD be the empty JSON object {}. "

    sid: Optional[str]
    "OPTIONAL. Session ID - String identifier for a Session. This represents a Session of a User Agent or device for a logged-in End-User at an RP. Different sid values are used to identify distinct sessions at an OP. The sid value need only be unique in the context of a particular issuer. Its contents are opaque to the RP."

    def validate_extern(
        self,
        issuer: str,
        client_id: str,
        extra_trusted_audiences: List[str] = [],
        min_iat: float = 0,
        validate_unique_jti: Union[Callable[[str], None], None] = None,
        validate_iss_has_sessions: Union[Callable[[str], None], None] = None,
        validate_sub_has_sessions: Union[Callable[[str], None], None] = None,
        validate_sid_exists: Union[Callable[[str], None], None] = None,
    ) -> None:
        """
        Validate this ID-Token with external data for consistency

        :param issuer: The issuer that this token is supposed to originate from.
            Should usually be :data:`ProviderMetadata.issuer`
        :param client_id: The client id of this client
        :param extra_trusted_audiences: Which token audiences (client ids) to consider trusted beside this client's own client_id.
            This is usually an empty list but if the token is intended to be used by more than one client, all of these need to be listed in the tokens :data:`IdToken.aud` field, and they all need to be known and trusted by this client.
        :param min_iat: Minimum value that the tokens :data:`IdToken.iat` claim must be.
            This value is a posix timestamp and defaults to 0 which allows arbitrarily old `iat` dates.
        :param validate_unique_jti: A callable which verifies that the given :data:`BackChannelLogoutToken.jti` value has not been previsouly used.
            If this parameter is not given, validation is skipped.
        :param validate_iss_has_sessions: A callable which verifies that the logout tokens :data:`iss <BackChannelLogoutToken.iss>` (issuer) has open sessions on this app.
            If this parameter is not given, validation is skipped.
        :param validate_sub_has_sessions: A callable which verifies that the logout tokens :data:`sub <BackChannelLogoutToken.sub>` (subject) has one or more open session on this app.
            If this parameter is not given or the token contains no `sub` claim, validation is skipped.
        :param validate_sid_exists:  A callable which verifies that the logout tokens :data:`sid <BackChannelLogoutToken.sid>` (session id) is a currently open session on this app.
            If this parameter is not given or the token contains no `sid` claim, validation is skipped.

        :raises ValidationError: if the validation fails
        """
        # this method implements https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation

        # 4. validate iss
        validate_that(
            self.iss == issuer, "Logout-Token was issued from unexpected issuer"
        )

        # 4. validate audience
        if isinstance(self.aud, str):
            validate_that(
                self.aud == client_id,
                "Logout-Token's audience does not contain own client_id",
            )
        elif isinstance(self.aud, list):
            validate_that(
                client_id in self.aud,
                "Logout-Token's audience does not contain own client_id",
            )
            validate_that(
                all(i in extra_trusted_audiences for i in self.aud),
                "Not all of the Logout-Token's audience are trusted",
            )

        # 4. validate iat
        validate_that(
            self.iat >= min_iat, "The Logout-Token was issued too far in the past"
        )

        # 5. validate that one of sub or sid (or both) is present
        validate_that(
            not (self.sub is None and self.sid is None),
            "Neither sub nor sid claim is present in Backchannel-Logout-Token",
        )

        # 8. optionally validate jti
        if validate_unique_jti is not None:
            validate_unique_jti(self.jti)

        # 9.optionally validate iss
        if validate_iss_has_sessions is not None:
            validate_iss_has_sessions(self.iss)

        # 10. optionally validate sub
        if validate_sub_has_sessions is not None and self.sub is not None:
            validate_sub_has_sessions(self.sub)

        # 11. optionally validate sid
        if validate_sid_exists is not None and self.sid is not None:
            validate_sid_exists(self.sid)


class TokenIntrospectionRequest(OpenidBaseModel):
    """
    The protected resource server calls the introspection endpoint using an HTTP POST request with this request formatted as `application/x-www-form-urlencoded` data.

    The protected resource sends a parameter representing the token along with optional parameters representing additional context that is known by the protected resource to aid the authorization server in its response.

    The introspection endpoint MAY accept other OPTIONAL parameters to provide further context to the query.
    For instance, an authorization server may desire to know the IP address of the client accessing the protected resource to determine if the correct client is likely to be presenting the token.
    The definition of this or any other parameters are outside the scope of the specification, to be defined by service documentation.
    If the authorization server is unable to determine the state of the token without additional information, it SHOULD return an :class:`introspection response <TokenIntrospectionResponse>` indicating the token is not active.
    """

    class Config:
        extra = Extra.allow

    token: str
    "REQUIRED. The string value of the token. The may be a refresh_token or access_token which must be understood by supporting OPs but may also be others."

    token_type_hint: Optional[str]
    'OPTIONAL. A hint about the type of the token submitted for introspection. The protected resource MAY pass this parameter to help the authorization server optimize the token lookup. If the server is unable to locate the token using the given hint, it MUST extend its search across all of its supported token types. An OP MAY ignore this parameter, particularly if it is able to detect the token type automatically. Values for this field are defined in the "OAuth Token Type Hints" registry defined in OAuth Token Revocation `RFC7009: OAuth 2.0 Token Revocation <https://www.rfc-editor.org/rfc/rfc7009>`_.'


class TokenIntrospectionSuccessResponse(OpenidBaseModel):
    """
    A message with which an OP responds to :class:`TokenIntrospectionRequest`\s and which contains information about the provided token.

    Specific implementations MAY extend this structure with their own service-specific response names as top-level members of this object.

    The response MAY be cached by the protected resource to improve performance and reduce load on the introspection endpoint, but at the cost of liveness of the information used by the protected resource to make authorization decisions.
    """

    class Config:
        extra = Extra.allow

    active: bool
    'REQUIRED. Boolean indicator of whether or not the presented token is currently active. The specifics of a token\'s "active" state will vary depending on the implementation of the authorization server and the information it keeps about its tokens, but a `true` value return for the "active" property will generally indicate that a given **token has been issued by this authorization server**, **has not been revoked by the resource owner**, and **is within its given time window of validity** (e.g., after its issuance time and before its expiration time).'

    scope: Optional[str]
    "OPTIONAL. A string containing a space-separated list of scopes associated with this token."

    client_id: Optional[str]
    "OPTIONAL. Client identifier for the client that requested this token."

    username: Optional[str]
    "OPTIONAL. Human-readable identifier for the resource owner who authorized this token."

    token_type: Optional[str]
    "OPTIONAL.  Type of the token as defined in `Section 5.1 of OAuth2.0 [RFC6749] <https://www.rfc-editor.org/rfc/rfc6749#section-5.1>`_."

    exp: Optional[int]
    "OPTIONAL. Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token will expire."

    iat: Optional[int]
    "OPTIONAL. Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token was originally issued."

    nbf: Optional[int]
    "OPTIONAL. Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token is not to be used before."

    sub: Optional[str]
    "OPTIONAL. Subject of the token. Usually a machine-readable identifier of the resource owner who authorized this token (user id)."

    aud: Optional[str]
    "OPTIONAL. Service-specific string identifier or list of string identifiers representing the intended audience for this token."

    iss: Optional[str]
    "OPTIONAL. String representing the issuer (OP) of this token."

    jti: Optional[str]
    "OPTIONAL. String identifier for the token."


class TokenIntrospectionErrorResponse(TokenErrorResponse):
    """
    An error with which an OP responds to :class:`TokenIntrospectionRequest`\s and which describes why the request could not be fulfilled.
    """

    pass
