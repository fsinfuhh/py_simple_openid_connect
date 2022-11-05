import enum
from typing import List, Optional

from pydantic import Extra, Field

from simple_openid.data import OpenidMessage


class AuthenticationRequest(OpenidMessage):
    """
    An Authentication Request requests that the End-User be authenticated by the Authorization Server.
    """

    class Config:
        extra = Extra.allow

    scope: str
    "REQUIRED. OpenID Connect authentication requests MUST contain the openid scope value." "Multiple scopes are encoded space separated. " "If the openid scope value is not present, the behavior is entirely unspecified. " "Other scope values MAY be present."

    response_type: str = Field(default="code", const=True)
    "REQUIRED. OAuth 2.0 Response Type value that determines the authorization processing flow to be used, including what parameters are returned from the endpoints used. " "When using the Authorization Code Flow, this value is code. "

    client_id: str
    "REQUIRED. OAuth 2.0 Client Identifier valid at the Authorization Server."

    redirect_uri: str
    "REQUIRED. Redirection URI to which the response will be sent. " "This URI MUST exactly match one of the Redirection URI values for the Client pre-registered at the OpenID Provider. " "When using this flow, the Redirection URI SHOULD use the https scheme; however, it MAY use the http scheme, provided that the Client Type is confidential, as defined in Section 2.1 of OAuth 2.0, and provided the OP allows the use of http Redirection URIs in this case. " "The Redirection URI MAY use an alternate scheme, such as one that is intended to identify a callback into a native application."

    state: Optional[str]
    "RECOMMENDED. Opaque value used to maintain state between the request and the callback. " "Typically, Cross-Site Request Forgery (CSRF, XSRF) mitigation is done by cryptographically binding the value of this parameter with a browser cookie."

    response_mode: Optional[str]
    "OPTIONAL. Informs the Authorization Server of the mechanism to be used for returning parameters from the Authorization Endpoint. This use of this parameter is NOT RECOMMENDED when the Response Mode that would be requested is the default mode specified for the Response Type."

    nonce: Optional[str]
    "OPTIONAL. String value used to associate a Client session with an ID Token, and to mitigate replay attacks. " "The value is passed through unmodified from the Authentication Request to the ID Token. " "Sufficient entropy MUST be present in the nonce values used to prevent attackers from guessing values."

    display: Optional[List[str]]
    'OPTIONAL. Space delimited, case sensitive list of ASCII string values that specifies whether the Authorization Server prompts the End-User for reauthentication and consent. The defined values are: "page", "popup", "touch" and "wap"'

    prompt: Optional[List[str]]
    'OPTIONAL. Space delimited, case sensitive list of ASCII string values that specifies whether the Authorization Server prompts the End-User for reauthentication and consent. The defined values are: "none", "login", "consent" and "select_account".'

    max_age: Optional[int]
    "OPTIONAL. Maximum Authentication Age. " "Specifies the allowable elapsed time in seconds since the last time the End-User was actively authenticated by the OP. " "If the elapsed time is greater than this value, the OP MUST attempt to actively re-authenticate the End-User. " "When max_age is used, the ID Token returned MUST include an auth_time Claim Value."

    ui_locales: Optional[List[str]]
    "OPTIONAL. End-User's preferred languages and scripts for the user interface, represented as a space-separated list of BCP47 [RFC5646] language tag values, ordered by preference. " 'For instance, the value "fr-CA fr en" represents a preference for French as spoken in Canada, then French (without a region designation), followed by English (without a region designation). ' "An error SHOULD NOT result if some or all of the requested locales are not supported by the OpenID Provider."

    id_token_hint: Optional[str]
    "OPTIONAL. ID Token previously issued by the Authorization Server being passed as a hint about the End-User's current or past authenticated session with the Client. " "If the End-User identified by the ID Token is logged in or is logged in by the request, then the Authorization Server returns a positive response; otherwise, it SHOULD return an error, such as login_required. " "When possible, an id_token_hint SHOULD be present when prompt=none is used and an invalid_request error MAY be returned if it is not; however, the server SHOULD respond successfully when possible, even if it is not present. " "The Authorization Server need not be listed as an audience of the ID Token when it is used as an id_token_hint value. "

    login_hint: Optional[str]
    "OPTIONAL. Hint to the Authorization Server about the login identifier the End-User might use to log in (if necessary). " "This hint can be used by an RP if it first asks the End-User for their e-mail address (or other identifier) and then wants to pass that value as a hint to the discovered authorization service. " "It is RECOMMENDED that the hint value match the value used for discovery (which is not supported by this library). " "This value MAY also be a phone number in the format specified for the `phone_number` Claim. " "The use of this parameter is left to the OP's discretion."

    acr_values: Optional[List[str]]
    "OPTIONAL. Requested Authentication Context Class Reference values. " "Space-separated string that specifies the acr values that the Authorization Server is being requested to use for processing this Authentication Request, with the values appearing in order of preference. " "The Authentication Context Class satisfied by the authentication performed is returned as the acr Claim Value, as specified in Section 2. " "The acr Claim is requested as a Voluntary Claim by this parameter."


class AuthenticationSuccessResponse(OpenidMessage):
    """
    A response that is sent by the Authorization Server if a previous :class:`.AuthenticationRequest` could successfully
    be parsed and handled.

    When using the Authorization Code Flow (this flow), the Authorization Response MUST return the parameters defined by adding them as query parameters to the redirect_uri specified in the Authorization Request using the application/x-www-form-urlencoded format, unless a different Response Mode was specified.
    """

    class Config:
        allow_mutation = False

    code: str
    "REQUIRED. The authorization code generated by the authorization server. " "The authorization code MUST expire shortly after it is issued to mitigate the risk of leaks. " "A maximum authorization code lifetime of 10 minutes is RECOMMENDED. " "The client MUST NOT use the authorization code more than once. " "If an authorization code is used more than once, the authorization server MUST deny the request and SHOULD revoke (when possible) all tokens previously issued based on that authorization code. " "The authorization code is bound to the client identifier and redirect URI."

    state: Optional[str]
    "REQUIRED if the `state` parameter was present in the client authorization request. " "The exact value received from the client."


class AuthenticationErrorResponse(OpenidMessage):
    """
    A response that is sent by the Authorization Server if a previous :class:`.AuthenticationRequest` could not be
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
        Possible values for :data:`error <AuthenticationErrorResponse.error>`
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
        "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. " "(This error code is needed because a 500 Internal Server Error HTTP status code cannot be returned to the client via an HTTP redirect.)"

        temporarily_unavailable = "temporarily_unavailable"
        "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server. " "(This error code is needed because a 503 Service Unavailable HTTP status code cannot be returned to the client via an HTTP redirect.)"

        interaction_required = "interaction_required"
        "The Authorization Server requires End-User interaction of some form to proceed. " "This error MAY be returned when the prompt parameter value in the Authentication Request is none, but the Authentication Request cannot be completed without displaying a user interface for End-User interaction."

        login_required = "login_required"
        "The Authorization Server requires End-User authentication. " "This error MAY be returned when the prompt parameter value in the Authentication Request is none, but the Authentication Request cannot be completed without displaying a user interface for End-User authentication."

        account_selection_required = "account_selection_required"
        "The End-User is REQUIRED to select a session at the Authorization Server. " "The End-User MAY be authenticated at the Authorization Server with different associated accounts, but the End-User did not select a session. " "This error MAY be returned when the prompt parameter value in the Authentication Request is none, but the Authentication Request cannot be completed without displaying a user interface to prompt for a session to use."

        consent_required = "consent_required"
        "The Authorization Server requires End-User consent. " "This error MAY be returned when the prompt parameter value in the Authentication Request is none, but the Authentication Request cannot be completed without displaying a user interface for End-User consent."

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
    "REQUIRED if a `state` parameter was present in the client authorization request. " "The exact value received from the client."


class TokenRequest(OpenidMessage):
    """
    A Client makes a Token Request by presenting its Authorization Grant (in the form of an Authorization Code) to the Token Endpoint.
    If the Client is a Confidential Client, then it MUST authenticate to the Token Endpoint using the authentication method registered for its client_id.

    This request MUST be sent to the token endpoint using POST with "application/x-www-form-urlencoded" body.
    """

    class Config:
        extra = Extra.allow

    grant_type: str = Field(default="authorization_code", const=True)
    'REQUIRED. Value MUST be set to "authorization_code".'

    code: str
    "REQUIRED. The authorization code received from the authorization server."

    redirect_uri: str
    "REQUIRED, must be identical to the value that was included in the :data:`AuthenticationRequest <AuthenticationRequest.redirect_uri>`."

    client_id: Optional[str]
    "REQUIRED, if the client is not authenticating with the authorization server." "Basically, confidential clients don't need to include it but others do."


class TokenSuccessResponse(OpenidMessage):
    """
    After receiving and validating a valid and authorized :class:`TokenRequest <TokenRequest>` from the Client, the Authorization Server returns a successful response that includes an ID Token and an Access Token.
    (The response uses the `application/json` media type.)
    """

    # TODO Implement ID Token validation
    # https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation

    class Config:
        allow_mutation = False

    access_token: str
    "REQUIRED. The access token issued by the authorization server."

    token_type: str
    "REQUIRED. The type of the token issued. " "Value is case insensitive." "Usually this is `Bearer` which is a type that MUST be supported by all OPs."

    expires_in: Optional[int]
    "RECOMMENDED.  The lifetime in seconds of the access token. " 'For example, the value "3600" denotes that the access token will expire in one hour from the time the response was generated. ' "If omitted, the authorization server SHOULD provide the expiration time via other means or document the default value."

    refresh_token: Optional[str]
    "OPTIONAL. The refresh token, which can be used to obtain new access tokens using the same authorization grant as described in `Section 6 of RFC6749 <https://www.rfc-editor.org/rfc/rfc6749#section-6>`_."

    scope: Optional[str]
    "OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED. " "The scope of the access token."

    id_token: str
    "ID Token value associated with the authenticated session."


class TokenErrorResponse(OpenidMessage):
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
        "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). " "The authorization server MAY return an HTTP 401 (Unauthorized) status code to indicate which HTTP authentication schemes are supported. " 'If the client attempted to authenticate via the "Authorization" request header field, the authorization server MUST respond with an HTTP 401 (Unauthorized) status code and include the "WWW-Authenticate" response header field matching the authentication scheme used by the client.'

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
