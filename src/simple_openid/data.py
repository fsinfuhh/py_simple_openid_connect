"""
Datatypes and models for various OpenID messages
"""
import logging
from typing import List, Optional, Union

from pydantic import BaseModel, Extra, HttpUrl

from simple_openid.base_data import OpenidBaseModel, OpenidMessage

logger = logging.getLogger(__name__)


class ProviderMetadata(BaseModel):
    """
    OpenID Providers have metadata describing their configuration

    Additional OpenID Provider Metadata parameters MAY also be used. Some are defined by other specifications, such as `OpenID Connect Session Management 1.0 <https://openid.net/specs/openid-connect-session-1_0.html>`_.

    See `OpenID Connect Spec: Provider Metadata <https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata>`_
    """

    class Config:
        extra = Extra.allow
        allow_mutation = False

    issuer: HttpUrl
    "REQUIRED. URL using the https scheme with no query or fragment component that the OP asserts as its Issuer Identifier This MUST be identical to the iss Claim value in ID Tokens issued from this Issuer."

    authorization_endpoint: HttpUrl
    "REQUIRED. URL of the OP's OAuth 2.0 Authorization Endpoint."

    token_endpoint: Optional[HttpUrl]
    "URL of the OP's OAuth 2.0 Token Endpoint. This is REQUIRED unless only the Implicit Flow is used."

    userinfo_endpoint: Optional[HttpUrl]
    "RECOMMENDED. URL of the OP's UserInfo Endpoint. This URL MUST use the https scheme and MAY contain port, path, and query parameter components."

    jwks_uri: HttpUrl
    "REQUIRED. URL of the OP's JSON Web Key Set document This contains the signing key(s) the RP uses to validate signatures from the OP The JWK Set MAY also contain the Server's encryption key(s), which are used by RPs to encrypt requests to the Server When both signing and encryption keys are made available, a use (Key Use) parameter value is REQUIRED for all keys in the referenced JWK Set to indicate each key's intended usage Although some algorithms allow the same key to be used for both signatures and encryption, doing so is NOT RECOMMENDED, as it is less secure The JWK x5c parameter MAY be used to provide X.509 representations of keys provided When used, the bare key values MUST still be present and MUST match those in the certificate. "

    registration_endpoint: Optional[HttpUrl]
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

    token_endpoint_auth_methods_supported: Optional[List[str]] = ["client_secret_basic"]
    "OPTIONAL. JSON array containing a list of Client Authentication methods supported by this Token Endpoint The options are client_secret_post, client_secret_basic, client_secret_jwt, and private_key_jwt, as described in Section 9 of OpenID Connect Core 1.0 Other authentication methods MAY be defined by extensions. If omitted, the default is client_secret_basic -- the HTTP Basic Authentication Scheme specified in Section 2.3.1 of OAuth 2.0 [RFC6749]."

    token_endpoint_auth_signing_alg_values_supported: Optional[List[str]]
    "OPTIONAL. JSON array containing a list of the JWS signing algorithms (alg values) supported by the Token Endpoint for the signature on the JWT used to authenticate the Client at the Token Endpoint for the private_key_jwt and client_secret_jwt authentication methods Servers SHOULD support RS256 The value none MUST NOT be used."

    display_values_supported: Optional[List[str]]
    "OPTIONAL. JSON array containing a list of the display parameter values that the OpenID Provider supports These values are described in Section 3.1.2.1 of OpenID Connect Core 1.0."

    claim_types_supported: Optional[List[str]]
    "OPTIONAL. JSON array containing a list of the Claim Types that the OpenID Provider supports These Claim Types are described in Section 5.6 of OpenID Connect Core 1.0 Values defined by this specification are normal, aggregated, and distributed If omitted, the implementation supports only normal Claims."

    claims_supported: Optional[List[str]]
    "RECOMMENDED. JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be able to supply values for Note that for privacy or other reasons, this might not be an exhaustive list."

    service_documentation: Optional[HttpUrl]
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

    op_policy_uri: Optional[HttpUrl]
    "OPTIONAL. URL that the OpenID Provider provides to the person registering the Client to read about the OP's requirements on how the Relying Party can use the data provided by the OP The registration process SHOULD display this URL to the person registering the Client if it is given."

    op_tos_uri: Optional[HttpUrl]
    "OPTIONAL. URL that the OpenID Provider provides to the person registering the Client to read about OpenID Provider's terms of service The registration process SHOULD display this URL to the person registering the Client if it is given. "


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

    iss: HttpUrl
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
    "OPTIONAL. Authentication Context Class Reference String specifying an Authentication Context Class Reference value that identifies the Authentication Context Class that the authentication performed satisfied. " 'The value "0" indicates the End-User authentication did not meet the requirements of ISO/IEC 29115 [ISO29115] level 1. ' 'Authentication using a long-lived browser cookie, for instance, is one example where the use of "level 0" is appropriate. ' "Authentications with level 0 SHOULD NOT be used to authorize access to any resource of any monetary value (This corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] nist_auth_level 0.)  An absolute URI or an RFC 6711 [RFC6711] registered name SHOULD be used as the acr value; registered names MUST NOT be used with a different meaning than that which is registered Parties using this claim will need to agree upon the meanings of the values used, which may be context-specific The acr value is a case sensitive string."

    amr: Optional[List[str]]
    "OPTIONAL. Authentication Methods References JSON array of strings that are identifiers for authentication methods used in the authentication For instance, values might indicate that both password and OTP authentication methods were used The definition of particular values to be used in the amr Claim is beyond the scope of this specification Parties using this claim will need to agree upon the meanings of the values used, which may be context-specific The amr value is an array of case sensitive strings."

    azp: Optional[str]
    "OPTIONAL. Authorized party - the party to which the ID Token was issued If present, it MUST contain the OAuth 2.0 Client ID of this party This Claim is only needed when the ID Token has a single audience value and that audience is different than the authorized party It MAY be included even when the authorized party is the same as the sole audience The azp value is a case sensitive string containing a StringOrURI value."


class UserinfoRequest(OpenidMessage):
    pass


class UserinfoSuccessResponse(OpenidMessage):
    class Config:
        extra = Extra.allow
        allow_mutation = False

    sub: str


class UserinfoErrorResponse(OpenidMessage):
    class Config:
        allow_mutation = False

    error: str
    error_description: Optional[str]
