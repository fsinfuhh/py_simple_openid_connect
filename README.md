# Simple OpenID

Simple and opinionated OpenID-Connect relying party and resource server implementation

[![Documentation Status](https://readthedocs.org/projects/simple-openid-connect/badge/?version=latest)](https://simple-openid-connect.readthedocs.io/en/latest/?badge=latest)

## Quick Links

- [PyPi Page](https://pypi.org/project/simple_openid_connect/)
- [Documentation](https://simple-openid-connect.readthedocs.io/en/stable/)
- [GitHub Repository](https://github.com/fsinfuhh/py_simple_openid_connect)


## Development philosophy

- Keep the API as simple as possible

  No `**kwargs` parameters, no function arguments called `request_args`, `http_args` or `something_else_args`

- Fully typed API

  Python has type hints now, let's use them.

- Support commonly used OpenID features and flows

  Commonly used flows will be supported but obscure and legacy or experimental mechanisms not so much.

- Be *just* an OpenID library

  Tell the user about function requirements clearly but don't try any fancy internal persistence or caching mechanisms that will only fail in different usage scenarios.
  Instead, abstract the underlying OpenID protocol into usable, clear functions but nothing more.


## Framework Integrations

| Name                                                            | Package Feature       | Integration Docs                                                                                   | Supported Versions     |
|-----------------------------------------------------------------|-----------------------|----------------------------------------------------------------------------------------------------|------------------------|
| [Django](https://www.djangoproject.com/)                        | `django`              | [Integration Docs](https://simple-openid-connect.readthedocs.io/en/stable/django-integration.html) | `v3.2`, `v4.0`, `v4.1` |
| [Django-Rest-Framework](https://www.django-rest-framework.org/) | `djangorestframework` | [Integration Docs](https://simple-openid-connect.readthedocs.io/en/stable/drf-integration.html)    | `v3.13`, `v3.14`       |



## Supported OpenID Specs

The list of [OpenID specifications](https://openid.net/developers/specs/) can be found on the official website.

- (✔️) Partial [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)

  Only the following flows and features are implemented:
  - ✔️ Authorization Code Flow
  - ✔️ Direct Access Grant (or *Resource Owner Password Credentials Grant*)
  - ✔️ `client_secret_basic` client authentication
  - ✔️ `none` client authentication
  - ✔️ Query String serialization and parsing
  - ✔️ ID Token handling (parsing + validation)
  - ✔️ Using refresh tokens
  - ✔️ Retrieving userinfo
  - ❌ Implicit Flow
  - ❌ Hybrid Flow
  - ❌ Handling third party initiated login
  - ❌ Passing requests as JWTs (neither by value nor by reference)
  - ❌ Self-Issued OpenID Provider
  - ❌ `client_secret_post` client authentication
  - ❌ `client_secret_jwt` client authentication
  - ❌ `private_key_jwt` client authentication

- (✔️) Partial [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html).
  *Provider Configuration Discovery* is implemented, *Provider Issuer Discovery* is not.

  This means that a known issuer can be introspected for its supported algorithms, endpoint locations and so forth but discovering that issuer in the first hand is not possible.

- ✔️ Full [OAuth 2.0 Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)

  Only the following features are implemented and supported:
  - ✔️  Response modes (fragment based response parsing)
  - ✔️  Multiple-Valued Response Types <br>
    No explicit support, but it is possible to supply one of the multivalued `response_type` values to an authentication request and then parse multiple responses from the resulting response.

- ✔️ Full [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)

- ✔️ Full [OpenID Connect Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html)

- ✔️ Full [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)

- ✔️ Full [OAuth 2.0 Token Introspection](https://www.rfc-editor.org/rfc/rfc7662)
