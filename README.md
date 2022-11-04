# Simple OpenID

> Simple and opinionated OpenID-Connect relying party (client) implementation


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


## Supported OpenID Specs

The list of [OpenID specifications](https://openid.net/developers/specs/) can be found on the official website.

- (✔️) Partial [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html).
  *Provider Configuration Discovery* is implemented, *Provider Issuer Discovery* is not.

  This means that a known issuer can be introspected for its supported algorithms, endpoint locations and so forth but discovering that issuer in the first hand is not possible.
