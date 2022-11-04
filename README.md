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
