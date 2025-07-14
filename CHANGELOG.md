# Changelog

## V2.3.0

### Notable features

- **core**: `IdToken.validate_extern()` now supports a `expect_self_azp` parameter.
  This parameter allows a user to specify whether the `azp` claim of an IdToken should be the same as the users own client-id.
  This is the case if the token was issued to that client but can differ if a token with multiple audiences was issued and the users client-id is just one of them.

- **django integration**: The django login views now impose a tighter requirement on tokens `iat` claim to ensure that tokens are only accapted if they get issued after a login process has been started by an end-user.

### Bug-Fixes

- **core**: Fix a validation bug for `IdToken.validate_extern()` when multiple `aud` claims were present on the token.
  Previously, the users own client-id was not considered as valid during this validation which would always lead to failures.

- **SECURITY**, **core**: Fix `JwTAccessToken` compliance with [RFC 9068 (JWT for OAuth 2.0)](https://www.rfc-editor.org/rfc/rfc9068#section-2.2-2.6) in making required claims also required in our implementation. This is also according to [RFC 8725 (JWT Best Practices)](https://www.rfc-editor.org/rfc/rfc8725#section-3.9) which dictates that a tokens `aud` claim must be used if the token is intended for multiple principles. In the context of OpenID-Connect, this is always a possibility.

  The security impact of the previous implementation is that a non-compliant identity providers tokens (ones without an `aud` claim) could be sent to applications using *simple_openid_connect* even though they were issued to a different client.

- **django integration**: Fix an error in django-admin view where it would fail to render on custom user models that didn't include a `username` and `email` field.

## v2.2.0

### Notable features

- **SECURITY** (integrations) Fix a behavior of the `TokenVerificationMiddleware` which would previously always pass a request forward in the pipeline and only validate a sessions associated openid tokens after a response had been generated.
  This behavior should not lead to exploitable applications since a session would have to be properly authenticated some time beforehand, but it would allow one single request on an already expired session.

- (integrations) Add a django-admin site to display federated openid accounts and information about their sessions.

- (integrations) Caching has been introduced to the django integration to skip mapping access tokens to internal user accounts if the token has recently already been handled.

- (integrations) A django-management command has been added to allow clearing the database of expired openid sessions.

- (docs) Documentation about the django integration has been enhanced with additional information about how the integration works internally and how a developer can use it.

## v2.1.0

### Notable features

- (integrations) Highlights of this release are the newly supported integration versions. We now officially include support for *Django v5.2* and *django-rest-framework v3.16* . Support for *Django v5.0* has been removed since it is a deprecated django version since 02. Apr. 2025.

- (integrations) The django integration now also ships with a proper error view which is displayed to an end-user whenever the OpenID authentication process fails. This view aims to explain in simple terms what went wrong and always offers the user a choice of action by displaying a button to try again. Technical information about the error can be revealed on-demand to allow developers to gain important insights.

## v2.0.0

This release is mainly a maintenance release.
It brings some fixes, some minor additions, and mainly adds support for newer python and library versions.

Thanks to Tim Hallman who contributed to this release.

### Breaking Changes

- The function signature of `JwtAccessToken.validate_extern()` changed. It now requires a `client_id` parameter so that a tokens `aud` claim can be validated as the OpenID specification requires.

### Notable Features

- (generic) Fix some errors relating to how state and nonce parameters were handled in the django integration.
- (dev) Signal full python typehint support of this library by adding a `py.typed` file.
  Type-Checking tools can now detect and assume that every function of this library has correct type hints.
- (dev) Add and ship a helper script that can be used during development for OpenID token introspection and debugging.
- (misc) Update supported python and library versions to current releases.

## v1.1.0

### Notable Features

- (general) Added support for `nonce` and `state` parameters during authorization code flow
- (general) Added support for PKCE challenge and verifier generation
- (django) Added usage of `nonce` and `state` in the django integrations auth flow

Thanks to new contributors Tim Hallman and Stéphane Brunner for their help.

## v1.0.0

Initial Release of this library onto an unsuspecting world :)
