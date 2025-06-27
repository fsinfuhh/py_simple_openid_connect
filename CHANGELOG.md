# Changelog

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
