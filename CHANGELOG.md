# Changelog

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
