Notes about ``nonce`` and ``state``
===================================

During the authentication initiation (e.g. via :func:`start_authentication() <simple_openid_connect.flows.authorization_code_flow.start_authentication>`), it is possible to specify a ``nonce`` as well as ``state`` parameter.
These two serve different purposes and are often not understoot.
This document serves as a guide on when and how to use these parameters to protect users.


Using ``state``
---------------

The ``state`` parameter protects against a CSRF attack which forces a user-agent to log into a new, attacker-provided session.
Protecting against this works by only allowing authentication to succeed when the user-agent is currently in the process (or *state*) of logging a user in.

CSRF attack against the relying party
#####################################

The CSRF (Cross-Site-Request-Forgery) attack in question is described in `RFC 6749, Section 10.12. <https://www.rfc-editor.org/rfc/rfc6749#section-10.12>`_ and works like this:

#. An attacker (**Eve**) initiates login to the relying party, receiving a redirect to the OIDC provider.
#. **Eve** authenticates at the OIDC provider, receiving a redirect back to the relying party.
   The redirect URI includes a *code* which binds to the authentication of **Eve** and enables the relying party to retrieve access tokens associated to the authenticated user (which is Eve).
#. **Eve** executes a CSRF attack against a user (**Alice**) via some here unspecified mechanism, directing their user-agent to the redirect URI.
#. The relying party exchanges the *code* for access tokens and binds **Alice's** user-agent to **Eve's** session.

This CSRF attack against the relying partie's redirection URI allows an attacker to inject its own authorization code or access token, which can result in the client using an access token associated with the attacker's protected resources rather than the victim's (e.g., save the victim's bank account information to a protected resource controlled by the attacker).

Protection using ``state``
##########################

A relying party can protect against this kind of CSRF attack by only allowing a code-for-token exchange if the users user-agent is currently in a state where authantication is performed.
In other words, the redirect URI endpoint must only succeed if the user-agent has visited the login initiation URI before and started an authentication flow.
It should also bind the authentication flow to the user-agent that initiated it.

One way to achieve this is by generating an opaque value which we now call ``state`` during login initiation, associating it to the user agent (e.g. by saving it in a session) and, because it is passed through to the redirect URI, validating it in the redirect URI's handler.


Using ``nonce``
---------------

The ``nonce`` parameter protects against replay attacks in which an attacker tricks the relying party into accepting captured acces tokens.
Relying parties can use a nonce to associate an authentication procedure with resulting the resulting access token and detect if an access token of a different session is to be cheated in.

The parameter is documented in the `OpenID Connect Core Specification, Section 15.5.2 <https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes>`_.

Replay attack against the relying party
#######################################

The scenario for id token replays is the following:

#. An attacker (**Eve**) captures an ID token identifying a user (e.g. **Alice**).
#. Through a here undescribed mechanism, **Eve** hijacks the connection between the relying party and the OIDC provider.
   When the relying party tries to retrieve an ID token from the OIDC provider, **Eve** inserts her captured token (the one belonging to **Alice**) into the response.
#. Since the captured token is properly signed by the OIDC provider, the relying party successfully verifies it and associates the authenticating session with Alice's identity.

Proection using ``nonce``
#########################

The nonce mechanism is used to associate an authentication procedure with the resulting ID tokens.
The relying party can specify a chosen nonce value during authentication initiation which is passed through unmodified into the ID token.
During ID token verification, the relying party is required to validate that the contained nonce has an expected value.
