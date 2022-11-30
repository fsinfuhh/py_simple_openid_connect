Usage
=====

This page describes how, in general, the library can be used to perform openid based authentication.

Library layout
--------------

This library can be categorized in two styles of usage.

The first of these is very *functional* in which all functionality is implemented as pure functions without any side effects.
This means that the implementing functions receive all required parameters as input and output a certain result without e.g. storing any by products in memory or associating requests with one another.
An example of this style is the :func:`introspect_token <simple_openid_connect.token_introspection.introspect_token>` function.

The other style is implemented by the :class:`OpenidClient <simple_openid_connect.client.OpenidClient>` which serves as
a higher level abstraction.
The client is still rather simple and does not persist any state internally except static information like the provider configuration, cryptographic keys and client credentials.
Notice how the same functionality as before (token introspection) is simpler to call :meth:`OpenidClient.introspect_token <simple_openid_connect.client.OpenidClient.introspect_token>`.


OpenID Protocol Overview
------------------------

The OpenID Connect protocol, in abstract, follows the following steps.

1. The Relying Party (RP / Client) sends a request to the OpenID Provider (OP).
2. The OP authenticates the End-User and obtains authorization.
3. The OP responds with an ID Token and usually an Access Token.
4. The RP can send a request with the Access Token to the UserInfo Endpoint.
5. The UserInfo Endpoint returns Claims about the End-User.

These steps are illustrated in the following diagram::

    +--------+                                   +--------+
    |        |                                   |        |
    |        |---------(1) AuthN Request-------->|        |
    |        |                                   |        |
    |        |  +--------+                       |        |
    |        |  |        |                       |        |
    |        |  |  End-  |<--(2) AuthN & AuthZ-->|        |
    |        |  |  User  |                       |        |
    |   RP   |  |        |                       |   OP   |
    |        |  +--------+                       |        |
    |        |                                   |        |
    |        |<--------(3) AuthN Response--------|        |
    |        |                                   |        |
    |        |---------(4) UserInfo Request----->|        |
    |        |                                   |        |
    |        |<--------(5) UserInfo Response-----|        |
    |        |                                   |        |
    +--------+                                   +--------+



Simple functional example
-------------------------

This example authenticates a user using the *authorization code flow*.
It should be interpreted as pseudocode without any specific web or application framework in mind::

    def on_login():
        # this method should be called when the user wants to log in
        # it returns an HTTP redirect to the Openid provider
        url = authorization_code_flow.start_authentication(
            "https://provider.example.com/openid/auth",
            "openid",
            "client-id",
            "https://myapp.example.com/login-callback",
        )
        return HttpRedirect(to=url)

    def on_login_callback(current_url):
        # this should be automatically called when the user is redirected back from the Openid provider
        token_response = authorization_code_flow.handle_authentication_result(
            current_url,
            "https://provider.example.com/openid/token",
            ClientSecretBasicAuth("client-id", "client-secret")
        )
        # token_response now contains access and id tokens
        ...



Simple client example
---------------------

This example utilizes the :class:`OpenidClient <simple_openid_connect.client.OpenidClient>` to authenticate a user using the *authorization code flow*.
It should be interpreted as pseudocode without any specific web or application framework in mind::

    client = OpenidClient.from_issuer_url(
        url="https://provider.example.com/openid",
        authentication_redirect_uri="https://myapp.example.com/login-callback",
        client_id="client-id",
        client_secret="client-secret",
    )

    def on_login():
        # this method should be called when the user wants to log in
        # it returns an HTTP redirect to the Openid provider
        return HttpRedirect(to=client.authorization_code_flow.start_authentication())

    def on_login_callback(current_url):
        token_response = client.authorization_code_flow.handle_authentication_result(current_url)
        # token_response now contains access and id tokens
        ...
