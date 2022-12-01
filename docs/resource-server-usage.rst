Resource Server Usage
*********************

If your app is not the one where a user is authenticated via Openid but instead one that accepts access tokens from
authenticated user (e.g. an API server) you can still use this library.

Access token validation is usually very simply and consists of asking the Openid provider if a given token is valid.
This process is called token introspection and the provider may add more information about the token in its response
(e.g. which scopes the token has access to).


Django Setup
============

There is almost no additional setup required when this library is used for resource servers.
Settings like ``OPENID_ISSUER`` or client credentials are reused.
The only exception is that the ``OPENID_REDIRECT_URI`` setting should be explicitly set to ``None`` if your project is
exclusively acting as a resource server.


Using a client
==============

A simple way to introspect a token is using an :class:`OpenidClient <simple_openid_connect.client.OpenidClient>`::

    client = OpenidClient(...)
    response = client.introspect_token(dummy_openid_provider.cheat_token)
    assert response.active


Using the ``access_token_required`` decorator
=============================================

If you are using Django, you can decorate your view functions with the :func:`access_token_required <simple_openid_connect.integrations.django.decorators.access_token_required>` to enforce that
only requests with a valid access token can access the view::

    @access_token_required(required_scopes="openid my_resource:read")
    def read_resource(request):
        ...
