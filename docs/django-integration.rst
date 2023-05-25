Django Integration
******************

This page describes how authentication can be done using the *Django* web framework.
Much of the library internals have been abstracted away so that Openid authentication can easily be plugged into django projects.

Setup
=====

Add to ``INSTALLED_APPS``
-------------------------

At first django settings need to be adapted to include ``simple_openid_connect.integrations.django`` as an app::

    # settings.py
    INSTALLED_APPS = [
        ...,
        "simple_openid_connect.integrations.django",
    ]

Add url routes
--------------

Django needs to be told how to route Openid related login views.
To do so, include this libraries urls into yours::

    # urls.py
    urlpatterns = [
        ...,
        path("auth/openid/", include("simple_openid_connect.integrations.django.urls")),
    ]

Required settings
-----------------

These values must be set in the projects ``settings.py`` to configure openid authentication.

- ``OPENID_ISSUER``
    This settings configures the Openid issuer to use.
    This is required to be an `https` url and an Openid discovery document should be served under ``{issuer}/.well-known/openid-configuration``.

- ``OPENID_CLIENT_ID``
    The client id that was issued to you from your Openid provider.

Recommended settings
--------------------

- ``OPENID_BASE_URI``
    The absolute base uri of this application.
    This is used to construct valid redirect urls to the current application.

- ``OPENID_CLIENT_SECRET``
    The client secret that was issued to you from your Openid provider if this is a confidential client.

- ``OPENID_SCOPE``
    The Openid scopes which are requested from the provider when a user logs in.
    It should be a list of scopes as space separated string and should contain the ``openid`` scope.

- ``LOGIN_URL`` (`django docs <https://docs.djangoproject.com/en/dev/ref/settings/#login-url>`_)
    This is recommended to be set to ``simple_openid_connect_django:login`` to serve this libraries login page which handles Openid authentication.
    If additional authentication methods are also used, don't do this.

- ``LOGOUT_REDIRECT_URL`` (`django docs <https://docs.djangoproject.com/en/dev/ref/settings/#logout-redirect-url>`_)
    This is the url the user is redirected to after logging out. If it is not set, some Openid providers do not redirect the user back to the application.

Usage
=====

After setup is done, this library is very *hands off*.
It authenticates users using Openid-Connect, parses retrieved user information, automatically creates or updates user
objects as required and then authenticates the current session.
It interoperates with Django's builtin authentication so things like the ``login_required`` decorator can still be used.

If you want to authenticate a user via Openid, simply visit ``/auth/openid/login`` on your app.


Customizing User Mapping
------------------------

User objects are automatically created from id tokens and also updated when the user re-authenticates.
The default behavior is to look for some well known id token attributes and map them to well known django attributes.
See :mod:`user_mapping <simple_openid_connect.integrations.django.user_mapping>` for the implementation.

This can be customized by defining ``OPENID_CREATE_USER_FUNC`` or ``OPENID_UPDATE_USER_FUNC`` in your django settings.
These should be a dotted module path with the function being the last name in the path.


Accessing ``OpenidClient``
--------------------------

If you ever need to do your own Openid interactions, a configured :class:`OpenidClient <simple_openid_connect.client.OpenidClient>` is available at this libraries :class:`AppConfig <simple_openid_connect.integrations.django.apps.OpenidAppConfig>` instance.
You can access it like this::

    from simple_openid_connect.integrations.django.apps import OpenidAppConfig
    client = OpenidAppConfig.get_instance().get_client(request)


Resource Server Usage
=====================

If your app is not the one where a user is authenticated via Openid but instead one that accepts access tokens from
authenticated user (e.g. an API server) you can still use this library.
Using :doc:`Django REST Framework <drf-integration>` is recommended but a plain django app can also be used as a resource server without it.

Access token validation is usually very simple and consists of asking the Openid provider if a given token is valid.
This process is called token introspection and the provider may add more information about the token in its response
(e.g. which scopes the token has access to).


Resource Server Configuration
-----------------------------

There is almost no additional setup required when this library is used for resource servers.
Settings like ``OPENID_ISSUER`` or client credentials are reused.
The only exception is that the ``OPENID_REDIRECT_URI`` setting should be explicitly set to ``None`` if your project is
exclusively acting as a resource server.


Verification using a client
---------------------------

A simple way to introspect a token is using an :class:`OpenidClient <simple_openid_connect.client.OpenidClient>`::

    client = OpenidClient(...)
    response = client.introspect_token(dummy_openid_provider.cheat_token)
    assert response.active


Using the ``access_token_required`` decorator
---------------------------------------------

If you are using Django, you can decorate your view functions with the :func:`access_token_required <simple_openid_connect.integrations.django.decorators.access_token_required>` to enforce that
only requests with a valid access token can access the view::

    @access_token_required(required_scopes="openid my_resource:read")
    def read_resource(request):
        ...
