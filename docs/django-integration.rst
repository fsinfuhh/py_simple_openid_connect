Django Integration
==================

This page describes how authentication can be done using the *Django* web framework.
Much of the library internals have been abstracted away so that Openid authentication can easily be plugged into django projects.

Setup
-----

Add to ``INSTALLED_APPS``
+++++++++++++++++++++++++

At first django settings need to be adapted to include ``simple_openid_connect.integrations.django`` as an app::

    # settings.py
    INSTALLED_APPS = [
        ...,
        "simple_openid_connect.integrations.django",
    ]

Add url routes
++++++++++++++

Django needs to be told how to route Openid related login views.
To do so, include this libraries urls into yours::

    # urls.py
    urlpatterns = [
        ...,
        path("auth/openid/", include("simple_openid_connect.integrations.django.urls")),
    ]

Required settings
+++++++++++++++++

These values must be set in the projects ``settings.py`` to configure openid authentication.

- ``OPENID_ISSUER``
    This settings configures the Openid issuer to use.
    This is required to be an `https` url and an Openid discovery document should be served under ``{issuer}/.well-known/openid-configuration``.

- ``OPENID_CLIENT_ID``
    The client id that was issued to you from your Openid provider.

Recommended settings
++++++++++++++++++++

- ``OPENID_BASE_URI``
    The absolute base uri of this application.
    This is used to construct valid redirect urls to the current application.

- ``OPENID_CLIENT_SECRET``
    The client secret that was issued to you from your Openid provider if this is a confidential client.

- ``LOGIN_URL`` (`django docs <LOGIN_URL>`_)
    This is recommended to be set to ``simple_openid_connect_django:login`` to serve this libraries login page which handles Openid authentication.
    If additional authentication methods are also used, don't do this.

Usage
-----

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
