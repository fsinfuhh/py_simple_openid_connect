Django Integration
******************

This page describes how authentication can be done using the *Django* web framework.
Much of the library internals have been abstracted away so that Openid authentication can easily be plugged into django projects.

One of the goals of this integration is to be as unobtrusive as possible to existing django projects and to allow signing in (and registering) users into you django application via a single preconfigured OpenID-Connect Identity Provider.

.. note::

  If you require a more sophisticated setup with multiple authentication backend that allow a user to associate and unassociate their different upstream accounts, use something like `python-social-auth <https://python-social-auth.readthedocs.io/en/latest/configuration/django.html>`_ instead.


How it Works
============

To follow the design goal outlined above, the integration is implemented only using views, middlewares (optional) and a few database models.
Inner workings of django or the authentication system are not changed by this integration, i.e. there are no additional authentication backends or custom user models.

The following models are added (relationships are visualized below):

* :class:`OpenidUser <simple_openid_connect.integrations.django.models.OpenidUser>` which is the central tracking model for federated user data. It is linked to a projects user model and can be accessed by the ``openid`` property on the django user model.

* :class:`OpenidSession <simple_openid_connect.integrations.django.models.OpenidUser>` to hold information relating to a concrete OpenID session.
  A single OpenID user can have multiple sessions, even on the same device.
  A session holds relevant tokens as well as expiry information.

.. code-block:: text

   ┌───────────────────┐           ┌───────────────────┐           ┌───────────────────┐
   │ Django User Model │           │ OpenidUser        │           │ OpenidSession     │
   ├───────────────────┤           ├───────────────────┤           ├───────────────────┤
   │ username          │           │ sub               │     ╭┄┄N┄┄│ user              │
   │ password          │     ╭┄┄1┄┄│ user              │     ┊     │ sid               │
   │ …                 │     ┊     │ sessions          │┄┄1┄┄╯     │ scope             │
   │ openid            │┄┄1┄┄╯     └───────────────────┘           │ access_token      │
   └───────────────────┘                                           │ refresh_token     │
                                                                   │ id_token          │
                                                                   │ …                 │
                                                                   └───────────────────┘

Logging In
----------

When a user completes OpenID authentication via one of the routes provided by :mod:`simple_openid_connect.integrations.django.urls` (usually ``/auth/openid/login/``), the information from the identity provider is saved in these models and the current django session is authenticated via a call to :func:`django.contrib.auth.login`.

The login view also supports a `?next` get parameter to influence where the user should be redirected after a successful login.
If not specified, the ``LOGIN_REDIRECT_URL`` django setting is used.

Logging Out
-----------

When a user visits the logout endpoint (usually ``/auth/openid/logout/``), the current django session is always immediately logged out via a call to :func:`django.contrib.auth.logout`.
Afterwards, the user is redirected to the OpenID Identity Provider so that the logout intent can get federated through all OpenID connected apps.
Unless the Identity Provider does something special, the user will return to the django app after this federated logout.


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

``simple_openid_connect.integrations.django.TokenVerificationMiddleware`` should also be added to the middleware stack.
This middleware makes sure that access tokens of users are still valid. It is not required if the library is only used as a Resource Server (see below)::

    # settings.py
    MIDDLEWARE = [
        ...,
        "simple_openid_connect.integrations.django.middleware.TokenVerificationMiddleware",
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

- ``LOGIN_URL`` (`django LOGIN_URL docs <https://docs.djangoproject.com/en/dev/ref/settings/#login-url>`_)
    This is recommended to be set to ``simple_openid_connect:login`` to serve this libraries login page which handles Openid authentication.
    If additional authentication methods are also used, don't do this.

- ``LOGIN_REDIRECT_URL`` (`django LOGIN_REDIRECT_URL docs <https://docs.djangoproject.com/en/dev/ref/settings/#login-redirect-url>`_)
    This is the URL to which a user is redirected after a successful login.

- ``LOGOUT_REDIRECT_URL`` (`django LOGOUT_REDIRECT_URL docs <https://docs.djangoproject.com/en/dev/ref/settings/#logout-redirect-url>`_)
    This is the url the user is redirected to after logging out. If it is not set, some Openid providers do not redirect the user back to the application.

Settings Reference
------------------

For a list of all settings that are read by *simple_openid_connect*, see the :class:`SettingsModel <simple_openid_connect.integrations.django.apps.SettingsModel>`.


Usage
=====

After setup is done, this library is very *hands off*.
It authenticates users using Openid-Connect, parses retrieved user information, automatically creates or updates user
objects as required and then authenticates the current session.
It interoperates with Django's builtin authentication so things like the ``login_required`` decorator can still be used.

If you want to authenticate a user via Openid, simply visit ``/auth/openid/login`` on your app.

.. note::

   Assuming, the URL setup from this documentation is followed, the following URLs are used by this integration:

   .. list-table::
      :header-rows: 1

      * - Relative URL
        - Purpose
      * - ``/auth/openid/login-callback/``
        - Redirect-URI to which the user is returned to during login
      * - ``/auth/openid/logout/frontchannel-notify/``
        - Notification endpoint to which an Identity Provider may send *Frontchannel Logout Notifications*


Custom User Mapping
-------------------

User objects are automatically created when the user authenticates to a django server using this integration.
This is done when the server is a relying party as well as when it is a resource server.
The goal is to be as transparent as possible to programmers because a user object is always available and associated
with authenticated requests.

Sometimes it is useful though to customize the behavior in which tokens are mapped to users or which information
is extracted from the tokens.
This can be done in two steps:

1. Subclass :class:`UserMapper <simple_openid_connect.integrations.django.user_mapping.UserMapper>` and overwrite the
   methods which should be changed.

   For details about which methods exist on the class, what they should do and what their signatures are, take a look
   at the ``UserMapper`` class documentation.

   .. code-block:: python

      from simple_openid_connect.integrations.django.user_mapping import UserMapper

      class CustomUserMapper(UserMapper):
          def automap_user_attrs(self, user, user_data):
              super().automap_user_attrs(user, user_data)
              if user_data.preferred_username == "admin":
                  user.is_superuser = True
                  user.is_staff = True

2. Configure simple_openid_connect to use the new ``UserMapper`` class by setting the ``OPENID_USER_MAPPER`` attribute
   in your projects ``settings.py``.


Accessing ``OpenidClient``
--------------------------

If you ever need to do your own Openid interactions, a configured :class:`OpenidClient <simple_openid_connect.client.OpenidClient>` is available at this libraries :class:`AppConfig <simple_openid_connect.integrations.django.apps.OpenidAppConfig>` instance.
You can access it like this::

    from simple_openid_connect.integrations.django.apps import OpenidAppConfig
    client = OpenidAppConfig.get_instance().get_client(request)


Logging into Django-Admin
-------------------------

Generally, because this integration does not replace the normal django authentication system, django-admin works normally and admin users can just use it as-is.
The standard ``is_superuser`` property of user objects still controls who can access the page and you can influence how that property is set by defining a custom User Mapper as described above.

Sometimes though, for example if OpenID login is the only intended login method and accounts don't have a password set, the *Username & Password* form rendered by django-admin can be a bit annoying.
It can be changed by defining a custom template which overrides the relevant sections.

1. Ensure your django app is loaded before django-admin:

   .. code-block:: python

      # settings.py
      INSTALLED_APPS = [
          "my_awesome_app",
          ...
          "django.contrib.admin",
      ]

   This is needed because django searches through all installed apps for a given template name and you want to override the template provided by django-admin.

2. Define your own ``admin/login.html`` template in your apps template directory.
   The example below does not completely overwrite the template provided by django-admin but instead extends it and only replaces the part which renders a login form.
   That way, all styles and themes are still applied correctly and the form looks consistent:

   .. code-block:: jinja

      {# my_awesome_app/templates/admin/login.html #}
      {% extends "admin/login.html" %}
      {% load i18n %}
      {% block content %}
      <div id="content-main">

      {% if user.is_authenticated %}
      <p class="errornote">
      {% blocktranslate trimmed %}
          You are authenticated as {{ username }}, but are not authorized to
          access this page. Would you like to login to a different account?
      {% endblocktranslate %}
      </p>
      {% endif %}

      <form id="login-form" method="get" action="{% url 'simple_openid_connect:login' %}">
        <input hidden name="next" value="{{ request.GET.next | default:"/admin/" }}">
        <div class="submit-row">
          <input type="submit" value="{% translate 'Log in with OpenID Connect' %}">
        </div>
      </form>

      </div>
      {% endblock %}

Clearing expired sessions
-------------------------

Depending on the OpenID Identity Provider, the federated sessions might be short lived and accumulate over time.
To clear old and expired sessions, a django management command is provided.
It can be run using the following command::

  ./manage.py clear-expired-openid-sessions



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
