"""
Django integration for :mod:`simple_openid_connect`.

Architecture
============

Integrating a new authentication mechanism into django involves a few missing parts.
Here's a quick overview over the most important classes involved:

.. code-block:: text

   ┌──────────────────────────────────┐   ┌──────────────────────────────────┐   ┌───────────────────┐
   │ @access_token_required decorator │   │ DRF AccessTokenAuthentication    │   │ LoginCallbackView │
   └────────────────┬─────────────────┘   └─────────────────┬────────────────┘   └─────────┬─────────┘
                    │                                       │                              │
                    └───────────────────┬───────────────────┘                              │
                                        ↓                                                  │
                 ┌──────────────────────┴─────────────────────┐                            │
                 │ UserMapper.handle_federated_access_token() │                            │
                 └──────────────────────┬─────────────────────┘                            │
                                        │                                                  │
                                        └──────────────────────────┬───────────────────────┘
                                                                   ↓
                                              ┌────────────────────┴───────────────────┐
                                              │ UserMapper.handle_federated_userinfo() │
                                              └────────────────────┬───────────────────┘
                                                                   ↓
                                                  ┌────────────────┴────────────────┐
                                                  │ UserMapper.automap_user_attrs() │
                                                  └─────────────────────────────────┘

- :class:`InitLoginView <simple_openid_connect.integrations.django.views.InitLoginView>` & :class:`LoginCallbackView <simple_openid_connect.integrations.django.views.LoginCallbackView>` are the backing views behind ``…/login/`` and ``…/login-callback/``.
  They implement authentication initiation with an OIDC provider and then handle the response to it in the callback.
- :class:`UserMapper <simple_openid_connect.integrations.django.user_mapping.UserMapper>` creates a local user account based on OIDC data and keeps it up to date.
  It is called every time a user authenticates, which is the case during interactive authentication as well as when a user passes an access token to e.g. an API route.
"""
