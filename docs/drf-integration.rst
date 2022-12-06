DRF Integration
***************

If you are using django together with `Django REST Framework <https://www.django-rest-framework.org/>`_ this page
explains how *DRF* can be configured to accept Openid access tokens.
This is useful if a django based server is only intended to serve as an *API-* or *Resource-Server* hosting resources
to which access is protected.

Setup
=====

Since *DRF* is built on Django the *DRF* Integration is built on top of the :doc:`django-integration`, that must
have already been set up.

Setup Authentication
--------------------

The *DRF* integration ships with the :class:`AccessTokenAuthentication <simple_openid_connect.integrations.djangorestframework.authentication.AccessTokenAuthentication>` authentication class which parses access tokens contained in a request, fetches a user based on that access token from the database or from the Openid Provider and associates them with the request.

Beware however that tokens are not always associated to a specific user (they might be issued directly to another client instead).
In this case, the request is authenticated but only associated with an anonymous django user.
If you wish to only allow identifiable users, use the :class:`AccessTokenNoAnonAuthentication <simple_openid_connect.integrations.djangorestframework.authentication.AccessTokenNoAnonAuthentication>` authentication class instead.

Set these classes as described in the corresponding `DRF documentation on Setting the authentication scheme <https://www.django-rest-framework.org/api-guide/authentication/#setting-the-authentication-scheme>`_.

.. code-block::

    class ExampleViewset(ModelViewSet):
        authentication_classes = [AccessTokenNoAnonAuthentication]
        ...

Setup Permissions
-----------------

Most of the time requests need to not only be authenticated but also authorized.
This can be done by validating the scopes that a received access token has been granted access to.

To do so, simply setup the :class:`HasTokenScope <simple_openid_connect.integrations.djangorestframework.permissions.HasTokenScope>` permission for your api view as described in the `DRF documentation on Setting the permission policy <https://www.django-rest-framework.org/api-guide/permissions/#setting-the-permission-policy>`_.

By default the required scopes for a view are taken from ``settings.OPENID_SCOPE``.
This can be overriden per view by setting the `required_scopes` attribute on it.

.. code-block::

    class ExampleViewset(ModelViewSet):
        permission_classes = [HasTokenScope]
        required_scopes = "openid example-resource"
        ...
