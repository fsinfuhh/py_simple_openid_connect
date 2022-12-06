"""
DRF Authentication classes

See the `DRF documentation on Setting the authentication scheme <https://www.django-rest-framework.org/api-guide/authentication/#setting-the-authentication-scheme>`_ about how to use the classes contained here.
"""

import logging
from typing import Any, Optional, Tuple, Union

from django.contrib.auth.models import AnonymousUser
from django.http import HttpRequest
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from simple_openid_connect.data import (
    TokenIntrospectionErrorResponse,
    TokenIntrospectionSuccessResponse,
)
from simple_openid_connect.integrations.django import models
from simple_openid_connect.integrations.django.apps import OpenidAppConfig

logger = logging.getLogger(__name__)


class AuthenticatedViaToken:
    """
    A marker that is attached as ``request.auth`` on successful authentication and which holds well formatted
    information about that authentication.
    """

    def __init__(
        self, token: str, token_introspection: TokenIntrospectionSuccessResponse
    ):
        self.token = token
        self.token_introspection = token_introspection

    def __str__(self) -> str:
        return self.token


class AccessTokenAuthentication(BaseAuthentication):
    """
    An authentication scheme that interprets ``Authorization: Bearer ...`` http headers as access tokens and validates
    by using the Openid providers token introspection capabilities.

    By default, this may confirm that a request is authenticated and has appropriate access while not identifying a user.
    In that case, only an ``AnonymousUser`` instance is set on the request.
    If this is not desired, either set the ``allow_anonymous`` constructor parameter to ``False`` or use the
    :class:`AccessTokenNoAnonAuthentication` authentication class.
    """

    def __init__(
        self,
        allow_anonymous: Optional[bool] = True,
    ):
        """
        :param allow_anonymous: Whether access is allowed when the token is valid but no user can be identified.
            This is the case if the Openid providers token introspection endpoint does not return a user id.
        """
        self.allow_anonymous = allow_anonymous

    def authenticate(
        self, request: HttpRequest
    ) -> Union[Tuple[Any, AuthenticatedViaToken], None]:
        # abort if no authentication is intended
        if "Authorization" not in request.headers.keys() or not request.headers[
            "Authorization"
        ].startswith("Bearer "):
            return None

        # introspect passed token
        token = request.headers["Authorization"].split(" ", 1)[1]
        oidc_client = OpenidAppConfig.get_instance().get_client(request)
        introspect_response = oidc_client.introspect_token(token)

        if isinstance(introspect_response, TokenIntrospectionErrorResponse):
            logger.error(
                "could not introspect access token for validity: %s",
                introspect_response,
            )
            raise AuthenticationFailed()

        # raise if the token is expired
        if not introspect_response.active:
            logger.info(
                "failing authentication because the access token is expired, token=%s",
                token,
            )
            raise AuthenticationFailed()

        # fetch user (if possible) and return authentication result
        if introspect_response.sub is not None:
            user = models.OpenidUser.objects.get_or_create_for_sub(
                introspect_response.sub, introspect_response.username
            ).user
            return user, AuthenticatedViaToken(token, introspect_response)
        else:
            if not self.allow_anonymous:
                logger.error(
                    "failing authentication because anonymous access is forbidden but the token introspection returned no user information that can be used to identify the requesting user"
                )
                raise AuthenticationFailed()
            return AnonymousUser(), AuthenticatedViaToken(token, introspect_response)

    def authenticate_header(self, request: HttpRequest) -> str:
        return "Bearer"


class AccessTokenNoAnonAuthentication(AccessTokenAuthentication):
    """
    An authentication scheme that overwrites the default behavior of :class:`AccessTokenAuthentication` so that tokens
    are only considered valid if a user can be uniquely identified.
    """

    def __init__(
        self,
        allow_anonymous: Optional[bool] = False,
    ):
        super().__init__(allow_anonymous)
