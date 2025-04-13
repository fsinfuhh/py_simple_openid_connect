"""
DRF Authentication classes

See the `DRF documentation on Setting the authentication scheme <https://www.django-rest-framework.org/api-guide/authentication/#setting-the-authentication-scheme>`_ about how to use the classes contained here.
"""

import logging
from typing import Any, Tuple, Union

from django.http import HttpRequest
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from simple_openid_connect.exceptions import ValidationError
from simple_openid_connect.integrations.django.apps import OpenidAppConfig
from simple_openid_connect.integrations.django.user_mapping import FederatedUserData

logger = logging.getLogger(__name__)


class AuthenticatedViaToken:
    """
    A marker that is attached as ``request.auth`` on successful authentication and which holds well formatted
    information about that authentication.
    """

    def __init__(
        self,
        token: str,
        user_data: FederatedUserData,
    ):
        self.token = token
        self.user_data = user_data

    def __str__(self) -> str:
        return self.token


class AccessTokenAuthentication(BaseAuthentication):
    """
    An authentication scheme that interprets ``Authorization: Bearer ...`` http headers as access tokens.
    """

    def authenticate(
        self, request: HttpRequest
    ) -> Union[Tuple[Any, AuthenticatedViaToken], None]:
        # abort if no authentication is intended
        if "Authorization" not in request.headers.keys() or not request.headers[
            "Authorization"
        ].startswith("Bearer "):
            return None

        oidc_client = OpenidAppConfig.get_instance().get_client(request)
        raw_token = request.headers["Authorization"].split(" ", 1)[1]

        # handle access token while not verifying scopes because those are verified by a permission class
        try:
            (
                user,
                userinfo,
            ) = OpenidAppConfig.get_instance().user_mapper.handle_federated_access_token(
                raw_token, oidc_client, required_scopes=""
            )
            return user, AuthenticatedViaToken(raw_token, userinfo)
        except ValidationError:
            raise AuthenticationFailed()

    def authenticate_header(self, request: HttpRequest) -> str:
        return "Bearer"
