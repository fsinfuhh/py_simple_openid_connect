"""
DRF permission classes

See the `DRF documentation on Setting the permission policy <https://www.django-rest-framework.org/api-guide/permissions/#setting-the-permission-policy>`_ on how to use the classes contained here.
"""


import logging
from typing import Any

from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest
from rest_framework.permissions import BasePermission

from simple_openid_connect.integrations.django.apps import OpenidAppConfig
from simple_openid_connect.integrations.django.models import OpenidSession
from simple_openid_connect.integrations.djangorestframework.authentication import (
    AuthenticatedViaToken,
)

logger = logging.getLogger(__name__)


class _HasScope(BasePermission):  # type: ignore # ignores a metaclass conflict that doesn't really exist
    @staticmethod
    def _get_required_scopes(view: Any) -> str:
        if hasattr(view, "required_scopes"):
            if not isinstance(view.required_scopes, str):
                raise ImproperlyConfigured(
                    f"view {view.__name__} has field 'required_scopes' but it is not a string. required_scopes needs to be a space separated string"
                )
            return view.required_scopes
        return OpenidAppConfig.get_instance().safe_settings.OPENID_SCOPE

    @staticmethod
    def _validate_scopes(required_scopes: str, granted_scopes: str) -> bool:
        """
        :returns: ``True`` iff all required scopes are present in granted scopes
        """
        return all(
            i_scope in granted_scopes.split(" ")
            for i_scope in required_scopes.split(" ")
        )


class HasSessionScope(_HasScope):  # type: ignore
    """Check whether an authenticated user has a session with the required scope"""

    def has_permission(self, request: HttpRequest, view: Any) -> bool:
        # validate that enough information is present to authorize the request
        if not request.user.is_authenticated:
            logger.error(
                "session permission is supposed to be checked but the request was not authenticated; denying access"
            )
            return False
        if not hasattr(request.user, "openid"):
            logger.error(
                "session permission is supposed to be checked but the request was not authenticated with an OpenidSession; denying access"
            )
            return False
        session_scopes = request.user.openid.sessions.values_list("scope", flat=True)
        required_scopes = self._get_required_scopes(view)
        for session_scope in session_scopes:
            if self._validate_scopes(required_scopes, session_scope):
                return True
        return False


class HasTokenScope(_HasScope):  # type: ignore
    """Check whether an authenticated user has a token with the required scope"""

    def has_permission(self, request: HttpRequest, view: Any) -> bool:
        # validate that enough information is present to authorize the request
        if not hasattr(request, "auth") or not isinstance(
            request.auth, AuthenticatedViaToken
        ):
            logger.error(
                "token permission is supposed to be checked but the request was not authenticated appropriately with an access token; denying access"
            )
            return False
        if request.auth.token_introspection.scope is None:
            logger.error(
                "token permission could not be checked because the token introspection does not contain token scopes; denying access"
            )
            return False

        # authorize the request
        required_scopes = self._get_required_scopes(view)
        return self._validate_scopes(
            required_scopes, request.auth.token_introspection.scope
        )
