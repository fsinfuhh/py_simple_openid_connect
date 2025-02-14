"""
Django AppConfig for this app
"""

import inspect
import logging
from functools import cached_property
from typing import TYPE_CHECKING, Any, List, Optional, Union

from django.apps import AppConfig, apps
from django.conf import settings
from django.core.cache import cache
from django.core.checks import Error, Warning, register
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest
from django.shortcuts import resolve_url
from django.utils.module_loading import import_string
from pydantic import BaseModel, ConfigDict

from simple_openid_connect.client import OpenidClient

if TYPE_CHECKING:
    from simple_openid_connect.integrations.django.user_mapping import UserMapper

logger = logging.getLogger(__name__)


class SettingsModel(BaseModel):
    """
    A pydantic model used to validate django settings
    """

    model_config = ConfigDict(from_attributes=True)

    OPENID_ISSUER: str
    "The Openid issuer to use. This is required to be an `https` url and an Openid discovery document should be served under ``{issuer}/.well-known/openid-configuration``."

    OPENID_CLIENT_ID: str
    "The client id that was issued to you from your OpenId provider."

    OPENID_CLIENT_SECRET: Optional[str] = None
    "The client secret that was issued to you from your OpenId provider if this is a confidential client."

    OPENID_SCOPE: str = "openid"
    "The Openid scopes which are requested from the provider when a user logs in. It should be a list of scopes as space separated string and should contain the ``openid`` scope."

    OPENID_REDIRECT_URI: Optional[str] = "simple_openid_connect:login-callback"
    "The URL or ``named URL pattern <https://docs.djangoproject.com/en/dev/topics/http/urls/#naming-url-patterns>``_ where users are redirected to from the OpenId provider and at which the authentication result is processed.\nThis is sometimes also called a callback uri."

    OPENID_BASE_URI: Optional[str] = None
    "The absolute base uri of this application. This is used to construct valid redirect urls to the current application."

    OPENID_USER_MAPPER: str = (
        "simple_openid_connect.integrations.django.user_mapping.UserMapper"
    )
    "A string specifying a class that inherits from :class:`simple_openid_connect.integrations.django.user_mapping.UserMapper`."

    OPENID_LOGIN_TIMEOUT: int = 60 * 10
    "Time in seconds which a login procedure is allowed to take at maximum. If a user takes more than this time between initiating a login and completing it, the login process fails and they have to redo it."


class OpenidAppConfig(AppConfig):
    """
    The Django AppConfig for simple_openid_connect
    """

    name = "simple_openid_connect.integrations.django"
    label = "simple_openid_connect_django"

    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        """
        Called when django starts.

        Performs settings validation and raises ImproperlyConfigured if necessary.
        """
        super().ready()

        # assert that are settings are as required
        try:
            _ = self.safe_settings
            _ = self.user_mapper
        except Exception as e:
            raise ImproperlyConfigured(
                f"django settings are invalid for openid usage: {e}"
            ) from e

    @classmethod
    def get_instance(cls) -> "OpenidAppConfig":
        """
        Retrieve the currently used instance from django's app registry
        """
        instance = apps.get_app_config(cls.label)
        assert isinstance(instance, OpenidAppConfig)
        return instance

    @cached_property
    def safe_settings(self) -> SettingsModel:
        """
        type-validated version of django settings
        """
        return SettingsModel.model_validate(settings)

    @cached_property
    def user_mapper(self) -> "UserMapper":
        """
        A UserMapper instance of which the actual implementation is configured via django settings.
        """
        from simple_openid_connect.integrations.django.user_mapping import UserMapper

        cls = import_string(self.safe_settings.OPENID_USER_MAPPER)
        if not issubclass(cls, UserMapper):
            raise ImproperlyConfigured(
                "OPENID_USER_MAPPER setting does not point to a subclass of UserMapper",
                cls,
            )
        return cls()  # type: ignore

    def get_client(
        self, own_base_uri: Union[HttpRequest, str, None] = None
    ) -> OpenidClient:
        """
        Get an `OpenidClient` instance that is appropriate for usage in django.

        It is automatically configured via django settings.

        :param own_base_uri: The base url of this application which will be used to construct a redirect_uri back to it.
            Can also be the current request in which case `{scheme}://{host}` of it will be used as the base url.
            If this parameter is not given, only the `OPENID_BASE_URI` setting is used.
            In any case, if the `OPENID_BASE_URI` setting is set, it will be used instead.

        :raises ImproperlyConfigured: when no *own_base_uri* is given and the `OPENID_BASE_URI` is also None
        """
        # use a cached client instance if one exists or create a new one if not
        client = cache.get("openid_client")  # type: OpenidClient
        if client is None:
            # determine base_uri of this app
            if self.safe_settings.OPENID_REDIRECT_URI is not None:
                if self.safe_settings.OPENID_BASE_URI is not None:
                    own_base_uri = self.safe_settings.OPENID_BASE_URI
                else:
                    if own_base_uri is None:
                        raise ImproperlyConfigured(
                            "either a value for own_base_uri must be given or the django setting OPENID_BASE_URI must be filled"
                        )
                    elif isinstance(own_base_uri, HttpRequest):
                        own_base_uri = (
                            f"{own_base_uri.scheme}://{own_base_uri.get_host()}"
                        )

                relative_redirect_uri = resolve_url(
                    self.safe_settings.OPENID_REDIRECT_URI
                )
                redirect_uri = f"{own_base_uri}{relative_redirect_uri}"
            else:
                redirect_uri = None

            # create a new client instance and cache it
            client = OpenidClient.from_issuer_url(
                url=self.safe_settings.OPENID_ISSUER,
                authentication_redirect_uri=redirect_uri,
                client_id=self.safe_settings.OPENID_CLIENT_ID,
                client_secret=self.safe_settings.OPENID_CLIENT_SECRET,
                scope=self.safe_settings.OPENID_SCOPE,
            )
            cache.set("openid_client", client)

        return client


@register
def check_middleware(*args: Any, **kwargs: Any) -> List[Union[Warning, Error]]:
    """
    Check that our TokenVerificationMiddleware has been added to django settings
    """
    from simple_openid_connect.integrations.django.middleware import (
        TokenVerificationMiddleware,
    )

    if (
        hasattr(settings, "OPENID_REDIRECT_URI")
        and settings.OPENID_REDIRECT_URI is None  # type: ignore
    ):
        # redirect uri is set to None,
        # so the library is probably used as a resource server,
        # therefore we don't need the middleware
        return []

    has_token_verification_middleware = False
    for middleware in settings.MIDDLEWARE:
        try:
            middleware_cls = import_string(middleware)
        except ImportError:
            continue
        if inspect.isclass(middleware_cls) and issubclass(
            middleware_cls, TokenVerificationMiddleware
        ):
            has_token_verification_middleware = True
            break

    if not has_token_verification_middleware:
        return [
            Warning(
                "Access tokens are not checked for expiry and users are not automatically logged out when their access token expires.",
                hint="Add 'simple_openid_connect.integrations.django.middleware.TokenVerificationMiddleware' to MIDDLEWARE.",
                obj="simple_openid_connect",
                id="simple_openid_connect.W001",
            )
        ]
    else:
        return []
