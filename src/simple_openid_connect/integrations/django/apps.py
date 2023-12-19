"""
Django AppConfig for this app
"""
import inspect
import logging
from functools import cached_property
from typing import TYPE_CHECKING, List, Optional, Union

from django.apps import AppConfig, apps
from django.conf import settings
from django.core.cache import cache
from django.core.checks import Error, Warning, register
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest
from django.shortcuts import resolve_url
from django.utils.module_loading import import_string
from pydantic import BaseModel

from simple_openid_connect.client import OpenidClient

if TYPE_CHECKING:
    from simple_openid_connect.integrations.django.user_mapping import UserMapper

logger = logging.getLogger(__name__)


class SettingsModel(BaseModel):
    """
    A pydantic model used to validate django settings
    """

    OPENID_ISSUER: str
    OPENID_CLIENT_ID: str
    OPENID_CLIENT_SECRET: Optional[str]
    OPENID_SCOPE: str = "openid"
    OPENID_REDIRECT_URI: Optional[str] = "simple_openid_connect:login-callback"
    OPENID_BASE_URI: Optional[str]
    OPENID_USER_MAPPER = (
        "simple_openid_connect.integrations.django.user_mapping.UserMapper"
    )

    class Config:
        orm_mode = True


class OpenidAppConfig(AppConfig):
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
        return SettingsModel.from_orm(settings)

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


@register  # type: ignore
def check_middleware(*args, **kwargs) -> List[Union[Warning, Error]]:
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
            )
        ]
    else:
        return []
