import logging
from types import EllipsisType
from typing import Optional, Union

from django.apps import AppConfig, apps
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest
from django.shortcuts import resolve_url
from pydantic import BaseModel

from simple_openid_connect.client import OpenidClient

logger = logging.getLogger(__name__)


class SettingsModel(BaseModel):
    OPENID_ISSUER: str
    OPENID_CLIENT_ID: str
    OPENID_CLIENT_SECRET: Optional[str]
    OPENID_SCOPE: str = "openid"
    OPENID_REDIRECT_URI: str = "simple_openid_connect_django:login-callback"
    OPENID_BASE_URI: Optional[str]

    class Config:
        orm_mode = True


class OpenidAppConfig(AppConfig):
    name = "simple_openid_connect_django"

    def ready(self) -> None:
        super().ready()

        # assert that are settings are as required
        try:
            _ = self.safe_settings
        except Exception as e:
            raise ImproperlyConfigured(
                f"django settings are invalid for openid usage: {e}"
            ) from e

    @classmethod
    def get_instance(cls) -> "OpenidAppConfig":
        """
        Retrieve the currently used instance from django's app registry
        """
        instance = apps.get_app_config(cls.name)
        assert isinstance(instance, OpenidAppConfig)
        return instance

    @property
    def safe_settings(self) -> SettingsModel:
        return SettingsModel.from_orm(settings)

    def get_client(
        self, own_base_uri: Union[HttpRequest, str, EllipsisType] = ...
    ) -> OpenidClient:
        """
        Get an `OpenidClient` instance that is appropriate for usage in django.

        It is automatically configured via django settings.

        :param own_base_uri: The base url of this application which will be used to construct a redirect_uri back to it.
            Can also be the current request in which case `{scheme}://{host}` of it will be used as the base url.
            If this parameter is not given, a fallback to the `OPENID_BASE_URI` setting is done.

        :raises ImproperlyConfigured: when the *own_base_uri* is given and the `OPENID_BASE_URI` is also None
        """
        # determine base_uri of this app
        if own_base_uri is ...:
            setting = self.safe_settings.OPENID_BASE_URI
            if setting is not None:
                own_base_uri = setting
            else:
                raise ImproperlyConfigured(
                    "either a value for own_base_uri must be given or the django setting OPENID_BASE_URI must be filled"
                )
        elif isinstance(own_base_uri, HttpRequest):
            own_base_uri = f"{own_base_uri.scheme}://{own_base_uri.get_host()}"

        # use a cached client instance if one exists or create a new one if not
        client = cache.get("openid_client")  # type: OpenidClient
        if client is None:
            redirect_uri = resolve_url(self.safe_settings.OPENID_REDIRECT_URI)
            client = OpenidClient.from_issuer_url(
                url=self.safe_settings.OPENID_ISSUER,
                authentication_redirect_uri=f"{own_base_uri}{redirect_uri}",
                client_id=self.safe_settings.OPENID_CLIENT_ID,
                client_secret=self.safe_settings.OPENID_CLIENT_SECRET,
                scope=self.safe_settings.OPENID_SCOPE,
            )
            cache.set("openid_client", client)

        return client
