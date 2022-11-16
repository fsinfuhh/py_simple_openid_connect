from typing import Optional, TypeVar, Union

from django.apps import AppConfig, apps
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest
from django.shortcuts import resolve_url
from pydantic import BaseModel

from simple_openid_connect.client import OpenidClient


class SettingsModel(BaseModel):
    OPENID_ISSUER: str
    OPENID_CLIENT_ID: str
    OPENID_CLIENT_SECRET: Optional[str]
    OPENID_SCOPE: str = "openid"
    OPENID_REDIRECT_URI: str = "simple_openid_connect_django:login-callback"

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
            raise ImproperlyConfigured(f"django settings are invalid: {e}") from e

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

    def get_client(self, own_base_url: Union[HttpRequest, str]) -> OpenidClient:
        if isinstance(own_base_url, HttpRequest):
            own_base_url = f"{own_base_url.scheme}://{own_base_url.get_host()}"

        redirect_uri = resolve_url(self.safe_settings.OPENID_REDIRECT_URI)
        return OpenidClient.from_issuer_url(
            url=self.safe_settings.OPENID_ISSUER,
            authentication_redirect_uri=f"{own_base_url}{redirect_uri}",
            client_id=self.safe_settings.OPENID_CLIENT_ID,
            client_secret=self.safe_settings.OPENID_CLIENT_SECRET,
            scope=self.safe_settings.OPENID_SCOPE,
        )
