from django.apps import AppConfig, apps

from simple_openid_connect.client import OpenidClient


class BaseAppConfig(AppConfig):
    name = "simple_openid_connect_django"
    default = False

    openid_client: OpenidClient

    @classmethod
    def get_instance(cls) -> "BaseAppConfig":
        """
        Retrieve the currently used instance from django's app registry
        """
        instance = apps.get_app_config(cls.name)
        assert isinstance(instance, BaseAppConfig)
        return instance

    def ready(self) -> None:
        super().ready()
        self.openid_client = OpenidClient.from_issuer_url(
            "https://identity.mafiasi.de/auth/realms/simple_openid_test",
            "http://127.0.0.1:8000/auth/openid/login-callback",
            "test-confidential",
            "foobar123",
        )


class DefaultAppConfig(BaseAppConfig):
    default = True
