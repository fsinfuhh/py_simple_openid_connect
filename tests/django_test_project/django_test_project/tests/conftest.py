from typing import Any

import pytest
import requests
from django.contrib.auth.models import User
from django.http import (
    HttpResponse,
    HttpResponsePermanentRedirect,
    HttpResponseRedirect,
)
from django.test.client import Client as DjangoClient
from furl import furl

from simple_openid_connect.integrations.django import models


@pytest.fixture
def dummy_provider_settings(settings):
    settings.ALLOWED_HOSTS.append("app.example.com")
    settings.OPENID_SCOPE = "openid"
    settings.OPENID_ISSUER = "https://provider.example.com"
    settings.OPENID_BASE_URI = "https://app.example.com"
    settings.OPENID_CLIENT_ID = "client-id"
    settings.OPENID_CLIENT_SECRET = "client-secret"


class DynClient(DjangoClient):
    def request(self, **request: Any) -> HttpResponse:
        # handle internal hosts normally
        from django.conf import settings

        if (
            "SERVER_NAME" not in request.keys()
            or request["SERVER_NAME"] in settings.ALLOWED_HOSTS
        ):
            return super().request(**request)

        # handle external hosts via request
        url = furl(
            scheme=request["wsgi.url_scheme"],
            host=request["SERVER_NAME"],
            port=request["SERVER_PORT"] if request["SERVER_PORT"] != "80" else None,
            path=request["PATH_INFO"],
            query=request["QUERY_STRING"],
        )
        response = requests.request(
            method=request["REQUEST_METHOD"],
            url=str(url),
            allow_redirects=False,
        )  # type: requests.Response
        base_kwargs = {
            "content": response.content,
            "status": response.status_code,
            "reason": response.reason,
            "charset": response.apparent_encoding,
            "headers": response.headers,
        }
        if response.status_code == 302:
            return HttpResponseRedirect(
                redirect_to=response.headers["Location"], **base_kwargs
            )
        elif response.status_code == 301:
            return HttpResponsePermanentRedirect(
                redirect_to=response.headers["Location"], **base_kwargs
            )
        return HttpResponse(**base_kwargs)


@pytest.fixture
def dyn_client(client) -> DynClient:
    """A client that automatically distinguishes between internal django calls and calls to external domains"""
    return DynClient()


@pytest.fixture
def test_user(db) -> User:
    user = User.objects.create_user("user1")
    _openid_user = models.OpenidUser.objects.create(sub="1", user=user)
    return user
