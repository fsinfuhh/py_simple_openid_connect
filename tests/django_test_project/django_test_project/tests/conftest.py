import json
import sys
from base64 import b64encode
from typing import Any, Mapping, Union

import pytest
import requests
from cryptojwt import JWS, KeyBundle
from django.http import (
    HttpResponse,
    HttpResponsePermanentRedirect,
    HttpResponseRedirect,
)
from django.shortcuts import resolve_url
from django.test.client import Client as DjangoClient
from furl import furl
from responses import matchers


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
