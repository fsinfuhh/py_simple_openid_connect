import logging
from datetime import datetime, timezone
from typing import Callable

from django.conf import settings
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import resolve_url
from django.urls import reverse

from simple_openid_connect.data import TokenSuccessResponse
from simple_openid_connect.integrations.django.apps import OpenidAppConfig
from simple_openid_connect.integrations.django.models import OpenidSession

logger = logging.getLogger(__name__)


class TokenVerificationMiddleware:
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)
        openid_session_id = request.session.get("openid_session")
        if not openid_session_id:
            return response

        openid_session = OpenidSession.objects.get(id=openid_session_id)
        refresh_token = openid_session.refresh_token
        session_valid_until = openid_session.access_token_expiry
        access_token_valid = (
            session_valid_until is not None
            and session_valid_until > datetime.now(timezone.utc)
        )
        if access_token_valid:
            return response

        logger.debug("access token expired, trying to refresh")
        client = OpenidAppConfig.get_instance().get_client(request)
        exchange_response = client.exchange_refresh_token(refresh_token)
        if isinstance(exchange_response, TokenSuccessResponse):
            openid_session.update_session(exchange_response)
            openid_session.save()
            return response
        else:
            return HttpResponseRedirect(resolve_url(settings.LOGIN_URL))
