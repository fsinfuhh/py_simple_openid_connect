import logging
from typing import Callable

from django.conf import settings
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, QueryDict
from django.shortcuts import resolve_url

from simple_openid_connect.data import TokenSuccessResponse
from simple_openid_connect.integrations.django.apps import OpenidAppConfig
from simple_openid_connect.integrations.django.models import OpenidSession

logger = logging.getLogger(__name__)


class TokenVerificationMiddleware:
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # if we are already trying to log in, no redirect should happen
        if request.path == resolve_url(settings.LOGIN_URL):
            return self.get_response(request)

        # if the user is not logged in, also no redirect should happen
        openid_session_id = request.session.get("openid_session")
        if not openid_session_id:
            return self.get_response(request)

        # if the access token is still valid, everything is fine
        openid_session = OpenidSession.objects.get(id=openid_session_id)
        if not openid_session.is_access_token_expired:
            return self.get_response(request)

        # try to refresh the access token with the refresh token
        logger.debug("access token expired, trying to refresh")
        if not openid_session.is_refresh_token_expired:
            client = OpenidAppConfig.get_instance().get_client(request)
            exchange_response = client.exchange_refresh_token(
                openid_session.refresh_token
            )
            if isinstance(exchange_response, TokenSuccessResponse):
                openid_session.update_session(exchange_response)
                openid_session.save()
                return self.get_response(request)
            else:
                logger.warning(
                    "could not exchange refresh token for new access token: %s",
                    exchange_response,
                )

        # if no response has been served until now, the request needs to be aborted because there is no way to restore
        # a valid session
        url_params = QueryDict(mutable=True)
        if request.method == "GET":
            url_params["next"] = request.get_full_path()
        return HttpResponseRedirect(
            f"{resolve_url(settings.LOGIN_URL)}?{url_params.urlencode()}"
        )
