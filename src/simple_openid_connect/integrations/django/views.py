"""
View functions which handle openid authentication and their related callbacks
"""
import logging
from http import HTTPStatus
from typing import Mapping

from django.conf import settings
from django.contrib.auth import login, logout
from django.http import (
    HttpRequest,
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseRedirect,
)
from django.shortcuts import resolve_url
from django.template.response import TemplateResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.cache import cache_control

from simple_openid_connect.data import (
    FrontChannelLogoutNotification,
    IdToken,
    RpInitiatedLogoutRequest,
    TokenSuccessResponse,
)
from simple_openid_connect.integrations.django.apps import OpenidAppConfig
from simple_openid_connect.integrations.django.models import OpenidSession

logger = logging.getLogger(__name__)


class InitLoginView(View):
    """
    The view which handles initiating a login.

    It essentially redirects the user agent to the Openid provider.
    """

    def get(self, request: HttpRequest) -> HttpResponse:
        logout(request)
        if "next" in request.GET.keys():
            request.session["login_redirect_url"] = request.GET["next"]
        client = OpenidAppConfig.get_instance().get_client(request)
        redirect = client.authorization_code_flow.start_authentication()
        return HttpResponseRedirect(redirect)


class LoginCallbackView(View):
    """
    The view which handles login callbacks.

    It handles an authentication response from the Openid provider that is encoded in the current url by either logging
    the user in or rendering the error.

    Error rendering can be customized by overwriting the template *simple_openid_connect/login_failed.html* which
    receives the context `token_response` of type :class:`TokenErrorResponse <simple_openid_connect.data.TokenErrorResponse>`.
    """

    def get(self, request: HttpRequest) -> HttpResponse:
        client = OpenidAppConfig.get_instance().get_client(request)

        # exchange the passed code for tokens
        token_response = client.authorization_code_flow.handle_authentication_result(
            current_url=request.get_full_path(),
        )
        if not isinstance(token_response, TokenSuccessResponse):
            return TemplateResponse(
                request,
                "simple_openid_connect/login_failed.html",
                {
                    "token_response": token_response,
                },
                status=HTTPStatus.UNAUTHORIZED,
            )

        # validate the received tokens
        id_token = IdToken.parse_jwt(token_response.id_token, client.provider_keys)
        id_token.validate_extern(
            client.provider_config.issuer, client.client_auth.client_id
        )

        # handle federated user information (create a new user if necessary or update local info) and log the user in
        user = OpenidAppConfig.get_instance().user_mapper.handle_federated_userinfo(
            id_token
        )
        openid_session = user.openid.update_session(token_response, id_token)
        request.session["openid_session"] = openid_session.id
        login(request, user, backend=settings.AUTHENTICATION_BACKENDS[0])

        # redirect to the next get parameter if present, otherwise to the configured default
        if "login_redirect_url" in request.session.keys():
            return HttpResponseRedirect(
                redirect_to=request.session["login_redirect_url"]
            )
        else:
            return HttpResponseRedirect(
                redirect_to=resolve_url(settings.LOGIN_REDIRECT_URL)
            )


class LogoutView(View):
    """
    The view which handles logging a user out.
    """

    def get(self, request: HttpRequest) -> HttpResponse:
        session_id = request.session.get("openid_session")
        logout(request)
        client = OpenidAppConfig.get_instance().get_client(request)

        if settings.LOGOUT_REDIRECT_URL is not None:
            openid_session = (
                OpenidSession.objects.get(id=session_id) if session_id else None
            )

            logout_request = RpInitiatedLogoutRequest(
                post_logout_redirect_uri=request.build_absolute_uri(
                    resolve_url(settings.LOGOUT_REDIRECT_URL)
                )
            )
            if openid_session is not None and openid_session.raw_id_token is not None:
                logout_request.id_token_hint = openid_session.raw_id_token
            else:
                logout_request.client_id = client.client_auth.client_id
        else:
            logout_request = None

        return HttpResponseRedirect(client.initiate_logout(logout_request))


class FrontChannelLogoutNotificationView(View):
    """
    A view which handles Openid front-channel logout notifications by logging out the current session
    """

    @method_decorator(cache_control(no_store=True))
    def get(self, request: HttpRequest) -> HttpResponse:
        logout(request)
        return HttpResponse(status=200)
