"""
View functions which handle openid authentication and their related callbacks
"""
import logging
import secrets
from datetime import datetime, timedelta, timezone
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


class InvalidAuthStateError(Exception):
    """
    Exception that is thrown when the LoginCallbackView is served and the user-agent has no authentication procedure currently in progress
    """

    def __init__(self) -> None:
        super().__init__(
            self,
            "User-Agent has no authentication procedures in progress so the login-callback will not be processed",
        )


class InvalidNonceError(Exception):
    """
    Exception that is thrown when an authentication response contains an invalid or no nonce value
    """

    def __init__(self) -> None:
        super().__init__(
            self, "Authentication response contained an invalid or no nonce value"
        )


class InitLoginView(View):
    """
    The view which handles initiating a login.

    It essentially redirects the user agent to the Openid provider.
    """

    def get(self, request: HttpRequest) -> HttpResponse:
        logout(request)
        if "next" in request.GET.keys():
            request.session["login_redirect_url"] = request.GET["next"]

        # save the login state into the session to prevent CSRF attacks (openid state parameter could be used instead)
        # See https://www.rfc-editor.org/rfc/rfc6749#section-10.12
        request.session["openid_auth_start_time"] = datetime.now(
            tz=timezone.utc
        ).timestamp()

        # prevent replay attacks by generating and specifying a nonce
        nonce = secrets.token_urlsafe(48)
        request.session["openid_auth_nonce"] = nonce

        # redirect the user-agent to the oidc provider
        client = OpenidAppConfig.get_instance().get_client(request)
        redirect = client.authorization_code_flow.start_authentication(nonce=nonce)
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
        app_settings = OpenidAppConfig.get_instance().safe_settings
        client = OpenidAppConfig.get_instance().get_client(request)

        # prevent CSRF attacks by verifying that the user agent is curently in the process of authenticating and that the authentication was not started more than the configured amount of time ago
        if request.session.get("openid_auth_start_time", None) is None or (
            datetime.now(tz=timezone.utc)
            - datetime.fromtimestamp(
                request.session["openid_auth_start_time"], tz=timezone.utc
            )
        ) > timedelta(seconds=app_settings.OPENID_LOGIN_TIMEOUT):
            raise InvalidAuthStateError()
        else:
            del request.session["openid_auth_start_time"]

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
            client.provider_config.issuer,
            client.client_auth.client_id,
            nonce=request.session["openid_auth_nonce"],
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
