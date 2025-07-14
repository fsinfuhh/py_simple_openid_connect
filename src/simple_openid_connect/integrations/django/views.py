"""
View functions which handle openid authentication and their related callbacks
"""

import logging
import secrets
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from typing import Optional, Union, Any

from django.conf import settings
from django.contrib.auth import login, logout
from django.http import (
    HttpRequest,
    HttpResponse,
    HttpResponseRedirect,
)
from django.shortcuts import resolve_url
from django.template.response import TemplateResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.cache import cache_control

from simple_openid_connect.data import (
    IdToken,
    RpInitiatedLogoutRequest,
    TokenSuccessResponse,
    TokenErrorResponse,
)
from simple_openid_connect.exceptions import ValidationError, AuthenticationFailedError
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

        # save the login state into the session to prevent CSRF attacks
        # ref: https://simple-openid-connect.readthedocs.io/en/stable/nonce_and_state.html
        state = secrets.token_urlsafe(32)
        request.session["openid_auth_state"] = state

        # save the time at which authentication was started
        request.session["openid_auth_start_time"] = datetime.now(
            tz=timezone.utc
        ).timestamp()

        # prevent replay attacks by generating and specifying a nonce
        # ref: https://simple-openid-connect.readthedocs.io/en/stable/nonce_and_state.html
        nonce = secrets.token_urlsafe(48)
        request.session["openid_auth_nonce"] = nonce

        # redirect the user-agent to the oidc provider
        client = OpenidAppConfig.get_instance().get_client(request)
        redirect = client.authorization_code_flow.start_authentication(
            state=state, nonce=nonce
        )
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
        # Basic implementation flow is the following:
        # A number of steps are performed in order, each of which may return an HttpResponse object (that displays an error to the user).
        # If such an early response is detected, the whole view terminates early and returns that response.

        # do basic preliminary checks
        if (resp := self.check_auth_state(request)) is not None:
            return resp
        if (resp := self.check_login_timeout(request)) is not None:
            return resp

        # perform exchanges with the identity provider
        if isinstance(
            token_response := self.exchange_code_for_token(request), HttpResponse
        ):
            return token_response
        if isinstance(
            id_token := self.extract_id(request, token_response), HttpResponse
        ):
            return id_token

        # perform the actual login
        self.perform_login(request, token_response, id_token)

        # cleanup session variables used during the login process
        del request.session["openid_auth_start_time"]
        del request.session["openid_auth_state"]
        del request.session["openid_auth_nonce"]

        # redirect to the next get parameter if present, otherwise to the configured default
        if "login_redirect_url" in request.session.keys():
            return HttpResponseRedirect(
                redirect_to=request.session["login_redirect_url"]
            )
        else:
            return HttpResponseRedirect(
                redirect_to=resolve_url(settings.LOGIN_REDIRECT_URL)
            )

    def render_error(
        self,
        request: HttpRequest,
        technical_msg: str,
        technical_description: str,
        **template_ctx: Any,
    ) -> HttpResponse:
        app_settings = OpenidAppConfig.get_instance()
        template_ctx.update(
            {
                "openid_settings": app_settings.safe_settings,
                "auth_redirect_url": app_settings.get_client(
                    request
                ).authentication_redirect_uri,
                "technical_msg": technical_msg,
                "technical_description": technical_description,
            }
        )
        return TemplateResponse(
            request,
            "simple_openid_connect/login_failed.html",
            template_ctx,
            status=HTTPStatus.UNAUTHORIZED,
        )

    def check_auth_state(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Prevent CSRF attacks by verifying the requests state parameter

        ref: https://simple-openid-connect.readthedocs.io/en/stable/nonce_and_state.html
        """
        if request.session.get("openid_auth_state", None) is None:
            return self.render_error(
                request,
                "Invalid state",
                "It is only allowed to finish a login procedure if one has been started before. The state associated with your browser does not indicate that such a login process has been started before and you can therefore not be logged in right now. Please retry and ensure your browser does not delete cookies during naviation.",
            )

        return None

    def check_login_timeout(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Don't allow login completion if the process was started too long ago
        """
        app_settings = OpenidAppConfig.get_instance().safe_settings

        if request.session.get("openid_auth_start_time", None) is None or (
            datetime.now(tz=timezone.utc)
            - datetime.fromtimestamp(
                request.session["openid_auth_start_time"], tz=timezone.utc
            )
        ) > timedelta(seconds=app_settings.OPENID_LOGIN_TIMEOUT):
            return self.render_error(
                request,
                "login process took too long",
                "For security reasons, loging in may only take a certain amount of time. Afterwards, the process must be restarted. This is done to prevent tricking a user into logging in when they did not request it right before.",
            )

        return None

    def exchange_code_for_token(
        self, request: HttpRequest
    ) -> Union[HttpResponse, TokenSuccessResponse]:
        """
        Exchange the code encoded in the current URL for an access token
        """
        client = OpenidAppConfig.get_instance().get_client(request)
        try:
            token_response = (
                client.authorization_code_flow.handle_authentication_result(
                    current_url=request.get_full_path(),
                    state=request.session["openid_auth_state"],
                )
            )
        except AuthenticationFailedError as e:
            return self.render_error(
                request,
                "The Identity-Provider ran into an error during the authentication process",
                "This can happen and is entirely in the discretion of the identity provider. See the additional message below for more info.",
                auth_failed_error=e.error,
            )
        if isinstance(token_response, TokenErrorResponse):
            return self.render_error(
                request,
                str(token_response.error),
                "This application was not able to exchange the *code* it got during the users navigation for proper access tokens. See the additional message below for more info.",
                token_error_response=token_response,
            )
        else:
            return token_response

    def extract_id(
        self, request: HttpRequest, token_response: TokenSuccessResponse
    ) -> Union[HttpResponse, IdToken]:
        """
        Extract the validated ID token from the given token response
        """
        client = OpenidAppConfig.get_instance().get_client(request)
        id_token = IdToken.parse_jwt(token_response.id_token, client.provider_keys)
        try:
            id_token.validate_extern(
                client.provider_config.issuer,
                client.client_auth.client_id,
                nonce=request.session["openid_auth_nonce"],
                min_iat=request.session["openid_auth_start_time"],
            )
            return id_token
        except ValidationError as e:
            return self.render_error(
                request,
                "Invalid ID-Token",
                "This application validates ID-Tokens (user information received from the identity provider) based on the providers cryptographic keys and based on certain properties during authentication. This validation failed for the reason indicated below.",
                id_token_validation_error=e,
            )

    def perform_login(
        self,
        request: HttpRequest,
        token_response: TokenSuccessResponse,
        id_token: IdToken,
    ) -> Any:
        """
        Perform internal user object maintenance and authentication after having performed all external communication

        This handles federated user information (create a new user if necessary or update local info) and logs the user in.
        """
        user = OpenidAppConfig.get_instance().user_mapper.handle_federated_userinfo(
            id_token
        )
        openid_session = user.openid.update_session(token_response, id_token)
        request.session["openid_session"] = openid_session.id
        login(request, user, backend=settings.AUTHENTICATION_BACKENDS[0])


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
