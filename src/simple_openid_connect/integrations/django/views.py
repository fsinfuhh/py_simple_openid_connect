"""
View functions which handle openid authentication and their related callbacks
"""

from http import HTTPStatus
from typing import Mapping

from django.conf import settings
from django.contrib.auth import login, logout
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import resolve_url
from django.template.response import TemplateResponse
from django.views import View

from simple_openid_connect.data import IdToken, TokenSuccessResponse
from simple_openid_connect.integrations.django.apps import OpenidAppConfig
from simple_openid_connect.integrations.django.models import OpenidUser


def _get_redirect_args(request: HttpRequest) -> Mapping[str, str]:
    """
    Calculate arguments which are appended to the redirect_uri
    """
    if "next" in request.GET.keys():
        return {
            "next": request.GET["next"],
        }
    return {}


class InitLoginView(View):
    """
    The view which handles initiating a login.

    It essentially redirects the user agent to the Openid provider.
    """

    def get(self, request: HttpRequest) -> HttpResponse:
        logout(request)
        client = OpenidAppConfig.get_instance().get_client(request)
        redirect = client.authorization_code_flow.start_authentication(
            additional_redirect_args=_get_redirect_args(request),
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
        client = OpenidAppConfig.get_instance().get_client(request)

        token_response = client.authorization_code_flow.handle_authentication_result(
            current_url=request.get_full_path(),
            additional_redirect_args=_get_redirect_args(request),
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

        id_token = IdToken.parse_jwt(token_response.id_token, client.provider_keys)
        id_token.validate_extern(
            client.provider_config.issuer, client.client_auth.client_id
        )

        user = OpenidUser.objects.get_or_create_from_id_token(id_token)
        user.update_session(token_response)
        login(request, user.user)

        # redirect to the next get parameter if present, otherwise to the configured default
        if "next" in request.GET.keys():
            return HttpResponseRedirect(redirect_to=request.GET["next"])
        else:
            return HttpResponseRedirect(
                redirect_to=resolve_url(settings.LOGIN_REDIRECT_URL)
            )


class LogoutView(View):
    """
    The view which handles logging a user out.
    """

    def get(self, request: HttpRequest) -> HttpResponse:
        client = OpenidAppConfig.get_instance().get_client(request)
        return HttpResponseRedirect(client.initiate_logout())
