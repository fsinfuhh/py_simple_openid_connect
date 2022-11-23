from http import HTTPStatus

from django.contrib.auth import login, logout
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.template.response import TemplateResponse
from django.views import View

from simple_openid_connect.data import IdToken, TokenSuccessResponse
from simple_openid_connect_django.apps import OpenidAppConfig
from simple_openid_connect_django.models import OpenidUser


class InitLoginView(View):
    def get(self, request: HttpRequest) -> HttpResponse:
        logout(request)
        client = OpenidAppConfig.get_instance().get_client(request)
        redirect = client.authorization_code_flow.start_authentication()
        return HttpResponseRedirect(redirect)


class LoginCallbackView(View):
    def get(self, request: HttpRequest) -> HttpResponse:
        client = OpenidAppConfig.get_instance().get_client(request)

        token_response = client.authorization_code_flow.handle_authentication_result(
            request.get_raw_uri()
        )
        if not isinstance(token_response, TokenSuccessResponse):
            return TemplateResponse(
                request,
                "simple_openid_connect_django/login_failed.html",
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

        return TemplateResponse(
            request,
            "simple_openid_connect_django/login_success.html",
            {
                "token_response": token_response,
                "id_token": id_token,
            },
            status=HTTPStatus.OK,
        )


class LogoutView(View):
    def get(self, request: HttpRequest) -> HttpResponse:
        client = OpenidAppConfig.get_instance().get_client(request)
        return HttpResponseRedirect(client.initiate_logout())


class LogoutNotificationView(View):
    pass
