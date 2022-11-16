from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.views import View

from simple_openid_connect.data import IdToken, TokenSuccessResponse
from simple_openid_connect_django.apps import OpenidAppConfig


class InitLoginView(View):
    def get(self, request: HttpRequest) -> HttpResponse:
        client = OpenidAppConfig.get_instance().get_client(request)
        redirect = client.authorization_code_flow.start_authentication()
        print(redirect)
        return HttpResponseRedirect(redirect)


class LoginCallbackView(View):
    def get(self, request: HttpRequest) -> HttpResponse:
        client = OpenidAppConfig.get_instance().get_client(request)

        token_response = client.authorization_code_flow.handle_authentication_result(
            request.get_raw_uri()
        )
        assert isinstance(token_response, TokenSuccessResponse)

        id_token = IdToken.parse_jwt(token_response.id_token, client.provider_keys)
        id_token.validate_extern(
            client.provider_config.issuer, client.client_auth.client_id
        )

        return JsonResponse(
            {
                "token_response": token_response.dict(),
                "id_token": id_token.dict(),
            }
        )


class LogoutView(View):
    def get(self, request: HttpRequest) -> HttpResponse:
        client = OpenidAppConfig.get_instance().get_client(request)
        return HttpResponseRedirect(client.initiate_logout())


class LogoutNotificationView(View):
    pass
