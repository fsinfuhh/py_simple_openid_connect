from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse

from simple_openid_connect.integrations.django.decorators import access_token_required


@login_required
def default_after_login(_request: HttpRequest) -> HttpResponse:
    return HttpResponse(content="default login redirect view")


@login_required
def test_protected_view(request: HttpRequest) -> HttpResponse:
    return HttpResponse(content=f"hello user {request.user.openid.sub}")


@access_token_required()
def test_access_token_view(_request: HttpRequest) -> HttpResponse:
    return HttpResponse(content="access granted")
