from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse


@login_required
def default_after_login(_request: HttpRequest) -> HttpResponse:
    return HttpResponse(content="default login redirect view")


@login_required
def test_protected_view(request: HttpRequest) -> HttpResponse:
    return HttpResponse(content=f"hello user {request.user.openid.sub}")
