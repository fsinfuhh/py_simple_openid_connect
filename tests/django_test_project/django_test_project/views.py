from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse


@login_required
def debug_view(request: HttpRequest) -> HttpResponse:
    return HttpResponse(content=f"All is fine {request.user}")
