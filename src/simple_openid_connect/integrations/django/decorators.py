"""
View-function decorators
"""

import logging
from functools import wraps
from http import HTTPStatus
from typing import Any, Callable, Optional, TypeVar, Union

from django.http import HttpRequest, HttpResponse, JsonResponse

from simple_openid_connect.exceptions import ValidationError
from simple_openid_connect.integrations.django.apps import OpenidAppConfig
from simple_openid_connect.utils import is_application_json

logger = logging.getLogger(__name__)

View_Return = TypeVar("View_Return", bound=HttpResponse)


def _invalid_token_response(request: HttpRequest) -> HttpResponse:
    if "Accept" in request.headers.keys() and is_application_json(
        request.headers["Accept"]
    ):
        return JsonResponse(
            status=HTTPStatus.UNAUTHORIZED,
            headers={"WWW-Authenticate": "Bearer"},
            data={
                "error": "invalid_token",
                "error_description": "the used access token is not valid or does not grant enough access",
            },
        )
    else:
        return HttpResponse(
            status=HTTPStatus.UNAUTHORIZED,
            content="the used access token is not valid or does not grant enough access",
            headers={"WWW-Authenticate": "Bearer"},
        )


def access_token_required(
    *, required_scopes: Optional[str] = None
) -> Callable[..., Union[HttpResponse, View_Return]]:
    """
    Decorator for views that checks that the request is authenticated using a valid access token, early-returning an
    appropriate http error response if necessary.

    :param required_scopes: Scopes to which the access token needs to have access.
        If not given, use the `settings.OPENID_SCOPE` value which defaults to "openid".

    :raises UnsupportedByProviderError: If the provider does not support token introspection.
    """
    if required_scopes is None:
        _required_scopes = OpenidAppConfig.get_instance().safe_settings.OPENID_SCOPE
    else:
        _required_scopes = required_scopes

    def actual_decorator(
        view_func: Callable[..., View_Return],
    ) -> Callable[..., View_Return]:
        @wraps(view_func)
        def wrapped_view(
            request: HttpRequest, *args: Any, **kwargs: Any
        ) -> Union[HttpResponse, View_Return]:
            # verify that an Authorization Header of type Bearer is present
            if "Authorization" not in request.headers.keys() or not request.headers[
                "Authorization"
            ].startswith("Bearer "):
                return HttpResponse(
                    status=HTTPStatus.UNAUTHORIZED,
                    headers={"WWW-Authenticate": "Bearer"},
                )

            oidc_client = OpenidAppConfig.get_instance().get_client(request)
            raw_token = request.headers["Authorization"].split(" ", 1)[1]

            try:
                (
                    request.user,
                    _,
                ) = OpenidAppConfig.get_instance().user_mapper.handle_federated_access_token(
                    raw_token, oidc_client, _required_scopes
                )
            except ValidationError:
                return _invalid_token_response(request)

            # execute the decorated view function
            return view_func(request, *args, **kwargs)

        return wrapped_view  # type: ignore

    return actual_decorator  # type: ignore
