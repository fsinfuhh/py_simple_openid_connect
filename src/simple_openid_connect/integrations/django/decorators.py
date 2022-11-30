"""
View-function decorators
"""

import logging
from functools import wraps
from http import HTTPStatus
from typing import Any, Callable, TypeVar, Union

from django.http import HttpRequest, HttpResponse, JsonResponse

from simple_openid_connect.data import TokenIntrospectionErrorResponse
from simple_openid_connect.integrations.django.apps import OpenidAppConfig
from simple_openid_connect.utils import is_application_json

logger = logging.getLogger(__name__)

View_Return = TypeVar("View_Return", bound=HttpResponse)


def access_token_required(
    *, required_scopes: str = "openid"
) -> Callable[..., Union[HttpResponse, View_Return]]:
    """
    Decorator for views that checks that the request is authenticated using a valid access token, early-returning an
    appropriate http error response if necessary.

    :param required_scopes: Scopes to which the access token needs to have access

    :raises UnsupportedByProviderError: If the provider does not support token introspection.
    """

    def actual_decorator(
        view_func: Callable[..., View_Return]
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

            # introspect passed token
            token = request.headers["Authorization"].split(" ", 1)[1]
            oidc_client = OpenidAppConfig.get_instance().get_client(request)
            result = oidc_client.introspect_token(token)

            if isinstance(result, TokenIntrospectionErrorResponse):
                logger.critical("could not introspect token for validity: %s", result)
                return HttpResponse(status=HTTPStatus.INTERNAL_SERVER_ERROR)

            # FIXME: This fails if the token is inactive because then it might have no scope
            if result.scope is None:
                logger.critical(
                    "could not determine access because token introspection did not return token scopes"
                )
                return HttpResponse(status=HTTPStatus.INTERNAL_SERVER_ERROR)

            # directly return a http response if the token is not valid
            if not result.active or any(
                scope not in result.scope.split(" ")
                for scope in required_scopes.split(" ")
            ):
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

            # execute the decorated view function
            return view_func(request, *args, **kwargs)

        return wrapped_view  # type: ignore

    return actual_decorator  # type: ignore
