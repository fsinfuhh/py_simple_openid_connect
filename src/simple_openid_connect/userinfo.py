"""
Userinfo implementation
"""

from typing import Literal, Union

import requests

from simple_openid_connect import utils
from simple_openid_connect.client_authentication import AccessTokenBearerAuth
from simple_openid_connect.data import (
    UserinfoErrorResponse,
    UserinfoRequest,
    UserinfoSuccessResponse,
)
from simple_openid_connect.exceptions import OpenidProtocolError


def fetch_userinfo(
    userinfo_endpoint: str,
    access_token: str,
    http_method: Literal["GET", "POST"] = "GET",
) -> Union[UserinfoSuccessResponse, UserinfoErrorResponse]:
    request = UserinfoRequest()
    auth = AccessTokenBearerAuth(access_token)

    if http_method == "GET":
        response = requests.get(request.encode_url(userinfo_endpoint), auth=auth)
    elif http_method == "POST":
        response = requests.post(
            userinfo_endpoint, request.encode_x_www_form_urlencoded(), auth=auth
        )
    else:
        raise ValueError(f"argument http_method has unsupported value {http_method}")

    if not utils.is_application_json(response.headers["Content-Type"]):
        raise OpenidProtocolError(
            "userinfo request was responded with invalid Content-Type", response
        )

    if response.status_code == 200:
        return UserinfoSuccessResponse.model_validate_json(response.content)
    else:
        return UserinfoErrorResponse.model_validate_json(response.content)
