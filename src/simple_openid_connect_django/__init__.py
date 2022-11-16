from typing import Any

from django.contrib.auth import get_user_model

from simple_openid_connect.data import IdToken


def create_user_from_token(id_token: IdToken) -> Any:
    print("creating new user")
    return get_user_model().objects.create()


def update_user_from_token(user: Any, id_token: IdToken) -> None:
    print("updating existing user")
