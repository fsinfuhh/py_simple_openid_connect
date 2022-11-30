"""
Default implementations for mapping tokens to user objects
"""

from typing import Any, Mapping, Type

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractBaseUser, AbstractUser

from simple_openid_connect.data import IdToken


def automap_user_attrs(
    user_t: Type["AbstractBaseUser"], id_token: IdToken
) -> Mapping[str, Any]:
    """
    Inspect the given user model, discover its attributes based on some heuristics and fetch their values from the id token.

    :param user_t: The user model type
    :param id_token: The id token which contains information about the user

    :return: A mapping of user model attribute to values as found in the id token
    """
    result = {}

    if issubclass(user_t, AbstractUser):
        # username
        if hasattr(id_token, "preferred_username"):
            result[user_t.USERNAME_FIELD] = id_token.preferred_username
        # email
        if hasattr(id_token, "email"):
            result[user_t.EMAIL_FIELD] = id_token.email
        # given name
        if hasattr(id_token, "given_name"):
            result["first_name"] = id_token.given_name
        # family name
        if hasattr(id_token, "family_name"):
            result["last_name"] = id_token.family_name

    return result


def create_user_from_token(id_token: IdToken) -> Any:
    """
    Implementation for creating a user object from an id token.

    It works by calling :func:`automap_user_attrs` with the token and passing that to the user models `objects.create()` method.

    :param id_token: The id token

    :returns: The created user object
    """
    user_t = get_user_model()
    user_attrs = automap_user_attrs(user_t, id_token)
    return user_t.objects.create(**user_attrs)


def update_user_from_token(user: Any, id_token: IdToken) -> None:
    """
    Implementation for updating an existing user object with new data

    This works by calling :func:`automap_user_attrs` with the token and setting all those attributes on the user object.

    :param user: The user object that should be updated.
    :param id_token: The token which contains user information.
    """
    user_t = get_user_model()
    user_attrs = automap_user_attrs(user_t, id_token)
    for name, value in user_attrs.items():
        setattr(user, name, value)
    user.save()
