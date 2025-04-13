"""
Default implementations for mapping tokens to user objects.

This implementation can be overriden by extending the :class:`UserMapper` class and then setting the django settings
variable ``OPENID_USER_MAPPER`` to an import string pointing to the newly created class.
"""

import logging
from typing import Any, Tuple, Union

from django.contrib.auth.models import AbstractBaseUser, AbstractUser
from django.db import transaction

from simple_openid_connect.client import OpenidClient
from simple_openid_connect.data import (
    IdToken,
    JwtAccessToken,
    TokenIntrospectionErrorResponse,
    TokenIntrospectionSuccessResponse,
    UserinfoSuccessResponse,
)
from simple_openid_connect.exceptions import ValidationError
from simple_openid_connect.integrations.django.apps import OpenidAppConfig
from simple_openid_connect.integrations.django.models import OpenidUser

logger = logging.getLogger(__name__)

FederatedUserData = Union[
    IdToken, UserinfoSuccessResponse, TokenIntrospectionSuccessResponse, JwtAccessToken
]
"Type alias for the different classes which can provide information about a federated user."


class UserMapper:
    """
    A base class which is responsible for mapping federated users into the local system.
    """

    def handle_federated_userinfo(self, user_data: FederatedUserData) -> Any:
        """
        Entry point for dynamically creating or updating user data based on information obtained through OpenID.

        The function automatically creates a new user model instance if the user is unknown or updates the locally
        stored user information based on the federated data.

        :param user_data: Information about the user.

        :returns: An instance of the applications user model.
        """
        # validate that user data contains at least a user id
        if user_data.sub is None:
            raise ValidationError(
                "could not map user to token because the issuer did not return a 'sub' claim in its token introspection response"
            )

        with transaction.atomic():
            openid_user = OpenidUser.objects.get_or_create_for_sub(user_data.sub)
            user = openid_user.user
            self.automap_user_attrs(user, user_data)
            user.save()
            return user

    def handle_federated_access_token(
        self,
        access_token: str,
        oidc_client: OpenidClient,
        required_scopes: Union[str, None] = None,
    ) -> Tuple[Any, FederatedUserData]:
        """
        Entry point for dynamically creating or updating user data based on an access token which was provided by a user.

        This method inspects the token and then calls into :meth:`UserMapper.handle_federated_userinfo()` once more information
        about the user is available.

        :param access_token: The raw access token that was passed to this application which should identify the user.
        :param oidc_client: An OpenID client which is used to access the OpenID providers signing keys or to introspect the token if necessary.
        :param required_scopes: Scopes to which the access token is required to have access.
            If ``None`` is passed, the default scopes from django settings ``OPENID_SCOPE`` are used.
            Pass an empty string if no scopes are required.

        :returns: An instance of the applications user model as well as additional data about the user.

        :raises ValidationError: If the passed token cannot be validated or is decidedly invalid.
        """
        if required_scopes is None:
            required_scopes = OpenidAppConfig.get_instance().safe_settings.OPENID_SCOPE

        # try to parse the raw token as JWT
        user_data = None  # type: JwtAccessToken | TokenIntrospectionSuccessResponse | None
        try:
            # parse an validate the general token structure
            token = JwtAccessToken.parse_jwt(
                access_token,
                oidc_client.provider_keys,
            )
            token.validate_extern(
                oidc_client.provider_config.issuer,
                oidc_client.client_auth.client_id,
            )

            # validate token scope for required access
            if required_scopes != "":
                if token.scope is None:
                    raise ValidationError(
                        "token does not contain required scopes claim"
                    )
                elif any(
                    i_scope not in token.scope.split(" ")
                    for i_scope in required_scopes.split(" ")
                ):
                    raise ValidationError(
                        f"token has access to scopes '{token.scope}' but '{required_scopes}' are required"
                    )

            # the token is determined to be valid, so we can use it as user_data
            user_data = token

        # fall back to introspecting the token at the issuer
        except Exception:
            logger.debug(
                "could not parse access token as JWT, falling back to calling the providers token introspection endpoint"
            )
            introspect_response = oidc_client.introspect_token(access_token)
            if isinstance(introspect_response, TokenIntrospectionErrorResponse):
                logger.critical(
                    "could not introspect token for validity: %s", introspect_response
                )
                raise ValidationError(
                    f"could not introspect token at the issuer: {introspect_response}"
                )

            # fail if the token is expired
            if not introspect_response.active:
                raise ValidationError("token is expired")

            # validate token scope for required access
            if introspect_response.scope is None:
                logger.error(
                    "could not determine access token access because the issuer did not return the tokens scope during token instrospection"
                )
                raise ValidationError(
                    "could not determine token scope because the issuer did not return the tokens scope during token introspection"
                )
            elif any(
                i_scope not in introspect_response.scope.split(" ")
                for i_scope in required_scopes.split(" ")
            ):
                raise ValidationError(
                    f"token has access to scopes '{introspect_response.scope}' but '{required_scopes}' are required"
                )

            # the token is determined to be valid, so we can use it as user_data
            user_data = introspect_response

        return self.handle_federated_userinfo(user_data), user_data

    def automap_user_attrs(
        self,
        user: "AbstractBaseUser",
        user_data: FederatedUserData,
    ) -> None:
        """
        Inspect the given user instance model, discover its attributes based on some heuristics and set their values
        from the passed user information.

        .. note::

           ``user.save()`` is not automatically called by this method to allow extending it via class inheritance
            without causing multiple database operations.

        :param user: The user instance on which attributes should be set
        :param user_data: Information about the user which was made available through OpenID.
        """
        if isinstance(user, AbstractUser):
            # username
            if hasattr(user_data, "preferred_username"):
                setattr(user, user.USERNAME_FIELD, user_data.preferred_username)
            elif hasattr(user_data, "username"):
                setattr(user, user.USERNAME_FIELD, user_data.username)
            elif hasattr(user_data, "sub"):
                setattr(user, user.USERNAME_FIELD, user_data.sub)
            else:
                logger.warning(
                    "Could not determine a username from federated user data. Creating more than one user will probably fail because the users username attribute is mapped to be empty and django enforces a unique-constraint on usernames."
                )
            # email
            if hasattr(user_data, "email"):
                setattr(user, user.EMAIL_FIELD, user_data.email)
            # given name
            if hasattr(user_data, "given_name") and hasattr(user, "first_name"):
                user.first_name = user_data.given_name
            # family name
            if hasattr(user_data, "family_name") and hasattr(user, "last_name"):
                user.last_name = user_data.family_name
