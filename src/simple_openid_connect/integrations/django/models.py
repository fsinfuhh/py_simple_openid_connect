"""
simple_openid_connect database models
"""

from datetime import datetime, timedelta
from typing import Optional

from django.contrib.auth import get_user_model
from django.db import models
from django.utils import timezone

from simple_openid_connect.data import IdToken, TokenSuccessResponse


def _calc_expiry(t: Optional[int]) -> Optional[datetime]:
    if t is not None:
        return timezone.now() + timedelta(seconds=t)
    return None


class OpenidUserManager(models.Manager["OpenidUser"]):
    """
    Custom user manager for the :class:`OpenidUser` model.
    """

    def get_or_create_for_sub(self, sub: str) -> "OpenidUser":
        """
        Dynamically get the existing model instance from the provided subject or create a new one if none already exists.

        This method also ensures that a django auth model user exists which is linked to this OpenidUser.
        """
        user_t = get_user_model()
        queryset = self.filter(sub=sub)
        if queryset.exists():
            return queryset.get()
        else:
            user = user_t.objects.create()
            return self.create(user=user, sub=sub)


class OpenidUser(models.Model):
    """
    A model which holds user related openid data.

    It is related to the user model instances via the `openid` relation.
    """

    objects = OpenidUserManager()

    sub = models.CharField(
        max_length=255,
        primary_key=True,
        help_text="subject identifier of this user (userid)",
    )
    user = models.OneToOneField(
        to=get_user_model(), on_delete=models.CASCADE, related_name="openid"
    )

    def update_session(
        self, token_response: TokenSuccessResponse, id_token: IdToken
    ) -> "OpenidSession":
        """
        Update session information based on the given openid token response.

        If the token contains a session id, that session is updated with newer information and if not, a new session
        object is created.
        """

        # update the existing session if possible
        if id_token.sid is not None:
            query = OpenidSession.objects.filter(sid=id_token.sid)
            if query.exists():
                session = query.get()  # type: OpenidSession
                session.update_session(token_response)
                session.id_token = id_token
                session.save()
                return session

        # fall back to creating a new session
        return OpenidSession.objects.create(
            user=self,
            sid=id_token.sid or "",
            scope=str(token_response.scope),
            access_token=token_response.access_token,
            access_token_expiry=_calc_expiry(token_response.expires_in),
            refresh_token=token_response.refresh_token or "",
            refresh_token_expiry=_calc_expiry(token_response.refresh_expires_in),
            _id_token=id_token.model_dump_json(),  # type: ignore[unused-ignore,misc]
            raw_id_token=token_response.id_token,
        )


class OpenidSession(models.Model):
    """
    A model to hold openid session information.
    """

    user = models.ForeignKey(
        to=OpenidUser, on_delete=models.CASCADE, db_index=True, related_name="sessions"
    )
    sid = models.CharField(
        max_length=256, blank=True, db_index=True, help_text="session id"
    )
    scope = models.CharField(max_length=256)
    access_token = models.TextField()
    access_token_expiry = models.DateTimeField(null=True)
    refresh_token = models.TextField(blank=True)
    refresh_token_expiry = models.DateTimeField(null=True)
    _id_token = models.TextField("json representation of this sessions is token")
    raw_id_token = models.TextField(blank=True)

    @property
    def id_token(self) -> IdToken:
        return IdToken.model_validate_json(self._id_token)

    @id_token.setter
    def id_token(self, value: IdToken) -> None:
        self._id_token = value.json()

    def update_session(self, token_response: TokenSuccessResponse) -> None:
        self.scope = str(token_response.scope)
        self.access_token = token_response.access_token
        self.access_token_expiry = _calc_expiry(token_response.expires_in)
        self.refresh_token = token_response.refresh_token or ""
        self.refresh_token_expiry = _calc_expiry(token_response.refresh_expires_in)
        self.raw_id_token = token_response.id_token
