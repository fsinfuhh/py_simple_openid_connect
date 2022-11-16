from datetime import datetime, timedelta
from typing import Optional

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import models
from django.utils import timezone

from simple_openid_connect.data import IdToken, TokenSuccessResponse
from simple_openid_connect_django.apps import OpenidAppConfig


class OpenidUserManager(models.Manager["OpenidUser"]):
    def get_or_create_from_id_token(self, id_token: IdToken) -> "OpenidUser":
        queryset = self.filter(sub=id_token.sub)
        if queryset.exists():
            # update existing objects
            openid_user = queryset.get()
            openid_user.id_token = id_token
            openid_user.save()
            OpenidAppConfig.get_instance().update_user_func(openid_user.user, id_token)
            return openid_user
        else:
            # create new objects
            user = OpenidAppConfig.get_instance().create_user_func(id_token)
            openid_user = self.create(
                user=user, sub=id_token.sub, _id_token=id_token.json()
            )
            return openid_user


class OpenidUser(models.Model):
    objects = OpenidUserManager()

    sub = models.CharField(
        max_length=255,
        primary_key=True,
        help_text="subject identifier of this user (userid)",
    )
    user = models.OneToOneField(
        to=get_user_model(), on_delete=models.CASCADE, related_name="openid"
    )
    _id_token = models.TextField(
        help_text="json representation of the most current id token"
    )

    @property
    def id_token(self) -> IdToken:
        return IdToken.parse_raw(self._id_token)

    @id_token.setter
    def id_token(self, value: IdToken) -> None:
        self._id_token = value.json()

    def update_session(self, token_response: TokenSuccessResponse) -> None:
        def calc_expiry(t: Optional[int]) -> Optional[datetime]:
            if t is not None:
                return timezone.now() + timedelta(seconds=t)
            return None

        # update the existing session if possible
        if self.id_token.sid is not None:
            query = OpenidSession.objects.filter(sid=self.id_token.sid)
            if query.exists():
                session = query.get()  # type: OpenidSession
                session.scope = str(token_response.scope)
                session.access_token = token_response.access_token
                session.access_token_expiry = calc_expiry(token_response.expires_in)
                session.refresh_token = token_response.refresh_token or ""
                session.refresh_token_expiry = calc_expiry(
                    token_response.refresh_expires_in
                )
                return

        # fall back to creating a new session
        OpenidSession.objects.create(
            user=self,
            sid=self.id_token.sid or "",
            scope=str(token_response.scope),
            access_token=token_response.access_token,
            access_token_expiry=calc_expiry(token_response.expires_in),
            refresh_token=token_response.refresh_token or "",
            refresh_token_expiry=calc_expiry(token_response.refresh_expires_in),
        )


class OpenidSession(models.Model):
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
