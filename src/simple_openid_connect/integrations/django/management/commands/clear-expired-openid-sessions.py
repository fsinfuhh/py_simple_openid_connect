from typing import Any

from django.core.management.base import BaseCommand
from django.db.models import Q
from django.utils import timezone

from simple_openid_connect.integrations.django import models


class Command(BaseCommand):
    help = "Remove expired OpenID Sessions from the database"

    def handle(self, *args: Any, **options: Any) -> Any:
        now = timezone.now()
        qs = models.OpenidSession.objects.filter(
            Q(access_token_expiry__lte=now, refresh_token_expiry__lte=now)
            | Q(access_token_expiry__lte=now, refresh_token="")
        )

        print(f"Deleting {qs.count()} expired sessions")
        qs.delete()
