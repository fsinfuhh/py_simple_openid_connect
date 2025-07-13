from typing import List

from django.contrib import admin
from django.http import HttpRequest
from django.contrib.auth import get_user_model

from . import models


class OpenidSessionAdmin(admin.options.InlineModelAdmin):  # type: ignore[type-arg]
    model = models.OpenidSession
    ordering = ["-access_token_expiry"]
    extra = 0
    template = "simple_openid_connect/admin/openid_session_inline.html"


@admin.register(models.OpenidUser)
class OpenidUserAdmin(admin.ModelAdmin):  # type: ignore[type-arg]
    actions = None
    list_display = ["__str__", "user"]
    readonly_fields = ["sub", "user"]
    inlines = [OpenidSessionAdmin]

    search_help_text = "Search for the user by sub (OpenID ID), username or email"

    def get_search_fields(self, request: HttpRequest) -> List[str]:
        result = ["sub"]

        UserModel = get_user_model()
        if hasattr(UserModel, "USERNAME_FIELD"):
            result.append(f"user__{UserModel.USERNAME_FIELD}")

        if hasattr(UserModel, "EMAIL_FIELD"):
            result.append(f"user__{UserModel.EMAIL_FIELD}")

        return result
