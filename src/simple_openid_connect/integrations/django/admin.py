from typing import List, Any, Dict, Optional

from django.contrib import admin
from django.http import HttpRequest
from django.contrib.auth import get_user_model
from django.conf import settings

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

    def change_view(
        self,
        request: Any,
        object_id: Any,
        form_url: Any = "",
        extra_context: Optional[Dict[str, Any]] = None,
    ) -> Any:
        # add a settings.DEBUG context variable
        extra_context = extra_context or dict()
        extra_context.setdefault("settings", dict())
        extra_context["settings"]["DEBUG"] = settings.DEBUG and True

        return super().change_view(request, object_id, form_url, extra_context)
