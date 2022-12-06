"""
Automatic OpenAPI schema generation for drf_spectacular.
"""

from typing import TYPE_CHECKING, Any, Dict, List, Union

from drf_spectacular.extensions import OpenApiAuthenticationExtension

if TYPE_CHECKING:
    from drf_spectacular.openapi import AutoSchema

from ..django.apps import OpenidAppConfig
from .authentication import AccessTokenAuthentication


class AccessTokenScheme(OpenApiAuthenticationExtension):  # type: ignore  # ignore missing __init_subclass__ type
    target_class = AccessTokenAuthentication
    name = "openidAccessToken"

    def get_security_definition(
        self, auto_schema: "AutoSchema"
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        return {
            "type": "openIdConnect",
            "description": "Authentication with OpenID Access token",
            "openIdConnectUrl": OpenidAppConfig.get_instance().safe_settings.OPENID_ISSUER
            + "/.well-known/openid-configuration",
        }
