"""
Internal utilities
"""
import cgi

from simple_openid_connect.exceptions import ValidationError


def is_application_json(content_type: str) -> bool:
    """
    Whether the given content type is `application/json`.
    This is needed because mime types can contain additional options which are ignored here.
    """
    main_type, _options = cgi.parse_header(content_type)
    return main_type == "application/json"


def validate_that(condition: bool, msg: str) -> None:
    """
    Validate that the given condition is true, raising a ValidationError with the given message if it is not.

    This is implemented to write concise validating assertions.

    :raises ValidationError: if the condition is false
    """
    if not condition:
        raise ValidationError(msg)
