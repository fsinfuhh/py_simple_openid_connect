"""
Internal utilities
"""
import cgi


def is_application_json(content_type: str) -> bool:
    """
    Whether the given content type is `application/json`.
    This is needed because mime types can contain additional options which are ignored here.
    """
    main_type, _options = cgi.parse_header(content_type)
    return main_type == "application/json"
