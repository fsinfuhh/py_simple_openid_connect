"""
Implementation of Relying-Party initiated logout
"""

from simple_openid_connect.data import RpInitiatedLogoutRequest


def initiate_logout(
    logout_endpoint: str, request: RpInitiatedLogoutRequest = None
) -> str:
    """
    Initiate user logout as a Relying-Party

    :param logout_endpoint: The OPs `end_session_endpoint`
    :param request: Additional data pertaining to the logout

    :returns: A url to which the user should be redirected
    """
    if request is not None:
        return request.encode_url(logout_endpoint)
    else:
        return logout_endpoint
