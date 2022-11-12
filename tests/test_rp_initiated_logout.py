from hypothesis import given

from simple_openid_connect import rp_initiated_logout
from simple_openid_connect.data import RpInitiatedLogoutRequest


def test_without_request():
    # act
    url = rp_initiated_logout.initiate_logout("https://example.com/logout")

    # assert
    assert url == "https://example.com/logout"


@given(request=...)
def test_with_request(request: RpInitiatedLogoutRequest):
    # act
    url = rp_initiated_logout.initiate_logout("https://example.com/logout", request)

    # assert
    assert url == request.encode_url("https://example.com/logout")
