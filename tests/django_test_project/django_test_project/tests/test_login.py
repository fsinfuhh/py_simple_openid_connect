import pytest
import requests
from django.shortcuts import resolve_url
from requests.exceptions import ConnectionError


def is_provider_running() -> bool:
    try:
        requests.get("http://localhost:3000")
        return True
    except ConnectionError:
        return False


@pytest.mark.skipif(not is_provider_running(), reason="dummy provider not running")
def test_directly_calling_login_endpoint(dummy_ua, live_server):
    # initiate login
    init_response = dummy_ua.naviagte_to(
        live_server + resolve_url("simple_openid_connect:login")
    )
    assert init_response.ok

    # perform login and give consent on the provider
    login_callback = dummy_ua.login_to_dummy_provider(init_response.url)

    # assert the page can now be accessed
    login_response = dummy_ua.naviagte_to(live_server + login_callback)
    assert login_response.ok
    assert login_response.content == b"default login redirect view"


@pytest.mark.skipif(not is_provider_running(), reason="dummy provider not running")
def test_directly_accessing_protected_resource(dummy_ua, live_server):
    # initiate login by accessing a protected resource
    init_response = dummy_ua.naviagte_to(
        live_server + resolve_url("test-protected-view")
    )
    assert init_response.ok

    # perform login and give consent on the provider
    login_callback = dummy_ua.login_to_dummy_provider(init_response.url)
    login_response = dummy_ua.naviagte_to(live_server + login_callback)

    # assert
    assert login_response.ok
    assert login_response.content == b"hello user test"
