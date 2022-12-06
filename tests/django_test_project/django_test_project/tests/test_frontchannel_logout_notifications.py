import random
import string

from django.shortcuts import resolve_url


def rand_str() -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=16))


def test_bare_request(
    dyn_client, dummy_provider_config, dummy_provider_settings, test_user
):
    # arrange
    dyn_client.force_login(test_user)

    # act
    response = dyn_client.get(
        resolve_url("simple_openid_connect:logout-frontchannel-notify")
    )

    # assert
    assert response.status_code == 200
    assert response["Cache-Control"] == "no-store"
    assert dyn_client.get(resolve_url("test-protected-view")).status_code == 302
