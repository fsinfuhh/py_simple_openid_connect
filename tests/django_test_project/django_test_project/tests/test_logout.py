from django.shortcuts import resolve_url


def test_logout_redirects_to_op(
    dummy_provider_settings, dyn_client, dummy_provider_config
):
    # act
    response = dyn_client.get(resolve_url("simple_openid_connect:logout"))

    # assert
    assert response.status_code == 302
    assert response.url == "https://provider.example.com/end-session"


def test_session_ended_after_logout_view(
    dyn_client, test_user, dummy_provider_settings, dummy_provider_config
):
    # arrange
    dyn_client.force_login(test_user)

    # act
    response = dyn_client.get(resolve_url("simple_openid_connect:logout"))

    # assert
    assert not response.wsgi_request.user.is_authenticated
