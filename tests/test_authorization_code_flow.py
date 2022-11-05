from simple_openid.flows import authorization_code_flow


def test_authorization_request(dummy_ua, dummy_openid_provider, dummy_app_server):
    # act
    url = authorization_code_flow.start_authentication(
        dummy_openid_provider.endpoints["authorization"],
        "openid",
        dummy_openid_provider.test_client_id,
        dummy_app_server.callback_url,
    )
    response = dummy_ua.naviagte_to(url)

    # assert
    response_msg = authorization_code_flow.AuthenticationSuccessResponse.parse_url(
        response.url
    )
    assert response_msg.code is not None
    assert response_msg.code != ""
