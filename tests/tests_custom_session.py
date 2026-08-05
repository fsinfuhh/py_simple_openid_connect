import requests
import responses
import responses.matchers
from simple_openid_connect.client import OpenidClient

CUSTOM_HEADER = "x-custom-test-header"
CUSTOM_HEADER_VALUE = "this header should be present"


def make_client() -> OpenidClient:
    session = requests.Session()
    # this client always sends this custom header
    session.headers = {CUSTOM_HEADER: CUSTOM_HEADER_VALUE}
    return OpenidClient.from_issuer_url(
        url="https://provider.example.com",
        authentication_redirect_uri="https://app.example.com/login-callback",
        client_id="test-client-id",
        client_secret="test-client-secret",
        session=session,
    )


def test_full_authorization_code_flow_with_custom_header(
    user_agent,
    dummy_provider_config,
    dummy_auth_response,
    dummy_token_response,
    response_mock: responses.RequestsMock,
):
    # change all existing mocked responses to raise an exception if the client does not present CUSTOM_HEADER
    for response in response_mock.registered():
        response.match = tuple(response.match) + (
            responses.matchers.header_matcher({CUSTOM_HEADER: CUSTOM_HEADER_VALUE}),
        )

    # now perform authentication once to check that the client really sends the header
    client = make_client()
    response = user_agent.naviagte_to(
        client.authorization_code_flow.start_authentication(),
        headers={CUSTOM_HEADER: CUSTOM_HEADER_VALUE},
    )
    result = client.authorization_code_flow.handle_authentication_result(response.url)

    # assert
    assert result.access_token
    assert result.id_token
