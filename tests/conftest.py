import logging
import random
import string
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable, Dict, List, Mapping, Tuple

import pytest
import requests
import responses
from furl import furl
from requests import PreparedRequest

from simple_openid.data import ProviderMetadata
from simple_openid.flows.authorization_code_flow import (
    AuthenticationRequest,
    AuthenticationSuccessResponse,
    TokenErrorResponse,
    TokenRequest,
    TokenSuccessResponse,
)

logger = logging.getLogger(__name__)


def rand_str() -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=16))


class DummyOpenidProvider:
    iss = "https://provider.example.com/openid-connect"
    endpoints = {
        "authorization": f"{iss}/client_auth",
        "token": f"{iss}/token",
    }

    test_client_id = "test-client"
    test_client_secret = "foobar123"
    test_client_redirect_uri = "https://app.example.com/auth/callback"

    cheat_code = "master access code which can always be exchanged for tokens"

    _valid_auth_codes: List[str]

    def __init__(self, requests_mock: responses.RequestsMock):
        self._valid_auth_codes = []
        self.setup_authorization_endpoint(requests_mock)
        self.setup_token_endpoint(requests_mock)

    def setup_authorization_endpoint(self, requests_mock: responses.RequestsMock):
        def callback(request: PreparedRequest) -> Tuple[int, Dict[str, str], str]:
            request_url = furl(request.url)
            auth_request = AuthenticationRequest.parse_x_www_form_urlencoded(
                request_url.query.encode()
            )

            code = rand_str()
            self._valid_auth_codes.append(code)
            response = AuthenticationSuccessResponse(
                code=code, state=auth_request.state
            )

            return 301, {"Location": response.encode_url(auth_request.redirect_uri)}, ""

        requests_mock.add_callback(
            method=responses.GET,
            url=self.endpoints["authorization"],
            callback=callback,
        )

    def setup_token_endpoint(self, requests_mock: responses.RequestsMock):
        def callback(request: PreparedRequest) -> Tuple[int, Dict[str, str], str]:
            request_msg = TokenRequest.parse_x_www_form_urlencoded(request.body)
            if request_msg.code == self.cheat_code:
                return (
                    200,
                    {},
                    TokenSuccessResponse(
                        access_token=rand_str(),
                        token_type="Bearer",
                        id_token=rand_str(),
                    ).json(),
                )
            elif request_msg.code in self._valid_auth_codes:
                self._valid_auth_codes.remove(request_msg.code)
                return (
                    200,
                    {},
                    TokenSuccessResponse(
                        access_token=rand_str(),
                        token_type="Bearer",
                        id_token=rand_str(),
                    ).json(),
                )
            else:
                return (
                    400,
                    {},
                    TokenErrorResponse(
                        error=TokenErrorResponse.ErrorType.invalid_grant,
                        error_description="token is invalid",
                    ).json(),
                )

        requests_mock.add_callback(
            method=responses.POST,
            url=self.endpoints["token"],
            callback=callback,
            content_type="application/json",
        )


@pytest.fixture
def dummy_openid_provider(
    mocked_responses: responses.RequestsMock,
) -> DummyOpenidProvider:
    yield DummyOpenidProvider(mocked_responses)


class DummyUserAgent:
    def naviagte_to(self, url: str) -> requests.Response:
        """
        Mimic navigating to the given URL
        """
        return requests.get(url, allow_redirects=True)


@pytest.fixture
def dummy_ua() -> DummyUserAgent:
    yield DummyUserAgent()


class DummyAppServer:
    callback_url = "https://app.example.com/auth/callback"

    def __init__(self, requests_mock: responses.RequestsMock):
        requests_mock.get(
            url=self.callback_url,
            status=200,
            body="dumm app server callback response",
        )


@pytest.fixture
def dummy_app_server(
    mocked_responses: responses.RequestsMock, dummy_openid_provider: DummyOpenidProvider
) -> DummyAppServer:
    return DummyAppServer(mocked_responses)


class RealAppServer(HTTPServer):
    login_url = "http://127.0.0.1:8000/login"
    login_callback_url = "http://127.0.0.1:8000/callback"

    _on_login = None
    _on_login_callback = None

    _is_done = False

    def __init__(self):
        super().__init__(
            ("127.0.0.1", 8000), self.RequestHandler, bind_and_activate=True
        )

    def serve_until_done(
        self,
        on_login: Callable[[furl], Tuple[int, Mapping[str, str], str]],
        on_login_callback: Callable[[furl], Tuple[int, Mapping[str, str], str]],
    ):
        self._on_login = on_login
        self._on_login_callback = on_login_callback
        while not self._is_done:
            self.handle_request()

    def done(self):
        self._is_done = True

    def handle_error(self, request, client_address) -> None:
        # re-raise exceptions so that they can fail the test
        raise sys.exc_info()[1]

    class RequestHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            url = furl(self.path)
            if url.path == "/login":
                response = self.server._on_login(url)
            elif url.path == "/callback":
                response = self.server._on_login_callback(url)
            else:
                response = 404, {}, "Not found"

            self.send_response(response[0])
            for k, v in response[1].items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(response[2].encode("UTF-8"))


@pytest.fixture
def real_app_server() -> RealAppServer:
    server = RealAppServer()
    yield server
    server.done()


@pytest.fixture
def mocked_responses():
    """
    A context manager that mocks and de-mocks http request responses
    """
    with responses.RequestsMock(assert_all_requests_are_fired=False) as mock:
        yield mock


@pytest.fixture
def mock_known_provider_configs(mocked_responses: responses.RequestsMock):
    """
    Mock requests to known OpenID provider config URLs to return static content
    """
    mocked_responses.get(
        url="https://example.com/not-found/.well-known/openid-configuration",
        content_type="text/plain",
        body="Issuer config not found",
        status=404,
    )
    mocked_responses.get(
        url="https://example.com/invalid-json-document/.well-known/openid-configuration",
        content_type="application/json",
        body="{ 'hello': 'world' }",
    )
    mocked_responses.get(
        url="https://example.com/invalid-json-syntax/.well-known/openid-configuration",
        content_type="application/json",
        body="{ 'hello }",
    )

    mocked_responses.get(
        url="https://provider.example.com/openid-connect/.well-known/openid-configuration",
        json=ProviderMetadata(
            issuer="https://provider.example.com/openid-connect",
            authorization_endpoint="https://provider.example.com/openid-connect/client_auth",
            token_endpoint="https://provider.example.com/openid-connect/token",
            jwks_uri="https://provider.example.com/openid-connect/jwks",
            subject_types_supported=["public"],
            id_token_signing_alg_values_supported=["RS256"],
        ).dict(exclude_defaults=True),
    )

    mocked_responses.get(
        url="https://identity.mafiasi.de/auth/realms/mafiasi/.well-known/openid-configuration",
        content_type="application/json",
        body='{"issuer":"https://identity.mafiasi.de/auth/realms/mafiasi","authorization_endpoint":"https://identity.mafiasi.de/auth/realms/mafiasi/protocol/openid-connect/auth","token_endpoint":"https://identity.mafiasi.de/auth/realms/mafiasi/protocol/openid-connect/token","introspection_endpoint":"https://identity.mafiasi.de/auth/realms/mafiasi/protocol/openid-connect/token/introspect","userinfo_endpoint":"https://identity.mafiasi.de/auth/realms/mafiasi/protocol/openid-connect/userinfo","end_session_endpoint":"https://identity.mafiasi.de/auth/realms/mafiasi/protocol/openid-connect/logout","jwks_uri":"https://identity.mafiasi.de/auth/realms/mafiasi/protocol/openid-connect/certs","check_session_iframe":"https://identity.mafiasi.de/auth/realms/mafiasi/protocol/openid-connect/login-status-iframe.html","grant_types_supported":["authorization_code","implicit","refresh_token","password","client_credentials"],"response_types_supported":["code","none","id_token","token","id_token token","code id_token","code token","code id_token token"],"subject_types_supported":["public","pairwise"],"id_token_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"id_token_encryption_alg_values_supported":["RSA-OAEP","RSA1_5"],"id_token_encryption_enc_values_supported":["A256GCM","A192GCM","A128GCM","A128CBC-HS256","A192CBC-HS384","A256CBC-HS512"],"userinfo_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512","none"],"request_object_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512","none"],"response_modes_supported":["query","fragment","form_post"],"registration_endpoint":"https://identity.mafiasi.de/auth/realms/mafiasi/clients-registrations/openid-connect","token_endpoint_auth_methods_supported":["private_key_jwt","client_secret_basic","client_secret_post","tls_client_auth","client_secret_jwt"],"token_endpoint_auth_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"claims_supported":["aud","sub","iss","auth_time","name","given_name","family_name","preferred_username","email","acr"],"claim_types_supported":["normal"],"claims_parameter_supported":false,"scopes_supported":["openid","offline_access","profile","email","address","phone","roles","web-origins","microprofile-jwt","shortlinks","dev-scope"],"request_parameter_supported":true,"request_uri_parameter_supported":true,"code_challenge_methods_supported":["plain","S256"],"tls_client_certificate_bound_access_tokens":true}',
    )
    mocked_responses.get(
        "https://accounts.google.com/.well-known/openid-configuration",
        content_type="application/json",
        body='{"issuer":"https://accounts.google.com","authorization_endpoint":"https://accounts.google.com/o/oauth2/v2/auth","device_authorization_endpoint":"https://oauth2.googleapis.com/device/code","token_endpoint":"https://oauth2.googleapis.com/token","userinfo_endpoint":"https://openidconnect.googleapis.com/v1/userinfo","revocation_endpoint":"https://oauth2.googleapis.com/revoke","jwks_uri":"https://www.googleapis.com/oauth2/v3/certs","response_types_supported":["code","token","id_token","code token","code id_token","token id_token","code token id_token","none"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"scopes_supported":["openid","email","profile"],"token_endpoint_auth_methods_supported":["client_secret_post","client_secret_basic"],"claims_supported":["aud","email","email_verified","exp","family_name","given_name","iat","iss","locale","name","picture","sub"],"code_challenge_methods_supported":["plain","S256"],"grant_types_supported":["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:device_code","urn:ietf:params:oauth:grant-type:jwt-bearer"]}',
    )


@pytest.fixture
def mock_known_provider_jwks(mocked_responses: responses.RequestsMock):
    mocked_responses.get(
        url="https://identity.mafiasi.de/auth/realms/mafiasi/protocol/openid-connect/certs",
        content_type="application/json",
        body='{"keys":[{"kid":"P9ONvIAIs3TvrQ9Qh_CArFhJXXN3uJrS-kiEcBbt8Ug","kty":"RSA","alg":"RS256","use":"sig","n":"jHVV2sZrujEZQv22fPKScSPyF-JKL6TrWDoztwRGwrxbiTd0nN7bNb9vGDxhqjpLXsg457wExJdwH3SRntYqm0QuykRmNNwaRjIfogI2CRA_F9Bm-QFYcSPTLaUclE1UtqN7Q5qi6mfi9UEzda6A8Tk4rur2UjLJ5BAgsYnkLSSobOimGJz-FK8Pf9SXYRJidkJN2TuLBPTEm7gQGTZ3NiOzcNBze09zUsJPHDDFg4-pXkMMp1rr14YddObXZqz1fHCWYz1obTibIvBKX-HC1KdP7OBevLE_5F9sv7wpK4P-5nrgPsW3CmPXIcqsedvciWun6pij4psxQmh_hq0YXw","e":"AQAB","x5c":["MIICnTCCAYUCBgF1/49sZzANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdtYWZpYXNpMB4XDTIwMTEyNTEzMTgxMFoXDTMwMTEyNTEzMTk1MFowEjEQMA4GA1UEAwwHbWFmaWFzaTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIx1VdrGa7oxGUL9tnzyknEj8hfiSi+k61g6M7cERsK8W4k3dJze2zW/bxg8Yao6S17IOOe8BMSXcB90kZ7WKptELspEZjTcGkYyH6ICNgkQPxfQZvkBWHEj0y2lHJRNVLaje0Oaoupn4vVBM3WugPE5OK7q9lIyyeQQILGJ5C0kqGzophic/hSvD3/Ul2ESYnZCTdk7iwT0xJu4EBk2dzYjs3DQc3tPc1LCTxwwxYOPqV5DDKda69eGHXTm12as9XxwlmM9aG04myLwSl/hwtSnT+zgXryxP+RfbL+8KSuD/uZ64D7Ftwpj1yHKrHnb3Ilrp+qYo+KbMUJof4atGF8CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAUGbC0ewNXJ0nkipteixQYb9fiWsHvhSLJv/jdPyzDpscpnJT3JLODlHbt25zsj8QBcyATlXpTolBB+Vg+zh4W3HS370wJvq8IPbk5NdpvJ7ksBWZt9yS99AWUPq7wAtwmWh8mSM52rlz+10u1bCTg2HrTUHFBr2I5sahfhEvZ5X2tl2aQkt+rAU0VoqFysBgsLQOndGmFgZNpkM2mHiPdned24ZaMM4j/3U/ScLsXxa3NHK7fLwyFjBJBqNZIeXplJ8iWKeDtHoFgvZdl5yFT6C1Kir3t4F6uzcIioRgcmX0WJWvB6bew+LM9RGivyCCSOiahPwWQbDsyupL8YojVg=="],"x5t":"wrCciYEqE2pzhEXDUbP52k9UGF0","x5t#S256":"6Ov7Lyhpkbwjd3UNW6076l2LMlbi9HzcGq37j_bK6IU"}]}',
    )
