import logging
import random
import string
from pathlib import Path
from typing import Dict, List, Mapping, Tuple

import pytest
import requests
import responses
import yaml
from furl import furl
from requests import PreparedRequest
from requests.adapters import HTTPAdapter

from simple_openid_connect.data import (
    AuthenticationRequest,
    AuthenticationSuccessResponse,
    ProviderMetadata,
    RpInitiatedLogoutRequest,
    TokenErrorResponse,
    TokenIntrospectionRequest,
    TokenIntrospectionSuccessResponse,
    TokenRequest,
    TokenSuccessResponse,
    UserinfoErrorResponse,
    UserinfoRequest,
    UserinfoSuccessResponse,
)

logger = logging.getLogger(__name__)


def rand_str() -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=16))


class DummyOpenidProvider:
    iss = "https://provider.example.com/openid-connect"
    endpoints = {
        "authorization": f"{iss}/client_auth",
        "token": f"{iss}/token",
        "userinfo": f"{iss}/userinfo",
        "end-session": f"{iss}/end-session",
        "token-introspection": f"{iss}/token-introspection",
    }

    test_client_id = "test-client"
    test_client_secret = "foobar123"
    test_client_redirect_uri = "https://app.example.com/auth/callback"

    cheat_code = "master access code which can always be exchanged for tokens"
    cheat_token = "master access token which can always be used for everything"

    _valid_auth_codes: List[str]
    _valid_access_tokens: List[str]

    def __init__(self, requests_mock: responses.RequestsMock):
        self._valid_auth_codes = []
        self._valid_access_tokens = []
        self.setup_authorization_endpoint(requests_mock)
        self.setup_token_endpoint(requests_mock)
        self.setup_userinfo_endpoint(requests_mock)
        self.setup_end_session_endpoint(requests_mock)
        self.setup_token_introspection_endpoint(requests_mock)

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
            access_token = rand_str()
            self._valid_access_tokens.append(access_token)
            if request_msg.code == self.cheat_code:
                return (
                    200,
                    {},
                    TokenSuccessResponse(
                        access_token=access_token,
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
                        access_token=access_token,
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

    def setup_userinfo_endpoint(self, requests_mock: responses.RequestsMock):
        def callback(request: PreparedRequest) -> Tuple[int, Dict[str, str], str]:
            _request_msg = UserinfoRequest.parse_x_www_form_urlencoded(request.body)
            if request.headers["Authorization"] == f"Bearer {self.cheat_token}" or any(
                request.headers["Authorization"] == f"Bearer {token}"
                for token in self._valid_access_tokens
            ):
                return (
                    200,
                    {},
                    UserinfoSuccessResponse(sub="abc123", username="test-user").json(),
                )
            else:
                return (
                    400,
                    {},
                    UserinfoErrorResponse(
                        error="invalid_token",
                        error_description="the access token was not valid",
                    ).json(),
                )

        requests_mock.add_callback(
            method=responses.GET,
            url=self.endpoints["userinfo"],
            callback=callback,
            content_type="application/json",
        )

    def setup_end_session_endpoint(self, requests_mock: responses.RequestsMock):
        def callback(request: PreparedRequest) -> Tuple[int, Dict[str, str], str]:
            request_msg = RpInitiatedLogoutRequest.parse_x_www_form_urlencoded(
                request.url.split("?")[1]
            )
            if request_msg.post_logout_redirect_uri is not None:
                return (302, {"Location": request_msg.post_logout_redirect_uri}, "")

            return 200, {}, "Logged out"

        requests_mock.add_callback(
            method=responses.GET,
            url=self.endpoints["end-session"],
            callback=callback,
        )

    def setup_token_introspection_endpoint(self, requests_mock: responses.RequestsMock):
        def callback(request: PreparedRequest) -> Tuple[int, Dict[str, str], str]:
            _request_msg = TokenIntrospectionRequest.parse_x_www_form_urlencoded(
                request.body
            )
            return (
                200,
                {},
                TokenIntrospectionSuccessResponse(
                    active=True,
                    scope="openid",
                    client_id=self.test_client_id,
                    username="test-user",
                    sub="abc123",
                ).json(),
            )

        requests_mock.add_callback(
            method=responses.POST,
            url=self.endpoints["token-introspection"],
            callback=callback,
            content_type="applictaion/json",
        )


@pytest.fixture
def dummy_openid_provider(
    mocked_responses: responses.RequestsMock,
) -> DummyOpenidProvider:
    yield DummyOpenidProvider(mocked_responses)


class DummyUserAgent(requests.Session):
    def naviagte_to(self, url: str) -> requests.Response:
        """
        Mimic navigating to the given URL
        """
        return self.get(url, allow_redirects=True)

    def login_to_dummy_provider(
        self, url: str, username: str = "test", password: str = "foobar123"
    ) -> str:
        """
        Login to the dummy provider by posting the given credentials.
        The credentials are not intended to be real credentials because the provider usually accepts all credentials.

        This is intended to be used against the dummy provider that is defined in this repositories `tests/dummy_provider`.

        :param url: The url which currently presents the login form.
            The user agent is usually redirected here and asked to log in.
        :param username: The username to use during login.
        :param password: The password to use during login.

        :returns: The absolute path on the app server which should now be called to complete the login
        """
        # perform login
        response = self.post(
            url,
            data={
                "prompt": "login",
                "login": username,
                "password": password,
            },
        )

        # give consent
        response = self.post(
            response.url,
            allow_redirects=False,
            data={
                "prompt": "consent",
            },
        )
        while response.headers["Location"].startswith("http://localhost:300"):
            response = self.get(response.headers["Location"], allow_redirects=False)

        assert response.is_redirect, "Consent response did not return a redirect"
        return "/" + response.headers["Location"].split("/", 3)[3]


@pytest.fixture
def dummy_ua(monkeypatch) -> DummyUserAgent:
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
    # invalid example.com
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

    # valid example.com
    mocked_responses.get(
        url="https://provider.example.com/openid-connect/.well-known/openid-configuration",
        json=ProviderMetadata(
            issuer="https://provider.example.com/openid-connect",
            authorization_endpoint="https://provider.example.com/openid-connect/client_auth",
            token_endpoint="https://provider.example.com/openid-connect/token",
            jwks_uri="https://provider.example.com/openid-connect/jwks",
            userinfo_endpoint="https://provider.example.com/openid-connect/userinfo",
            end_session_endpoint="https://provider.example.com/openid-connect/end-session",
            introspection_endpoint="https://provider.example.com/openid-connect/token-introspection",
            subject_types_supported=["public"],
            id_token_signing_alg_values_supported=["RS256"],
        ).dict(exclude_defaults=True),
    )
    mocked_responses.get(
        url="https://provider.example.com/openid-connect/jwks",
        json={"keys": []},
    )

    # mafiasi identity
    mocked_responses.get(
        url="https://identity.mafiasi.de/auth/realms/simple_openid_test/.well-known/openid-configuration",
        content_type="application/json",
        body='{"issuer":"https://identity.mafiasi.de/auth/realms/simple_openid_test","authorization_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/auth","token_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/token","introspection_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/token/introspect","userinfo_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/userinfo","end_session_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/logout","frontchannel_logout_session_supported":true,"frontchannel_logout_supported":true,"jwks_uri":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/certs","check_session_iframe":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/login-status-iframe.html","grant_types_supported":["authorization_code","implicit","refresh_token","password","client_credentials","urn:ietf:params:oauth:grant-type:device_code","urn:openid:params:grant-type:ciba"],"response_types_supported":["code","none","id_token","token","id_token token","code id_token","code token","code id_token token"],"subject_types_supported":["public","pairwise"],"id_token_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"id_token_encryption_alg_values_supported":["RSA-OAEP","RSA-OAEP-256","RSA1_5"],"id_token_encryption_enc_values_supported":["A256GCM","A192GCM","A128GCM","A128CBC-HS256","A192CBC-HS384","A256CBC-HS512"],"userinfo_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512","none"],"request_object_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512","none"],"request_object_encryption_alg_values_supported":["RSA-OAEP","RSA-OAEP-256","RSA1_5"],"request_object_encryption_enc_values_supported":["A256GCM","A192GCM","A128GCM","A128CBC-HS256","A192CBC-HS384","A256CBC-HS512"],"response_modes_supported":["query","fragment","form_post","query.jwt","fragment.jwt","form_post.jwt","jwt"],"registration_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/clients-registrations/openid-connect","token_endpoint_auth_methods_supported":["private_key_jwt","client_secret_basic","client_secret_post","tls_client_auth","client_secret_jwt"],"token_endpoint_auth_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"introspection_endpoint_auth_methods_supported":["private_key_jwt","client_secret_basic","client_secret_post","tls_client_auth","client_secret_jwt"],"introspection_endpoint_auth_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"authorization_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"authorization_encryption_alg_values_supported":["RSA-OAEP","RSA-OAEP-256","RSA1_5"],"authorization_encryption_enc_values_supported":["A256GCM","A192GCM","A128GCM","A128CBC-HS256","A192CBC-HS384","A256CBC-HS512"],"claims_supported":["aud","sub","iss","auth_time","name","given_name","family_name","preferred_username","email","acr"],"claim_types_supported":["normal"],"claims_parameter_supported":true,"scopes_supported":["openid","address","web-origins","offline_access","profile","email","roles","phone","microprofile-jwt"],"request_parameter_supported":true,"request_uri_parameter_supported":true,"require_request_uri_registration":true,"code_challenge_methods_supported":["plain","S256"],"tls_client_certificate_bound_access_tokens":true,"revocation_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/revoke","revocation_endpoint_auth_methods_supported":["private_key_jwt","client_secret_basic","client_secret_post","tls_client_auth","client_secret_jwt"],"revocation_endpoint_auth_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"backchannel_logout_supported":true,"backchannel_logout_session_supported":true,"device_authorization_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/auth/device","backchannel_token_delivery_modes_supported":["poll","ping"],"backchannel_authentication_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/ext/ciba/auth","backchannel_authentication_request_signing_alg_values_supported":["PS384","ES384","RS384","ES256","RS256","ES512","PS256","PS512","RS512"],"require_pushed_authorization_requests":false,"pushed_authorization_request_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/ext/par/request","mtls_endpoint_aliases":{"token_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/token","revocation_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/revoke","introspection_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/token/introspect","device_authorization_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/auth/device","registration_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/clients-registrations/openid-connect","userinfo_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/userinfo","pushed_authorization_request_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/ext/par/request","backchannel_authentication_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/ext/ciba/auth"}}',
    )

    # google
    mocked_responses.get(
        "https://accounts.google.com/.well-known/openid-configuration",
        content_type="application/json",
        body='{"issuer":"https://accounts.google.com","authorization_endpoint":"https://accounts.google.com/o/oauth2/v2/auth","device_authorization_endpoint":"https://oauth2.googleapis.com/device/code","token_endpoint":"https://oauth2.googleapis.com/token","userinfo_endpoint":"https://openidconnect.googleapis.com/v1/userinfo","revocation_endpoint":"https://oauth2.googleapis.com/revoke","jwks_uri":"https://www.googleapis.com/oauth2/v3/certs","response_types_supported":["code","token","id_token","code token","code id_token","token id_token","code token id_token","none"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"scopes_supported":["openid","email","profile"],"token_endpoint_auth_methods_supported":["client_secret_post","client_secret_basic"],"claims_supported":["aud","email","email_verified","exp","family_name","given_name","iat","iss","locale","name","picture","sub"],"code_challenge_methods_supported":["plain","S256"],"grant_types_supported":["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:device_code","urn:ietf:params:oauth:grant-type:jwt-bearer"]}',
    )


@pytest.fixture
def mock_known_provider_jwks(mocked_responses: responses.RequestsMock):
    mocked_responses.get(
        url="https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/certs",
        content_type="application/json",
        body='{"keys":[{"kid":"JAehgk0O0uzTEht7KGCPVB_urwfsBGe22phHVDZezeo","kty":"RSA","alg":"RS256","use":"sig","n":"n1t4R6mVlBZggtmEM5HohZYg5QjLtjlRVyAMMM93H4WRPpP2Xqj3RrGwP-LZr6lQhk6w8nvPNGnFujWtXb_dBrhZDBh2z0mCNvfjJMp5Ki5sLT9nCbuZ4NkIhfx7qTzQ--GomQ6uKOSuoE12A_r9UopwuCf_1zrx0MIqN_kMeYU2px5yJW-5qbwPL9hcWcfY_Pdz5SFcQ3kDi6GlXA0PN74Ivhs9baVIv60cwB0TytQXGn__GYFZ-K5qAjIymyIy8cPRy9N27Gs29cWF-C56n1pAxwkcPY1SAQgcrspIhntQbZBeGboUx2pnQ_v8LEqVt9ahh52eAbV36YoQqu1DbQ","e":"AQAB","x5c":["MIICszCCAZsCBgGEZpqrijANBgkqhkiG9w0BAQsFADAdMRswGQYDVQQDDBJzaW1wbGVfb3BlbmlkX3Rlc3QwHhcNMjIxMTExMTIxMDIzWhcNMzIxMTExMTIxMjAzWjAdMRswGQYDVQQDDBJzaW1wbGVfb3BlbmlkX3Rlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCfW3hHqZWUFmCC2YQzkeiFliDlCMu2OVFXIAwwz3cfhZE+k/ZeqPdGsbA/4tmvqVCGTrDye880acW6Na1dv90GuFkMGHbPSYI29+MkynkqLmwtP2cJu5ng2QiF/HupPND74aiZDq4o5K6gTXYD+v1SinC4J//XOvHQwio3+Qx5hTanHnIlb7mpvA8v2FxZx9j893PlIVxDeQOLoaVcDQ83vgi+Gz1tpUi/rRzAHRPK1Bcaf/8ZgVn4rmoCMjKbIjLxw9HL03bsazb1xYX4LnqfWkDHCRw9jVIBCByuykiGe1BtkF4ZuhTHamdD+/wsSpW31qGHnZ4BtXfpihCq7UNtAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAD3aKq2xiLNPlUcmxwtR1FihkEM+NM7VV+m+74Lf9m/lhNzuM00JZAW67gIz2kO5K4XaU84PCRzt3sELma/xVoBs3iW8AhtldTax17g0NZzpMEExzYi0vyihq8xihbx+8XrVwxQ3JBkb/y3b+otDX3xRxBKSCDuxuigL1bX7UzgJ3oe4wD6m8yN7nrMdqSMbspd8lkceKNPziclXnbKPIUwrnxdWMmB41zYcT3y+zHxqk6EDkf3NU+C3gCoRCQoBKcK4X2dwZdUbv0ginU9kROjNXc2+gP53CYDT4fqOEX/jBuljbYb9ziaQ9/5kJZ9SsazgWNjpf4VvhAsH64i7+dE="],"x5t":"PxLqu4M4uNWaUhbfkvI0tGrkhtQ","x5t#S256":"OWVSYSSNFaLyfxV0Lg6XyVDnB2t6sHwtNbzVB2fNCVc"}]}',
    )


@pytest.fixture
def secrets() -> Mapping[str, str]:
    path = Path(__file__).parent / "secrets.yml"
    with open(path, "r", encoding="UTF-8") as f:
        return yaml.safe_load(f)
