import logging
import random
import string
from base64 import b64encode

import pytest
import requests
import responses
from cryptojwt import JWT, KeyBundle, KeyJar
from cryptojwt.jwk.rsa import new_rsa_key
from responses import matchers

from simple_openid_connect.data import ProviderMetadata

logger = logging.getLogger(__name__)


def rand_str() -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=16))


@pytest.fixture(scope="session")
def jwks() -> KeyBundle:
    """A random JSON-Web-KeySet"""
    key = new_rsa_key()
    bundle = KeyBundle()
    bundle.set([key])
    return bundle


@pytest.fixture(scope="session")
def jwt(jwks) -> JWT:
    """JWT builder based on the generated JWKs"""
    jar = KeyJar()
    jar.add_kb("https://provider.example.com", jwks)
    return JWT(jar, "https://provider.example.com", 3600)


class DummyUserAgent(requests.Session):
    def naviagte_to(self, url: str) -> requests.Response:
        """
        Mimic navigating to the given URL
        """
        return self.get(url, allow_redirects=True)


@pytest.fixture
def user_agent(response_mock) -> DummyUserAgent:
    response_mock.get("https://app.example.com/login-callback")
    response_mock.get("https://app.example.com/logout-callback")
    yield DummyUserAgent()


@pytest.fixture
def response_mock() -> responses.RequestsMock:
    """
    A context manager that mocks and de-mocks http request responses
    """
    with responses.RequestsMock(assert_all_requests_are_fired=False) as mock:
        yield mock


@pytest.fixture
def known_provider_configs(response_mock):
    """
    Mock requests to known OpenID provider config URLs to return static content
    """
    # mafiasi identity
    response_mock.get(
        url="https://identity.mafiasi.de/auth/realms/simple_openid_test/.well-known/openid-configuration",
        content_type="application/json",
        body='{"issuer":"https://identity.mafiasi.de/auth/realms/simple_openid_test","authorization_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/auth","token_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/token","introspection_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/token/introspect","userinfo_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/userinfo","end_session_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/logout","frontchannel_logout_session_supported":true,"frontchannel_logout_supported":true,"jwks_uri":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/certs","check_session_iframe":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/login-status-iframe.html","grant_types_supported":["authorization_code","implicit","refresh_token","password","client_credentials","urn:ietf:params:oauth:grant-type:device_code","urn:openid:params:grant-type:ciba"],"response_types_supported":["code","none","id_token","token","id_token token","code id_token","code token","code id_token token"],"subject_types_supported":["public","pairwise"],"id_token_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"id_token_encryption_alg_values_supported":["RSA-OAEP","RSA-OAEP-256","RSA1_5"],"id_token_encryption_enc_values_supported":["A256GCM","A192GCM","A128GCM","A128CBC-HS256","A192CBC-HS384","A256CBC-HS512"],"userinfo_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512","none"],"request_object_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512","none"],"request_object_encryption_alg_values_supported":["RSA-OAEP","RSA-OAEP-256","RSA1_5"],"request_object_encryption_enc_values_supported":["A256GCM","A192GCM","A128GCM","A128CBC-HS256","A192CBC-HS384","A256CBC-HS512"],"response_modes_supported":["query","fragment","form_post","query.jwt","fragment.jwt","form_post.jwt","jwt"],"registration_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/clients-registrations/openid-connect","token_endpoint_auth_methods_supported":["private_key_jwt","client_secret_basic","client_secret_post","tls_client_auth","client_secret_jwt"],"token_endpoint_auth_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"introspection_endpoint_auth_methods_supported":["private_key_jwt","client_secret_basic","client_secret_post","tls_client_auth","client_secret_jwt"],"introspection_endpoint_auth_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"authorization_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"authorization_encryption_alg_values_supported":["RSA-OAEP","RSA-OAEP-256","RSA1_5"],"authorization_encryption_enc_values_supported":["A256GCM","A192GCM","A128GCM","A128CBC-HS256","A192CBC-HS384","A256CBC-HS512"],"claims_supported":["aud","sub","iss","auth_time","name","given_name","family_name","preferred_username","email","acr"],"claim_types_supported":["normal"],"claims_parameter_supported":true,"scopes_supported":["openid","address","web-origins","offline_access","profile","email","roles","phone","microprofile-jwt"],"request_parameter_supported":true,"request_uri_parameter_supported":true,"require_request_uri_registration":true,"code_challenge_methods_supported":["plain","S256"],"tls_client_certificate_bound_access_tokens":true,"revocation_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/revoke","revocation_endpoint_auth_methods_supported":["private_key_jwt","client_secret_basic","client_secret_post","tls_client_auth","client_secret_jwt"],"revocation_endpoint_auth_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"backchannel_logout_supported":true,"backchannel_logout_session_supported":true,"device_authorization_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/auth/device","backchannel_token_delivery_modes_supported":["poll","ping"],"backchannel_authentication_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/ext/ciba/auth","backchannel_authentication_request_signing_alg_values_supported":["PS384","ES384","RS384","ES256","RS256","ES512","PS256","PS512","RS512"],"require_pushed_authorization_requests":false,"pushed_authorization_request_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/ext/par/request","mtls_endpoint_aliases":{"token_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/token","revocation_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/revoke","introspection_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/token/introspect","device_authorization_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/auth/device","registration_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/clients-registrations/openid-connect","userinfo_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/userinfo","pushed_authorization_request_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/ext/par/request","backchannel_authentication_endpoint":"https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/ext/ciba/auth"}}',
    )
    response_mock.get(
        url="https://identity.mafiasi.de/auth/realms/simple_openid_test/protocol/openid-connect/certs",
        content_type="application/json",
        body='{"keys":[{"kid":"JAehgk0O0uzTEht7KGCPVB_urwfsBGe22phHVDZezeo","kty":"RSA","alg":"RS256","use":"sig","n":"n1t4R6mVlBZggtmEM5HohZYg5QjLtjlRVyAMMM93H4WRPpP2Xqj3RrGwP-LZr6lQhk6w8nvPNGnFujWtXb_dBrhZDBh2z0mCNvfjJMp5Ki5sLT9nCbuZ4NkIhfx7qTzQ--GomQ6uKOSuoE12A_r9UopwuCf_1zrx0MIqN_kMeYU2px5yJW-5qbwPL9hcWcfY_Pdz5SFcQ3kDi6GlXA0PN74Ivhs9baVIv60cwB0TytQXGn__GYFZ-K5qAjIymyIy8cPRy9N27Gs29cWF-C56n1pAxwkcPY1SAQgcrspIhntQbZBeGboUx2pnQ_v8LEqVt9ahh52eAbV36YoQqu1DbQ","e":"AQAB","x5c":["MIICszCCAZsCBgGEZpqrijANBgkqhkiG9w0BAQsFADAdMRswGQYDVQQDDBJzaW1wbGVfb3BlbmlkX3Rlc3QwHhcNMjIxMTExMTIxMDIzWhcNMzIxMTExMTIxMjAzWjAdMRswGQYDVQQDDBJzaW1wbGVfb3BlbmlkX3Rlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCfW3hHqZWUFmCC2YQzkeiFliDlCMu2OVFXIAwwz3cfhZE+k/ZeqPdGsbA/4tmvqVCGTrDye880acW6Na1dv90GuFkMGHbPSYI29+MkynkqLmwtP2cJu5ng2QiF/HupPND74aiZDq4o5K6gTXYD+v1SinC4J//XOvHQwio3+Qx5hTanHnIlb7mpvA8v2FxZx9j893PlIVxDeQOLoaVcDQ83vgi+Gz1tpUi/rRzAHRPK1Bcaf/8ZgVn4rmoCMjKbIjLxw9HL03bsazb1xYX4LnqfWkDHCRw9jVIBCByuykiGe1BtkF4ZuhTHamdD+/wsSpW31qGHnZ4BtXfpihCq7UNtAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAD3aKq2xiLNPlUcmxwtR1FihkEM+NM7VV+m+74Lf9m/lhNzuM00JZAW67gIz2kO5K4XaU84PCRzt3sELma/xVoBs3iW8AhtldTax17g0NZzpMEExzYi0vyihq8xihbx+8XrVwxQ3JBkb/y3b+otDX3xRxBKSCDuxuigL1bX7UzgJ3oe4wD6m8yN7nrMdqSMbspd8lkceKNPziclXnbKPIUwrnxdWMmB41zYcT3y+zHxqk6EDkf3NU+C3gCoRCQoBKcK4X2dwZdUbv0ginU9kROjNXc2+gP53CYDT4fqOEX/jBuljbYb9ziaQ9/5kJZ9SsazgWNjpf4VvhAsH64i7+dE="],"x5t":"PxLqu4M4uNWaUhbfkvI0tGrkhtQ","x5t#S256":"OWVSYSSNFaLyfxV0Lg6XyVDnB2t6sHwtNbzVB2fNCVc"}]}',
    )

    # google
    response_mock.get(
        "https://accounts.google.com/.well-known/openid-configuration",
        content_type="application/json",
        body='{"issuer":"https://accounts.google.com","authorization_endpoint":"https://accounts.google.com/o/oauth2/v2/auth","device_authorization_endpoint":"https://oauth2.googleapis.com/device/code","token_endpoint":"https://oauth2.googleapis.com/token","userinfo_endpoint":"https://openidconnect.googleapis.com/v1/userinfo","revocation_endpoint":"https://oauth2.googleapis.com/revoke","jwks_uri":"https://www.googleapis.com/oauth2/v3/certs","response_types_supported":["code","token","id_token","code token","code id_token","token id_token","code token id_token","none"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"scopes_supported":["openid","email","profile"],"token_endpoint_auth_methods_supported":["client_secret_post","client_secret_basic"],"claims_supported":["aud","email","email_verified","exp","family_name","given_name","iat","iss","locale","name","picture","sub"],"code_challenge_methods_supported":["plain","S256"],"grant_types_supported":["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:device_code","urn:ietf:params:oauth:grant-type:jwt-bearer"]}',
    )


@pytest.fixture
def dummy_provider_config(jwks, response_mock):
    """Mocked responses for the dummy *https://provider.example.com provider*"""
    response_mock.get(
        url="https://provider.example.com/.well-known/openid-configuration",
        json=ProviderMetadata(
            issuer="https://provider.example.com",
            authorization_endpoint="https://provider.example.com/auth",
            token_endpoint="https://provider.example.com/token",
            jwks_uri="https://provider.example.com/jwks",
            userinfo_endpoint="https://provider.example.com/userinfo",
            end_session_endpoint="https://provider.example.com/end-session",
            introspection_endpoint="https://provider.example.com/token-introspection",
            subject_types_supported=["public"],
            id_token_signing_alg_values_supported=["RS256"],
        ).model_dump(exclude_defaults=True),
    )
    response_mock.get(
        url="https://provider.example.com/jwks",
        body=jwks.jwks(),
        content_type="application/json",
    )


@pytest.fixture
def dummy_auth_response(response_mock):
    """
    Mocked response for the authorization endpoint

    - endpoint url: `https://provider.example.com/auth`
    - client_id: `test-client-id`
    - valid redirect_uri: `https://app.example.com/login-callback`
    - returned code: `code.foobar123`
    """
    response_mock.get(
        url="https://provider.example.com/auth",
        match=[
            matchers.query_param_matcher(
                {
                    "client_id": "test-client-id",
                    "redirect_uri": "https://app.example.com/login-callback",
                    "response_type": "code",
                    "scope": "openid",
                }
            )
        ],
        status=302,
        headers={
            "Location": "https://app.example.com/login-callback?code=code.foobar123"
        },
    )


@pytest.fixture
def dummy_token_response(response_mock):
    """
    Mocked response for the token endpoint

    - endpoint url: `https://provider.example.com/token`
    - client_id: `test-client-id`
    - client_secret: `client-secret`
    - valid redirect_uri: `https://app.example.com/login-callback`
    - expected code: `code.foobar123`

    - returned access_token: `access_token.foobar123`
    - returned id_token: `id_token.user1`
    """
    response_mock.post(
        url="https://provider.example.com/token",
        match=[
            matchers.urlencoded_params_matcher(
                {
                    "client_id": "test-client-id",
                    "code": "code.foobar123",
                    "grant_type": "authorization_code",
                    "redirect_uri": "https://app.example.com/login-callback",
                }
            ),
            matchers.header_matcher(
                {
                    "Authorization": f"Basic {b64encode(b'test-client-id:test-client-secret').decode()}",
                }
            ),
        ],
        json={
            "access_token": "access_token.foobar123",
            "token_type": "Bearer",
            "id_token": "id_token.user1",
        },
    )


@pytest.fixture
def dumm_userinfo_response(response_mock):
    """
    Mocked response for the userinfo endpoint

    - endpoint url: `https://provider.example.com/userinfo`
    - expected access token: `access_token.foobar123`

    - returned sub: `1`
    - returned username: `user1`
    """
    response_mock.get(
        url="https://provider.example.com/userinfo",
        match=[
            matchers.header_matcher(
                {
                    "Authorization": "Bearer access_token.foobar123",
                }
            )
        ],
        json={"sub": "1", "username": "user1"},
    )


@pytest.fixture
def dummy_end_session_response(response_mock):
    """
    Mocked response for the end-session endpoint

    - endpoint url: `https://provider.example.com/end-session`
    - expected logout redirect uri: `https://app.example.com/logout-callback`

    - redirects to: `https://app.example.com/logout-callback`
    """
    response_mock.get(
        url="https://provider.example.com/end-session",
        match=[
            matchers.query_param_matcher(
                {"post_logout_redirect_uri": "https://app.example.com/logout-callback"}
            )
        ],
        status=302,
        headers={
            "Location": "https://app.example.com/logout-callback",
        },
    )


@pytest.fixture
def dummy_token_introspection_response(response_mock):
    """
    Mocked response for the token introspection endpoint

    - endpoint url: `https://provider.example.com/token-introspection`
    - access token: `access_token.foobar123`
    - client credentials: `test-client-id` & `test-client-secret`

    - returned: `active=true`

    All other access tokens are responded as `active=true`
    """
    response_mock.post(
        url="https://provider.example.com/token-introspection",
        match=[
            matchers.urlencoded_params_matcher(
                {
                    "token": "access_token.foobar123",
                }
            ),
            matchers.header_matcher(
                {
                    "Authorization": f"Basic {b64encode(b'test-client-id:test-client-secret').decode()}",
                }
            ),
        ],
        json={
            "active": True,
        },
    )
    response_mock.post(
        url="https://provider.example.com/token-introspection",
        match=[
            matchers.header_matcher(
                {
                    "Authorization": f"Basic {b64encode(b'test-client-id:test-client-secret').decode()}",
                }
            )
        ],
        json={
            "active": False,
        },
    )
