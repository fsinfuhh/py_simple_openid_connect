import pytest
import responses


@pytest.fixture(autouse=True)
def mocked_responses():
    """
    A context manager that mocks and de-mocks http request responses
    """
    with responses.RequestsMock(assert_all_requests_are_fired=False) as mock:
        yield mock


@pytest.fixture
def openid_provider_configs(mocked_responses: responses.RequestsMock):
    """
    Mock requests to known OpenID provider config URLs to return static content
    """
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
