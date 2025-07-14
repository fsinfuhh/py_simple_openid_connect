from simple_openid_connect.data import IdToken
from datetime import datetime


def test_id_token_aud_multiple_audiences():
    # arrange
    now = int(datetime.now().timestamp())
    token = IdToken(
        iss="https://provider.example.com",
        sub="f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
        aud=["test-client", "other-client"],
        azp="test-client",
        iat=now,
        exp=now + 60 * 5,
    )

    # assert (does not raise)
    token.validate_extern(
        issuer="https://provider.example.com",
        client_id="test-client",
        extra_trusted_audiences=["other-client"],
    )
