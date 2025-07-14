from simple_openid_connect.data import IdToken, JwtAccessToken
import time

import pytest

from simple_openid_connect.exceptions import ValidationError


def test_id_token__minimal():
    # arrange
    now = int(time.time())
    token = IdToken(
        iss="https://provider.example.com",
        sub="f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
        aud="test-client",
        iat=now,
        exp=now + 60 * 5,
    )

    # assert
    token.validate_extern(
        issuer="https://provider.example.com",
        client_id="test-client",
    )
    with pytest.raises(
        ValidationError, match="ID-Token was issued from unexpected issuer"
    ):
        token.validate_extern(
            issuer="https://wrong.example.com", client_id="test-client"
        )
    with pytest.raises(
        ValidationError, match="ID-Token's audience does not contain own client_id"
    ):
        token.validate_extern(
            issuer="https://provider.example.com", client_id="wrong-client"
        )


def test_id_token___aud_list_single_client():
    # arrange
    now = int(time.time())
    token = IdToken(
        iss="https://provider.example.com",
        sub="f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
        aud=["test-client"],
        iat=now,
        exp=now + 60 * 5,
    )

    # assert
    token.validate_extern(
        issuer="https://provider.example.com",
        client_id="test-client",
    )


def test_id_token__multiple_audiences():
    # arrange
    now = int(time.time())
    token = IdToken(
        iss="https://provider.example.com",
        sub="f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
        aud=["test-client", "other-client"],
        azp="test-client",
        iat=now,
        exp=now + 60 * 5,
    )

    # assert
    token.validate_extern(
        issuer="https://provider.example.com",
        client_id="test-client",
        extra_trusted_audiences=["other-client"],
    )
    with pytest.raises(
        ValidationError, match="Not all of the ID-Token's audiences are trusted"
    ):
        token.validate_extern(
            issuer="https://provider.example.com",
            client_id="test-client",
            extra_trusted_audiences=[],
        )


def test_id_token__azp_is_required():
    # arrange
    now = int(time.time())
    token = IdToken(
        iss="https://provider.example.com",
        sub="f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
        aud=["test-client", "other-client"],
        iat=now,
        exp=now + 60 * 5,
    )

    # assert
    with pytest.raises(
        ValidationError,
        match="ID-Token does not contain azp claim but is required to because it is issued to more than 1 audience",
    ):
        token.validate_extern(
            issuer="https://provider.example.com",
            client_id="test-client",
            extra_trusted_audiences=["other-client"],
        )


def test_id_token__expiry():
    # arrange
    now = int(time.time())
    token = IdToken(
        iss="https://provider.example.com",
        sub="f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
        aud=["test-client", "other-client"],
        azp="test-client",
        iat=now - 60 * 5,
        exp=now - 60,
    )

    # assert
    with pytest.raises(ValidationError, match="The ID-Token is expired"):
        token.validate_extern(
            issuer="https://provider.example.com",
            client_id="test-client",
            extra_trusted_audiences=["other-client"],
        )


def test_id_token__iat():
    # arrange
    now = int(time.time())
    token = IdToken(
        iss="https://provider.example.com",
        sub="f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
        aud="test-client",
        iat=now - 60,
        exp=now + 60 * 5,
    )

    # assert
    token.validate_extern(
        issuer="https://provider.example.com",
        client_id="test-client",
        min_iat=0,
    )
    with pytest.raises(
        ValidationError, match="The ID-Token was issued too far in the past"
    ):
        token.validate_extern(
            issuer="https://provider.example.com",
            client_id="test-client",
            extra_trusted_audiences=["other-client"],
            min_iat=now,
        )


def test_id_token__nonce():
    # arrange
    now = int(time.time())
    token_with = IdToken(
        iss="https://provider.example.com",
        sub="f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
        aud="test-client",
        iat=now - 60,
        exp=now + 60 * 5,
        nonce="42",
    )
    token_without = IdToken(
        iss="https://provider.example.com",
        sub="f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
        aud="test-client",
        iat=now - 60,
        exp=now + 60 * 5,
        nonce=None,
    )

    # assert (does not raise)
    token_with.validate_extern(
        issuer="https://provider.example.com",
        client_id="test-client",
        nonce="42",
    )

    # assert (passing a wrong nonce)
    with pytest.raises(
        ValidationError, match="The ID-Token's nonce does not match its expected value"
    ):
        token_with.validate_extern(
            issuer="https://provider.example.com",
            client_id="test-client",
            nonce="0",
        )

    # assert (not passing a nonce but one is in the token)
    with pytest.raises(
        ValidationError, match="The ID-Token's nonce does not match its expected value"
    ):
        token_with.validate_extern(
            issuer="https://provider.example.com",
            client_id="test-client",
        )

    # assert (passing a nonce but the token does not have one)
    with pytest.raises(
        ValidationError, match="The ID-Token's nonce does not match its expected value"
    ):
        token_without.validate_extern(
            issuer="https://provider.example.com",
            client_id="test-client",
            nonce="42",
        )


def test_id_token__auth_time():
    # arrange
    now = int(time.time())
    token = IdToken(
        iss="https://provider.example.com",
        sub="f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
        aud="test-client",
        iat=now - 60,
        exp=now + 60 * 5,
        auth_time=now - 120,
    )

    # assert
    token.validate_extern(
        issuer="https://provider.example.com",
        client_id="test-client",
        min_auth_time=0,
    )
    with pytest.raises(
        ValidationError,
        match="The session associated with this ID-Token was authenticated too far in the past",
    ):
        token.validate_extern(
            issuer="https://provider.example.com",
            client_id="test-client",
            min_auth_time=now,
        )


def test_jwt_access_token__issuer():
    # arrange
    now = int(time.time())
    token = JwtAccessToken(
        iss="https://provider.example.com",
        exp=now + 60 * 5,
        aud="test-client",
        sub="f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
        client_id="test-client",
        iat=now,
        jti="token-1",
    )

    # assert
    token.validate_extern(
        issuer="https://provider.example.com",
        client_id="test-client",
    )
    with pytest.raises(
        ValidationError, match="The access token was issued from an unexpected issuer"
    ):
        token.validate_extern(
            issuer="https://wrong.example.com",
            client_id="test-client",
        )


def test_jwt_access_token__expiry():
    # arrange
    now = int(time.time())
    token = JwtAccessToken(
        iss="https://provider.example.com",
        aud="test-client",
        sub="f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
        client_id="test-client",
        iat=now,
        jti="token-1",
        exp=now - 60,
    )

    # assert
    with pytest.raises(ValidationError, match="The access token is expired"):
        token.validate_extern(
            issuer="https://provider.example.com",
            client_id="test-client",
        )


def test_jwt_access_token__aud():
    # arrange
    now = int(time.time())
    token = JwtAccessToken(
        iss="https://provider.example.com",
        sub="f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
        exp=now + 60 * 5,
        client_id="test-client",
        iat=now,
        jti="token-1",
        aud="test-client",
    )

    # assert
    token.validate_extern(
        issuer="https://provider.example.com",
        client_id="test-client",
    )
    with pytest.raises(
        ValidationError,
        match="The access tokens audience does not contain own client_id",
    ):
        token.validate_extern(
            issuer="https://provider.example.com",
            client_id="wrong-client",
        )
