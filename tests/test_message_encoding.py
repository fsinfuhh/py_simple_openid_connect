import time
import unittest
from typing import Optional

from hypothesis import given

from simple_openid_connect.data import OpenidBaseModel, JwtAccessToken


class DummyMessage(OpenidBaseModel):
    required_field: str
    optional_field: Optional[str]
    optional_with_default: Optional[str] = "default value"


class XwwwFormEncodingTestCase(unittest.TestCase):
    @given(a=..., b=..., c=...)
    def test_encode_does_not_throw(self, a: str, b: Optional[str], c: Optional[str]):
        # setup
        msg = DummyMessage(required_field=a, optional_field=b, optional_with_default=c)

        # execution
        msg.encode_x_www_form_urlencoded()

    @given(a=..., b=..., c=...)
    def test_encode_can_be_decoded(self, a: str, b: Optional[str], c: Optional[str]):
        # setup
        original_msg = DummyMessage(
            required_field=a, optional_field=b, optional_with_default=c
        )

        # execution
        reconstructed_msg = DummyMessage.parse_x_www_form_urlencoded(
            original_msg.encode_x_www_form_urlencoded()
        )

        # verification
        self.assertEqual(original_msg, reconstructed_msg)


class UrlEncodingTestCase(unittest.TestCase):
    @given(msg=...)
    def test_encode_does_not_throw(self, msg: DummyMessage):
        msg.encode_url("https://example.com")

    @given(msg=...)
    def test_encode_can_be_decoded(self, msg: DummyMessage):
        # act
        reconstructed_msg = DummyMessage.parse_url(
            msg.encode_url("https://example.com"), location="query"
        )

        # assert
        self.assertEqual(msg, reconstructed_msg)

    @given(msg=...)
    def test_auto_decode_in_fragment(self, msg: DummyMessage):
        # act
        reconstructed_msg = DummyMessage.parse_url(
            f"https://example.com#{msg.encode_x_www_form_urlencoded()}",
            location="auto",
        )
        # assert
        self.assertEqual(reconstructed_msg, msg)

    @given(msg=...)
    def test_auto_decode_in_query(self, msg: DummyMessage):
        # act
        reconstructed_msg = DummyMessage.parse_url(
            f"https://example.com?{msg.encode_x_www_form_urlencoded()}",
            location="auto",
        )
        # assert
        self.assertEqual(reconstructed_msg, msg)


def test_jwt_access_token_with_azp_claim():
    # arrange
    now = int(time.time())
    token_data = {
        "iss": "https://provider.example.com",
        "sub": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
        "jti": "test-token",
        "iat": now,
        "exp": now + 60 * 5,
        "aud": "test-client",
        "azp": "test-client",
    }

    # act
    token = JwtAccessToken.model_validate(token_data)

    # assert
    assert token.client_id == "test-client"


def test_jwt_access_token_with_azp_and_client_id_claim():
    # arrange
    now = int(time.time())
    token_data = {
        "iss": "https://provider.example.com",
        "sub": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
        "jti": "test-token",
        "iat": now,
        "exp": now + 60 * 5,
        "aud": ["test-client", "other-client"],
        "azp": "other-client",
        "client_id": "test-client",
    }

    # act
    token = JwtAccessToken.model_validate(token_data)

    # assert
    assert token.client_id == "test-client"
