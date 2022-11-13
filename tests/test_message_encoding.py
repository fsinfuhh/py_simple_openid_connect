import unittest
from typing import Optional

from furl import quote as urlquote
from hypothesis import given

from simple_openid_connect.data import OpenidBaseModel


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
