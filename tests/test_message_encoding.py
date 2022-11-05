import unittest
from typing import Optional

from hypothesis import given

from simple_openid.data import OpenidMessage


class DummyMessage(OpenidMessage):
    required_field: str
    optional_field: Optional[str]
    optional_with_default: Optional[str] = "default value"


class MessageEncodingTestCase(unittest.TestCase):
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
