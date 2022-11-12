"""
Base data types which are extended with concrete OpenId data types in :mod:`simple_openid_connect.data`
"""
import abc
import logging
from typing import Any, List, Literal, Type, TypeVar

from cryptojwt import JWK, JWS
from furl import Query, furl
from pydantic import BaseModel

logger = logging.getLogger(__name__)


Self = TypeVar("Self", bound="OpenidBaseModel")


class OpenidBaseModel(BaseModel, metaclass=abc.ABCMeta):
    """
    Base model type upon which all openid data types are built.

    It implements decoding functionality that should always be supported.
    """

    @classmethod
    def parse_jwt(cls: Type[Self], value: str, signing_keys: List[JWK]) -> Self:
        verifier = JWS()
        msg = verifier.verify_compact(value, signing_keys)
        return cls.parse_obj(msg)


class OpenidMessage(OpenidBaseModel, metaclass=abc.ABCMeta):
    """
    A base class for messages sent to and received from an Openid issuer
    """

    def encode_x_www_form_urlencoded(self) -> str:
        """
        Encode this message as a `x-www-form-urlencoded` formatted string.

        This is useful to send the message to an OP (if it is a request) either directly as GET url parameters or as an
        `x-www-form-urlencoded` request body

        """
        query = Query()
        query.set(self.dict(exclude_defaults=True))
        return query.encode()

    def encode_url(self, url: str) -> str:
        """
        Encode this message as query string parameters into the existing url.

        This method explicitly only encodes the message into an urls query string because Openid specifies that only
        responses can be returned via a fragment and since this library is only intended for usage as a relying party,
        it should never need to generate responses.
        """
        url = furl(url, query_params=self.dict(exclude_defaults=True))
        return url.tostr()

    @classmethod
    def parse_x_www_form_urlencoded(cls: Type[Self], s: str) -> Self:
        """
        Parse a received message that is parsed from the given `x-www-form-urlencoded` formatted string.
        """
        query = Query(s)
        one_value_params = {key: query.params[key] for key in query.params.keys()}
        return cls.parse_obj(one_value_params)

    @classmethod
    def parse_url(
        cls: Type[Self],
        url: str,
        location: Literal["query", "fragment", "auto"] = "auto",
    ) -> Self:
        """
        Parse a received message that is encoded as part of the URL as query parameters.

        :param url: The url which contains a message either in its query string or fragment
        :param location: Where the message data is located in the url.
            If set to 'auto', fragment will be tried first with query being used as a fallback.
        """
        if location == "query":
            return cls.parse_x_www_form_urlencoded(str(furl(url).query))
        elif location == "fragment":
            fragment = furl(url).fragment.query
            return cls.parse_x_www_form_urlencoded(str(fragment))
        elif location == "auto":
            try:
                return cls.parse_url(url, location="fragment")
            except Exception as e:
                logger.debug(
                    "Could not parse %s from fragment, trying query string: %s",
                    cls.__name__,
                    e,
                )
                return cls.parse_url(url, location="query")
        else:
            raise ValueError(f"invalid location value {location}")
