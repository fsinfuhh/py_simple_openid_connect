"""
Base data types which are extended with concrete OpenId data types in :mod:`simple_openid_connect.data`
"""
import abc
import logging
from typing import List, Literal, Type, TypeVar

from cryptojwt import JWK, JWS, JWT, KeyBundle, KeyJar
from furl import Query, furl
from pydantic import BaseModel

logger = logging.getLogger(__name__)


Self = TypeVar("Self", bound="OpenidBaseModel")


class OpenidBaseModel(BaseModel, metaclass=abc.ABCMeta):
    """
    Base model type upon which all openid data types are built.

    It implements encoding and decoding functionality that are commonly used in OpenID contexts.
    """

    def encode_x_www_form_urlencoded(self) -> str:
        """
        Encode this message as a `x-www-form-urlencoded` formatted string.

        This is useful to send the message to an OP (if it is a request) either directly as GET url parameters or as an
        `x-www-form-urlencoded` request body

        """
        query = Query()
        query.set(self.dict(exclude_defaults=True))
        return query.encode()  # type: ignore # because furl has no typedefs, but we know what this returns

    def encode_url(self, url: str) -> str:
        """
        Encode this message as query string parameters into the existing url.

        This method explicitly only encodes the message into an urls query string because Openid specifies that only
        responses can be returned via a fragment and since this library is only intended for usage as a relying party,
        it should never need to generate responses.
        """
        url_parsed = furl(url)
        url_parsed.args.update(self.dict(exclude_defaults=True))
        return url_parsed.tostr()  # type: ignore # because furl has no typedefs, but we know what this returns

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

    @classmethod
    def parse_jws(cls: Type[Self], value: str, signing_keys: List[JWK]) -> Self:
        """
        Parse received data that is encoded as a signed Json-Web-Signature (JWS).

        :param value: The encoded JWT
        :param signing_keys: List of keys one of which has been used to sign the JWT
        """
        verifier = JWS()
        msg = verifier.verify_compact(value, signing_keys)
        return cls.parse_obj(msg)

    @classmethod
    def parse_jwt(
        cls: Type[Self], token: str, signing_keys: List[JWK], issuer: str
    ) -> Self:
        key_bundle = KeyBundle(keys=signing_keys)
        key_jar = KeyJar()
        key_jar.add_kb(issuer, key_bundle)
        verifier = JWT(key_jar)
        msg = verifier.unpack(token)
        return cls.parse_obj(msg)
