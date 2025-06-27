#!/usr/bin/env python3
import argparse
import json
import logging
import urllib.parse
from collections import defaultdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from secrets import token_urlsafe
from typing import Any, Dict
from typing import Optional  # noqa: F401

from simple_openid_connect.client import OpenidClient
from simple_openid_connect.data import (
    TokenSuccessResponse,
)

# initialize a session object (which is very primitive but works)
session = defaultdict(lambda: "")
client = None  # type: Optional[OpenidClient]


class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        url = urllib.parse.urlparse(self.path)
        if url.path == "/":
            self._handle_initial()
        elif url.path.startswith("/callback"):
            self._handle_callback()
        else:
            self.return_redirect("/")

    def _handle_initial(self) -> None:
        global session
        global client
        assert client is not None

        # setup authorization code flow
        session["state"] = token_urlsafe(16)
        session["nonce"] = token_urlsafe(16)
        login_url = client.authorization_code_flow.start_authentication(
            state=session["state"], nonce=session["nonce"]
        )

        # send response
        self.return_redirect(login_url)

    def _handle_callback(self) -> None:
        global session
        global client
        assert client is not None

        # parse callback
        response = client.authorization_code_flow.handle_authentication_result(
            self.path, state=session["state"]
        )

        if isinstance(response, TokenSuccessResponse):
            access_token = response.access_token
            id_token = client.decode_id_token(response.id_token, nonce=session["nonce"])
            userinfo = client.fetch_userinfo(access_token)
            self.return_json_response(
                {
                    "token_response": response.model_dump(),
                    "id_token": id_token.model_dump(),
                    "userinfo": userinfo.model_dump(),
                }
            )

        else:
            self.return_json_response(response.model_dump())

    def return_redirect(self, to: str, code: int = HTTPStatus.FOUND) -> None:
        self.send_response(code)
        self.send_header("location", to)
        self.end_headers()

    def return_json_response(self, content: Dict[Any, Any]) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(content).encode("UTF-8"))


def main() -> None:
    argp = argparse.ArgumentParser(
        description="Script to retrieve access and refresh tokens from an OpenID-Connect identity provider and display them to the user. Useful for debugging purposes when requiring low-level access to these tokens."
    )
    argp.add_argument(
        "--issuer",
        required=True,
        help="OpenID_Connect issuer url",
    )
    argp.add_argument(
        "--client-id",
        required=True,
        help="OpenID-Connect client id",
    )
    argp.add_argument(
        "--client-secret", required=True, help="OpenID-Connect client secret"
    )
    argp.add_argument(
        "--scope",
        help="OpenID-Connect scopes to request. Default to just 'openid'. Can be given multiple times, once for each additional scope",
        action="append",
        default=["openid"],
    )
    argp.add_argument(
        "-p",
        "--port",
        type=int,
        default=8080,
        help="Port to bind this server to. Defaults to 8080",
    )
    argp.add_argument(
        "--host",
        default="127.0.0.1",
        help="IP address to bind this server to. Defaults to 127.0.0.1",
    )
    args = argp.parse_args()

    logging.basicConfig(level=logging.INFO)

    # initialize openid client
    global client
    own_base_url = f"http://{args.host}:{args.port}"
    client = OpenidClient.from_issuer_url(
        args.issuer,
        authentication_redirect_uri=own_base_url + "/callback",
        client_id=args.client_id,
        client_secret=args.client_secret,
        scope=" ".join(args.scope),
    )

    # serve a basic http server so that authorization code flow can be used
    with HTTPServer((args.host, args.port), RequestHandler) as server:
        print(f"Open http://{server.server_name}:{server.server_port}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
