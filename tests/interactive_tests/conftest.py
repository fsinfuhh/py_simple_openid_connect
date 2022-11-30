import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable, Mapping, Tuple

import pytest
from furl import furl


class RealAppServer(HTTPServer):
    login_url = "http://127.0.0.1:8000/login"
    callback_url = "http://127.0.0.1:8000/callback"

    _on_login = None
    _on_callback = None

    _is_done = False

    def __init__(self):
        super().__init__(
            ("127.0.0.1", 8000), self.RequestHandler, bind_and_activate=True
        )

    def serve_until_done(
        self,
        on_login: Callable[[furl], Tuple[int, Mapping[str, str], str]],
        on_callback: Callable[[furl], Tuple[int, Mapping[str, str], str]],
    ):
        self._on_login = on_login
        self._on_callback = on_callback
        while not self._is_done:
            self.handle_request()

    def done(self):
        self._is_done = True

    def handle_error(self, request, client_address) -> None:
        # re-raise exceptions so that they can fail the test
        raise sys.exc_info()[1]

    class RequestHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            url = furl(self.path)
            if url.path == "/login":
                response = self.server._on_login(url)
            elif url.path == "/callback":
                response = self.server._on_callback(url)
            else:
                response = 404, {}, "Not found"

            self.send_response(response[0])
            for k, v in response[1].items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(response[2].encode("UTF-8"))


@pytest.fixture
def real_app_server() -> RealAppServer:
    server = RealAppServer()
    yield server
    server.server_close()
