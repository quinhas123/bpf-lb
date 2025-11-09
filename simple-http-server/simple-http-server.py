# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "dotenv",
# ]
# ///

'''
Reference repo: https://gist.github.com/bradmontgomery/2219997
Start server with uv using:
    - uv run --script simple-http-server.py -i 1
'''

import argparse
from functools import partial
from http.server import HTTPServer, BaseHTTPRequestHandler

class S(BaseHTTPRequestHandler):
    def __init__(self, identifier, request, client_address, server):
        self.identifier = identifier
        super().__init__(request, client_address, server)

    def _set_headers(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()

    def _plain_text(self, message):
        content = message
        return content.encode("utf8")

    def do_GET(self):
        self._set_headers()
        self.wfile.write(self._plain_text(f"Hi from server {self.identifier}!\n"))

def run(identifier, server_class=HTTPServer, handler_class=S, addr="localhost", port=80):
    server_address = (addr, port)
    partially_initialized_handler_class = partial(handler_class, identifier)
    httpd = server_class(server_address, partially_initialized_handler_class)

    print(f"Starting httpd server on {addr}:{port}")
    httpd.serve_forever()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple HTTP server")
    parser.add_argument(
        "-l",
        "--listen",
        default="localhost",
        help="Specify the IP address on which the server listens",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=8000,
        help="Specify the port on which the server listens",
    )
    parser.add_argument(
        "-i",
        "--identifier",
        required=True,
        help="Specify an identifier to this http server"
    )
    args = parser.parse_args()
    run(addr=args.listen, port=args.port, identifier=args.identifier)