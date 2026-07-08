"""
Fake HTTP service.
"""
import argparse
import sys
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from honeypot.common.db import log_event, init_db

FAKE_LOGIN_PAGE = b"""<!doctype html><html><head><title>Admin Login</title></head>
<body><h2>Administrator Login</h2>
<form method="POST" action="/login">
<input name="username" placeholder="Username"><br>
<input name="password" type="password" placeholder="Password"><br>
<button type="submit">Login</button>
</form></body></html>"""


class DecoyHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.41"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _client_ip(self):
        return self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()

    def _common_log(self, event_type, raw_payload=None, username=None, password=None):
        log_event(
            "http", self._client_ip(), self.client_address[1], event_type,
            username=username, password=password, raw_payload=raw_payload,
            extra={"headers": dict(self.headers), "path": self.path, "method": self.command},
        )

    def do_GET(self):
        full_url = "GET " + self.path + " headers=" + str(dict(self.headers))
        self._common_log("request", raw_payload=full_url)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(FAKE_LOGIN_PAGE)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        username = password = None
        try:
            parsed = parse_qs(body.decode(errors="replace"))
            username = parsed.get("username", [None])[0]
            password = parsed.get("password", [None])[0]
        except Exception:
            pass
        self._common_log(
            "auth_attempt",
            raw_payload="POST " + self.path + " body=" + repr(body[:500]),
            username=username, password=password,
        )
        self.send_response(401)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<h3>Invalid credentials</h3>")


def serve(host, port):
    init_db()
    srv = ThreadingHTTPServer((host, port), DecoyHandler)
    print("[http_decoy] listening on " + host + ":" + str(port))
    srv.serve_forever()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8080)
    args = p.parse_args()
    serve(args.host, args.port)
