"""A deliberately small authenticated HTTP interface to the outbox."""

import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
import socket
import sqlite3

from .delivery import resolve_target
from .store import IdempotencyConflict, canonical_json

MAX_BODY_BYTES = 64 * 1024


def _reject_constant(value):
    raise ValueError("Non-finite JSON number: " + value)


def make_server(address, store, api_token, *, allow_loopback=False):
    if len(api_token.encode("utf-8")) < 24:
        raise ValueError("Use an API token of at least 24 bytes")

    class Handler(BaseHTTPRequestHandler):
        server_version = "WebhookRelay/1"
        sys_version = ""

        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, *_args):
            # Avoid logging bearer tokens, payloads, or caller-controlled paths.
            pass

        def respond(self, status, data):
            body = canonical_json(data)
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def authorized(self):
            supplied = self.headers.get("Authorization", "").encode("utf-8")
            expected = ("Bearer " + api_token).encode("utf-8")
            if not hmac.compare_digest(supplied, expected):
                self.respond(401, {"error": "Bearer token required"})
                return False
            return True

        def do_GET(self):
            if self.path == "/health":
                self.respond(200, {"status": "ok"})
                return
            if not self.authorized():
                return
            match = re.fullmatch(r"/deliveries/([a-f0-9]{32})", self.path)
            delivery = store.get(match[1]) if match else None
            self.respond(200, delivery) if delivery else self.respond(404, {"error": "Not found"})

        def do_POST(self):
            if not self.authorized():
                return
            if self.path != "/deliveries":
                self.respond(404, {"error": "Not found"})
                return
            if self.headers.get_content_type() != "application/json":
                self.respond(415, {"error": "Content-Type must be application/json"})
                return
            key = self.headers.get("Idempotency-Key", "")
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", key):
                self.respond(400, {"error": "Use an Idempotency-Key of 1-128 letters, digits, . _ : -"})
                return
            if self.headers.get("Transfer-Encoding"):
                self.respond(400, {"error": "Chunked requests are not supported"})
                return
            if len(self.headers.get_all("Content-Length", [])) > 1:
                self.respond(400, {"error": "Use one Content-Length header"})
                return
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self.respond(411, {"error": "Content-Length required"})
                return
            if length <= 0 or length > MAX_BODY_BYTES:
                self.respond(413, {"error": "Body must be between 1 and 65536 bytes"})
                return
            try:
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ValueError("Incomplete request body")
                data = json.loads(raw, parse_constant=_reject_constant)
                if (not isinstance(data, dict) or set(data) != {"url", "payload"}
                        or not isinstance(data["payload"], dict)):
                    raise ValueError("Provide exactly url and an object payload")
                existing = store.replay(key, data["url"], data["payload"])
                if existing is not None:
                    self.respond(200, existing)
                    return
                resolve_target(data["url"], allow_loopback=allow_loopback)
                delivery, created = store.enqueue(key, data["url"], data["payload"])
            except IdempotencyConflict as exc:
                self.respond(409, {"error": str(exc)})
                return
            except (ValueError, UnicodeError, RecursionError) as exc:
                self.respond(400, {"error": str(exc) or "Invalid JSON request"})
                return
            except (OSError, socket.timeout):
                self.respond(503, {"error": "Destination resolution or request read failed"})
                return
            except sqlite3.Error:
                self.respond(503, {"error": "Outbox temporarily unavailable"})
                return
            self.respond(202 if created else 200, delivery)

    return ThreadingHTTPServer(address, Handler)
