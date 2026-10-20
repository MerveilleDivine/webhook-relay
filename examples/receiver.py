"""Local test receiver: verify signatures, deduplicate, optionally fail once."""

import argparse
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import sys
import threading
import time

# Run as `python -m examples.receiver` from the project directory.
from webhook_relay.delivery import signature


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--fail-first", action="store_true")
    args = parser.parse_args()
    secret = os.environ.get("WEBHOOK_SIGNING_SECRET", "").encode("utf-8")
    if len(secret) < 32:
        parser.error("Set WEBHOOK_SIGNING_SECRET to at least 32 bytes")
    seen, failed_once = set(), set()
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 70 * 1024:
                    raise ValueError("Invalid body size")
                self.connection.settimeout(5)
                body = self.rfile.read(size)
                timestamp = self.headers.get("X-Webhook-Timestamp", "")
                if abs(time.time() - int(timestamp)) > 300:
                    raise ValueError("Expired signature")
                expected = signature(secret, timestamp, body).encode("ascii")
                received = self.headers.get("X-Webhook-Signature", "").encode("utf-8")
                if not hmac.compare_digest(expected, received):
                    raise ValueError("Invalid signature")
                delivery_id = json.loads(body)["id"]
                if not isinstance(delivery_id, str):
                    raise ValueError("Invalid delivery id")
                with lock:
                    duplicate = delivery_id in seen
                    if args.fail_first and delivery_id not in failed_once:
                        failed_once.add(delivery_id)
                        status = 503
                    else:
                        seen.add(delivery_id)
                        status = 200
                print(json.dumps({"id": delivery_id, "status": status,
                                  "duplicate": duplicate}), flush=True)
            except (ValueError, KeyError, TypeError, OSError, UnicodeError):
                status = 400
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()

    print(f"Local receiver: http://127.0.0.1:{args.port}/events", flush=True)
    try:
        with ThreadingHTTPServer(("127.0.0.1", args.port), Handler) as server:
            server.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
