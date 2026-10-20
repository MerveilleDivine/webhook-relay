from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from webhook_relay.api import make_server
from webhook_relay.delivery import resolve_target, run_once, send, signature
from webhook_relay.store import IdempotencyConflict, Store

TOKEN = "local-test-token-with-32-characters"
SECRET = b"local-test-signing-secret-32-bytes"


@contextmanager
def serving(server):
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01),
                              daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@contextmanager
def receiver(statuses):
    requests = []
    remaining = list(statuses)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            requests.append((dict(self.headers), body, self.path))
            status = remaining.pop(0) if remaining else 200
            self.send_response(status)
            if status == 302:
                self.send_header("Location", "/should-not-be-followed")
            self.send_header("Content-Length", "0")
            self.end_headers()

    with serving(ThreadingHTTPServer(("127.0.0.1", 0), Handler)) as server:
        yield f"http://127.0.0.1:{server.server_port}/events?source=test", requests


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "outbox.sqlite3"
        self.store = Store(self.path)

    def enqueue(self, key="invoice-1", **kwargs):
        return self.store.enqueue(key, "https://example.com/hooks", {"invoice": 1}, **kwargs)

    def test_idempotency_uses_canonical_payload_and_rejects_conflict(self):
        first, created = self.store.enqueue("same", "https://example.com/h",
                                            {"b": 2, "a": 1})
        again, repeated = self.store.enqueue("same", "https://example.com/h",
                                             {"a": 1, "b": 2})
        self.assertTrue(created)
        self.assertFalse(repeated)
        self.assertEqual(first["id"], again["id"])
        with self.assertRaises(IdempotencyConflict):
            self.store.enqueue("same", "https://example.com/h", {"a": 3})
        with self.assertRaises(IdempotencyConflict):
            self.store.enqueue("same", "https://example.com/other", {"a": 1, "b": 2})

    def test_concurrent_enqueue_creates_one_event(self):
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(lambda _: self.enqueue(), range(16)))
        self.assertEqual(sum(created for _, created in results), 1)
        self.assertEqual(len({event["id"] for event, _ in results}), 1)

    def test_one_worker_claims_each_due_row(self):
        self.enqueue(now=10)
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(lambda _: self.store.claim(now=10), range(16)))
        self.assertEqual(sum(claim is not None for claim in results), 1)

    def test_retry_schedule_and_state_survive_reopening(self):
        event, _ = self.enqueue(now=10)
        first = self.store.claim(now=10)
        self.store.finish(first, delivered=False, retryable=True, error="HTTP 503", now=11)
        reopened = Store(self.path)
        self.assertIsNone(reopened.claim(now=12.9))
        second = reopened.claim(now=13)
        self.assertEqual(second.id, event["id"])
        self.assertEqual(second.attempts, 2)
        self.assertEqual(second.body, first.body)
        reopened.finish(second, delivered=True, now=14)
        self.assertEqual(reopened.get(event["id"])["status"], "delivered")
        self.assertIsNone(reopened.claim(now=100))

    def test_expired_claim_is_recovered_and_old_worker_is_fenced(self):
        event, _ = self.enqueue(now=10)
        old = self.store.claim(now=10, lease_seconds=5)
        self.assertIsNone(self.store.claim(now=14.9))
        current = self.store.claim(now=15, lease_seconds=5)
        self.assertNotEqual(old.lease_token, current.lease_token)
        self.assertFalse(self.store.finish(old, delivered=True, now=16))
        self.assertEqual(self.store.get(event["id"])["status"], "delivering")
        self.assertTrue(self.store.finish(current, delivered=True, now=16))

    def test_final_attempt_crash_does_not_retry_forever(self):
        event, _ = self.enqueue(now=10, max_attempts=1)
        self.store.claim(now=10, lease_seconds=5)
        self.assertIsNone(self.store.claim(now=15))
        record = self.store.get(event["id"])
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["attempts"], 1)

    def test_attempt_budget_and_permanent_failure_are_terminal(self):
        event, _ = self.enqueue(now=10, max_attempts=2)
        first = self.store.claim(now=10)
        self.store.finish(first, delivered=False, retryable=True, now=10)
        second = self.store.claim(now=12)
        self.store.finish(second, delivered=False, retryable=True, error="HTTP 503", now=12)
        self.assertEqual(self.store.get(event["id"])["status"], "failed")
        self.assertIsNone(self.store.claim(now=100))
        another, _ = self.enqueue("second", now=100)
        claim = self.store.claim(now=100)
        self.store.finish(claim, delivered=False, retryable=False, error="HTTP 400", now=100)
        self.assertEqual(self.store.get(another["id"])["status"], "failed")

    def test_retry_backoff_is_capped(self):
        event, _ = self.enqueue(now=10)
        claim = self.store.claim(now=10)
        self.store.finish(claim, delivered=False, retryable=True, now=10,
                          base_delay=30, max_delay=4)
        self.assertEqual(self.store.get(event["id"])["available_at"], 14)


class DestinationTests(unittest.TestCase):
    @staticmethod
    def resolved(address):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))]

    def test_blocks_private_link_local_multicast_and_http_by_default(self):
        for address in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "224.0.0.1"):
            with self.subTest(address=address), patch("socket.getaddrinfo",
                                                     return_value=self.resolved(address)):
                with self.assertRaises(ValueError):
                    resolve_target("https://example.com/hooks")
        with patch("socket.getaddrinfo", return_value=self.resolved("93.184.216.34")):
            with self.assertRaises(ValueError):
                resolve_target("http://example.com/hooks", allow_loopback=True)

    def test_rejects_credentials_fragments_and_mixed_dns_answers(self):
        for url in ("https://user:pass@example.com/h", "https://example.com/h#fragment",
                    "file:///etc/passwd", "https://example.com/has space"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                resolve_target(url)
        answers = self.resolved("93.184.216.34") + self.resolved("127.0.0.1")
        with patch("socket.getaddrinfo", return_value=answers), self.assertRaises(ValueError):
            resolve_target("https://example.com/h")

    def test_resolves_checked_ip_and_preserves_host_and_query(self):
        with patch("socket.getaddrinfo", return_value=self.resolved("93.184.216.34")):
            target = resolve_target("https://example.com/hooks?type=paid")
        self.assertEqual(target.address, "93.184.216.34")
        self.assertEqual(target.hostname, "example.com")
        self.assertEqual(target.path, "/hooks?type=paid")

    def test_rejects_zero_port_and_encodes_unicode_path(self):
        with self.assertRaises(ValueError):
            resolve_target("https://example.com:0/hooks")
        with patch("socket.getaddrinfo", return_value=self.resolved("93.184.216.34")):
            target = resolve_target("https://example.com/événements?name=été")
        self.assertEqual(target.path, "/%C3%A9v%C3%A9nements?name=%C3%A9t%C3%A9")


class HTTPIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = Store(Path(self.directory.name) / "outbox.sqlite3")

    def request(self, server, method, path, data=None, *, token=TOKEN, key="event-1",
                content_type="application/json"):
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
        body = json.dumps(data).encode() if data is not None else None
        headers = {"Content-Type": content_type, "Idempotency-Key": key}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_api_auth_validation_idempotency_and_readback(self):
        with receiver([200]) as (url, _), serving(make_server(
                ("127.0.0.1", 0), self.store, TOKEN, allow_loopback=True)) as server:
            self.assertEqual(self.request(server, "GET", "/health", token=None)[0], 200)
            data = {"url": url, "payload": {"type": "invoice.paid"}}
            self.assertEqual(self.request(server, "POST", "/deliveries", data, token=None)[0], 401)
            self.assertEqual(self.request(server, "POST", "/deliveries", data, key="")[0], 400)
            self.assertEqual(self.request(server, "POST", "/deliveries", data,
                                          content_type="text/plain")[0], 415)
            status, event = self.request(server, "POST", "/deliveries", data)
            self.assertEqual(status, 202)
            self.assertEqual(self.request(server, "POST", "/deliveries", data)[0], 200)
            data["payload"]["type"] = "changed"
            self.assertEqual(self.request(server, "POST", "/deliveries", data)[0], 409)
            status, fetched = self.request(server, "GET", "/deliveries/" + event["id"])
            self.assertEqual(status, 200)
            self.assertEqual(fetched["id"], event["id"])
            self.assertNotIn("body", fetched)
            self.assertEqual(self.request(server, "GET", "/deliveries/" + "0" * 32)[0], 404)

    def test_api_rejects_oversized_and_non_finite_payload(self):
        with receiver([200]) as (url, _), serving(make_server(
                ("127.0.0.1", 0), self.store, TOKEN, allow_loopback=True)) as server:
            data = {"url": url, "payload": {"huge": "x" * 65536}}
            self.assertEqual(self.request(server, "POST", "/deliveries", data)[0], 413)
            data["payload"] = {"invalid": float("nan")}
            self.assertEqual(self.request(server, "POST", "/deliveries", data)[0], 400)

    def test_api_replays_accepted_event_when_destination_is_unavailable(self):
        with receiver([200]) as (url, _), serving(make_server(
                ("127.0.0.1", 0), self.store, TOKEN, allow_loopback=True)) as server:
            data = {"url": url, "payload": {"invoice": 1042}}
            status, event = self.request(server, "POST", "/deliveries", data)
            self.assertEqual(status, 202)
            with patch("webhook_relay.api.resolve_target", side_effect=OSError("DNS offline")):
                status, replay = self.request(server, "POST", "/deliveries", data)
                self.assertEqual(status, 200)
                self.assertEqual(replay["id"], event["id"])
                data["payload"]["invoice"] = 1043
                self.assertEqual(self.request(server, "POST", "/deliveries", data)[0], 409)

    def test_real_http_retry_delivers_identical_signed_body(self):
        with receiver([503, 200]) as (url, requests):
            event, _ = self.store.enqueue("retry", url, {"message": "Bonjour, Mervine"})
            first = run_once(self.store, SECRET, allow_loopback=True, base_delay=0.001)
            self.assertFalse(first["delivered"])
            # Move the queued timestamp rather than sleeping for a retry delay.
            next_due = self.store.get(event["id"])["available_at"]
            with patch("webhook_relay.store.time.time", return_value=next_due + 1):
                second = run_once(self.store, SECRET, allow_loopback=True)
            self.assertTrue(second["delivered"])
            self.assertEqual(self.store.get(event["id"])["status"], "delivered")
            self.assertEqual(len(requests), 2)
            self.assertEqual(requests[0][1], requests[1][1])
            for attempt, (headers, body, path) in enumerate(requests, 1):
                expected = "sha256=" + hmac.new(SECRET,
                    headers["X-Webhook-Timestamp"].encode() + b"." + body,
                    hashlib.sha256).hexdigest()
                self.assertEqual(headers["X-Webhook-Signature"], expected)
                self.assertEqual(headers["X-Webhook-Attempt"], str(attempt))
                self.assertEqual(json.loads(body)["id"], event["id"])
                self.assertEqual(path, "/events?source=test")

    def test_redirects_are_not_followed(self):
        with receiver([302, 200]) as (url, requests):
            event, _ = self.store.enqueue("redirect", url, {})
            result = run_once(self.store, SECRET, allow_loopback=True)
            self.assertEqual(result["error"], "HTTP 302")
            self.assertEqual(len(requests), 1)
            self.assertEqual(self.store.get(event["id"])["status"], "failed")

    def test_worker_rechecks_destination_before_sending(self):
        event, _ = self.store.enqueue("blocked", "http://127.0.0.1:9999/h", {})
        result = run_once(self.store, SECRET)
        self.assertFalse(result["delivered"])
        self.assertEqual(self.store.get(event["id"])["status"], "failed")


if __name__ == "__main__":
    unittest.main()
