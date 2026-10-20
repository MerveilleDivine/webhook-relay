# Webhook Relay

I built this to work through three common webhook problems: clients retry requests, receivers go offline, and workers can stop halfway through a delivery. The API saves each accepted event to SQLite, and a separate worker sends signed requests, retries temporary failures, and records the result.

This is an October 2026 backend exercise, built and tested locally. The interesting part is the failure handling: idempotency, database transactions, worker leases, and the point where an external request can succeed before its local state is saved.

[Mervine Muganguzi](https://www.mervine.dev) · [GitHub](https://github.com/MerveilleDivine)

## Run it

Requires Python 3.11 or newer. There are no third-party dependencies. From this directory:

```sh
python -m unittest discover -s tests -v
```

The tests use temporary databases and local HTTP servers. They do not contact external services.

For a local demonstration, set these development values in each terminal. Use independent random values outside this example, and keep them out of Git:

```sh
export WEBHOOK_API_TOKEN=local-development-api-token-change-this
export WEBHOOK_SIGNING_SECRET=local-development-signing-secret-change-this
```

Start the API:

```sh
python -m webhook_relay --db relay.sqlite3 --allow-loopback serve
```

In another terminal, start a receiver that returns 503 on the first attempt for each event:

```sh
python -m examples.receiver --fail-first
```

In a third terminal, start the worker:

```sh
python -m webhook_relay --db relay.sqlite3 --allow-loopback worker
```

Submit an event:

```sh
curl -i http://127.0.0.1:8080/deliveries \
  -H "Authorization: Bearer $WEBHOOK_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: invoice-1042-paid' \
  -d '{"url":"http://127.0.0.1:9000/events","payload":{"type":"invoice.paid","invoice_id":1042}}'
```

The API returns 202 and a delivery ID. The receiver logs a 503 followed by a successful retry. Inspect the stored result with:

```sh
curl http://127.0.0.1:8080/deliveries/DELIVERY_ID \
  -H "Authorization: Bearer $WEBHOOK_API_TOKEN"
```

Repeat the original POST with the same key and content: it returns the existing event with 200. Reusing the key for different content returns 409. The key covers the URL and canonical JSON payload; it does not enqueue a second delivery after success.

`worker --once` processes at most one due attempt and exits. Run the API and workers against the same database file. The loopback flag is only for local demonstrations; omit it for public HTTPS destinations.

## Request and delivery contracts

| Request | Result |
| --- | --- |
| `GET /health` | Anonymous process liveness check |
| `POST /deliveries` | Bearer authentication, required idempotency key, exactly `url` and object `payload`, at most 64 KiB |
| `GET /deliveries/{id}` | Authenticated status, attempt count, timestamps, and last error |

Receivers get the same UTF-8 body on every attempt:

```json
{"id":"delivery-id","payload":{"invoice_id":1042,"type":"invoice.paid"}}
```

The worker sends `X-Webhook-ID`, `X-Webhook-Attempt`, `X-Webhook-Timestamp`, and `X-Webhook-Signature`. The signature is `sha256=` followed by the HMAC-SHA256 hex digest of `timestamp + "." + raw_body`, using the signing secret. Verify the raw bytes with constant-time comparison, reject stale timestamps, and deduplicate by the signed body ID. The example receiver does all three, with in-memory deduplication for this local demonstration.

## Failure handling

SQLite transactions atomically create idempotent events and claim due work. A claim increments the attempt count and receives a random lease token. If a worker dies, another can reclaim the event after 30 seconds. Completion updates require the matching token, so an older worker cannot overwrite a replacement worker's result.

- A 2xx response marks the event delivered.
- Network errors, HTTP 408/425/429, and 5xx responses retry after 2, 4, 8, then 16 seconds, up to five attempts. The delay calculation has a 300-second cap.
- Other responses, including redirects, fail without retry. The worker never follows redirects.
- A crash during the final attempt becomes a terminal failure when its lease expires.

Delivery is at least once. A receiver can accept a request just before the worker crashes, leaving the outbox unable to record success. Recovery can therefore send it again, so the receiver must deduplicate by the signed event ID.

## Destination checks

HTTPS is required by default. Every resolved address must be public; private, link-local, reserved, and multicast destinations are rejected. Destinations are checked at enqueue and again immediately before delivery. The worker connects to a checked numeric address while preserving the original host for TLS certificate verification and the HTTP Host header. It does not perform a second hostname lookup during connection. `--allow-loopback` permits local HTTP(S) tests but does not allow arbitrary private networks or cloud metadata addresses.

## Scope and tradeoffs

I chose SQLite so the project runs without a separate database service and the transaction boundaries stay visible. The API and workers share one database file on one host. The HTTP API binds to loopback and uses Python's development HTTP server.

Production deployment would need a production HTTP server with TLS, process supervision, destination allowlists, separate customer keys, rate limits, backups, and monitoring. Retry jitter, `Retry-After` handling, and manual redrive are useful next steps. The network timeout is an idle socket timeout; a slow request can outlive its lease even though the lease token prevents stale state updates.

The 18 tests cover concurrent requests and workers, destination outages, retries after reopening the database, expired leases, stale-worker fencing, attempt budgets, API errors, destination checks, real HTTP signatures, and redirect rejection.

## Files

| File | Responsibility |
| --- | --- |
| `webhook_relay/api.py` | Authentication, input validation, HTTP responses |
| `webhook_relay/store.py` | SQLite schema and atomic state transitions |
| `webhook_relay/delivery.py` | Destination validation, signatures, network delivery |
| `webhook_relay/__main__.py` | API and worker commands |
| `tests/test_relay.py` | Unit and local HTTP integration tests |
| `examples/receiver.py` | Receiver for manual retry/signature checks |
