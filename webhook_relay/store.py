"""SQLite state transitions. Each operation owns its connection and transaction."""

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import time
import uuid


class IdempotencyConflict(ValueError):
    """The key already identifies a different request."""


@dataclass(frozen=True)
class Claim:
    id: str
    url: str
    body: bytes
    attempts: int
    max_attempts: int
    lease_token: str


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


class Store:
    def __init__(self, path):
        self.path = str(Path(path))
        if self.path == ":memory:":
            raise ValueError("Use a file database; connections are short lived")
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("""
                CREATE TABLE IF NOT EXISTS deliveries (
                    id TEXT PRIMARY KEY,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    request_hash TEXT NOT NULL,
                    url TEXT NOT NULL,
                    body BLOB NOT NULL,
                    status TEXT NOT NULL CHECK(status IN
                        ('queued', 'delivering', 'delivered', 'failed')),
                    attempts INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL CHECK(max_attempts > 0),
                    available_at REAL NOT NULL,
                    lease_until REAL,
                    lease_token TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    last_error TEXT
                )
            """)
            db.execute("CREATE INDEX IF NOT EXISTS due_deliveries ON "
                       "deliveries(status, available_at, lease_until)")

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def enqueue(self, key, url, payload, *, now=None, max_attempts=5):
        now = time.time() if now is None else now
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        fingerprint = hashlib.sha256(canonical_json([url, payload])).hexdigest()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT * FROM deliveries WHERE idempotency_key=?",
                                  (key,)).fetchone()
            if existing:
                if existing["request_hash"] != fingerprint:
                    raise IdempotencyConflict("Key already used for a different request")
                return self._public(existing), False
            delivery_id = uuid.uuid4().hex
            body = canonical_json({"id": delivery_id, "payload": payload})
            db.execute("""INSERT INTO deliveries
                (id, idempotency_key, request_hash, url, body, status,
                 max_attempts, available_at, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?)""",
                       (delivery_id, key, fingerprint, url, body, max_attempts,
                        now, now, now))
            row = db.execute("SELECT * FROM deliveries WHERE id=?",
                             (delivery_id,)).fetchone()
            return self._public(row), True

    @staticmethod
    def _public(row):
        return {name: row[name] for name in (
            "id", "url", "status", "attempts", "max_attempts", "available_at",
            "created_at", "updated_at", "last_error")}

    def get(self, delivery_id):
        with self._connect() as db:
            row = db.execute("SELECT * FROM deliveries WHERE id=?",
                             (delivery_id,)).fetchone()
            return self._public(row) if row else None

    def replay(self, key, url, payload):
        """Read an accepted request without requiring its destination to be online."""
        fingerprint = hashlib.sha256(canonical_json([url, payload])).hexdigest()
        with self._connect() as db:
            row = db.execute("SELECT * FROM deliveries WHERE idempotency_key=?",
                             (key,)).fetchone()
            if row and row["request_hash"] != fingerprint:
                raise IdempotencyConflict("Key already used for a different request")
            return self._public(row) if row else None

    def claim(self, *, now=None, lease_seconds=30):
        now = time.time() if now is None else now
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            # A crash during the last permitted attempt must not retry forever.
            db.execute("""UPDATE deliveries SET status='failed', lease_token=NULL,
                lease_until=NULL, updated_at=?,
                last_error='Worker lease expired after final attempt'
                WHERE status='delivering' AND lease_until<=?
                AND attempts>=max_attempts""", (now, now))
            row = db.execute("""SELECT * FROM deliveries WHERE attempts<max_attempts
                AND ((status='queued' AND available_at<=?) OR
                     (status='delivering' AND lease_until<=?))
                ORDER BY available_at, created_at, id LIMIT 1""", (now, now)).fetchone()
            if row is None:
                return None
            token = secrets.token_hex(16)
            db.execute("""UPDATE deliveries SET status='delivering', attempts=attempts+1,
                lease_token=?, lease_until=?, updated_at=? WHERE id=?""",
                       (token, now + lease_seconds, now, row["id"]))
            return Claim(row["id"], row["url"], bytes(row["body"]),
                         row["attempts"] + 1, row["max_attempts"], token)

    def finish(self, claim, *, delivered, retryable=False, error=None,
               now=None, base_delay=2, max_delay=300):
        now = time.time() if now is None else now
        if base_delay <= 0 or max_delay <= 0:
            raise ValueError("Retry delays must be positive")
        retry = not delivered and retryable and claim.attempts < claim.max_attempts
        status = "delivered" if delivered else ("queued" if retry else "failed")
        delay = min(max_delay, base_delay * 2 ** (claim.attempts - 1)) if retry else 0
        with self._connect() as db:
            cursor = db.execute("""UPDATE deliveries SET status=?, available_at=?,
                lease_token=NULL, lease_until=NULL, updated_at=?, last_error=?
                WHERE id=? AND status='delivering' AND lease_token=?""",
                                (status, now + delay, now,
                                 None if delivered else str(error or "Delivery failed")[:500],
                                 claim.id, claim.lease_token))
            # A worker whose lease was replaced cannot overwrite a newer claim.
            return cursor.rowcount == 1
