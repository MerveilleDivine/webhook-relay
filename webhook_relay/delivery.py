"""Resolve, validate and pin destinations before sending signed webhook bodies."""

from dataclasses import dataclass
import hashlib
import hmac
import http.client
import ipaddress
import socket
import ssl
import time
from urllib.parse import quote, urlsplit


@dataclass(frozen=True)
class Target:
    hostname: str
    port: int
    path: str
    address: str
    tls: bool


def resolve_target(url, *, allow_loopback=False):
    if not isinstance(url, str) or len(url) > 2048 or any(ord(c) < 33 for c in url):
        raise ValueError("url must be a URL without whitespace, at most 2048 characters")
    parts = urlsplit(url)
    if (parts.scheme not in ("https", "http") or not parts.hostname
            or parts.username is not None or parts.password is not None or parts.fragment):
        raise ValueError("Use an HTTP(S) URL without credentials or a fragment")
    hostname = parts.hostname.encode("idna").decode("ascii")
    port = parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise ValueError("Invalid destination port")
    addresses = list(dict.fromkeys(
        entry[4][0] for entry in socket.getaddrinfo(
            hostname, port, type=socket.SOCK_STREAM)))
    if not addresses:
        raise ValueError("Destination did not resolve")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip.is_multicast or (not ip.is_global and not (allow_loopback and ip.is_loopback)):
            raise ValueError("Private, link-local and reserved destinations are blocked")
        if parts.scheme == "http" and not (allow_loopback and ip.is_loopback):
            raise ValueError("HTTPS is required; HTTP is allowed only for loopback tests")
    path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(parts.query, safe="/?%:@!$&'()*+,;=-._~")
    return Target(hostname, port, path + ("?" + query if query else ""),
                  addresses[0], parts.scheme == "https")


def signature(secret, timestamp, body):
    message = str(timestamp).encode("ascii") + b"." + body
    return "sha256=" + hmac.new(secret, message, hashlib.sha256).hexdigest()


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, target, timeout):
        super().__init__(target.hostname, target.port, timeout=timeout)
        self.target = target

    def connect(self):
        # Connect to the checked numeric address, not a second DNS lookup of host.
        self.sock = socket.create_connection(
            (self.target.address, self.target.port), self.timeout)


class _PinnedHTTPSConnection(_PinnedHTTPConnection):
    def connect(self):
        super().connect()
        self.sock = ssl.create_default_context().wrap_socket(
            self.sock, server_hostname=self.target.hostname)


def send(claim, secret, *, timeout=5, allow_loopback=False, timestamp=None):
    """Return (delivered, retryable, error). Never follow redirects."""
    connection = None
    try:
        target = resolve_target(claim.url, allow_loopback=allow_loopback)
        connection_type = _PinnedHTTPSConnection if target.tls else _PinnedHTTPConnection
        connection = connection_type(target, timeout)
        timestamp = int(time.time()) if timestamp is None else timestamp
        connection.request("POST", target.path, body=claim.body, headers={
            "Content-Type": "application/json",
            "User-Agent": "webhook-relay/1",
            "X-Webhook-ID": claim.id,
            "X-Webhook-Attempt": str(claim.attempts),
            "X-Webhook-Timestamp": str(timestamp),
            "X-Webhook-Signature": signature(secret, timestamp, claim.body),
        })
        status = connection.getresponse().status
        if 200 <= status < 300:
            return True, False, None
        return False, status in (408, 425, 429) or status >= 500, "HTTP " + str(status)
    except (ValueError, UnicodeError) as exc:
        return False, False, str(exc)
    except (OSError, http.client.HTTPException) as exc:
        return False, True, type(exc).__name__ + ": " + str(exc)
    finally:
        if connection is not None:
            connection.close()


def run_once(store, secret, *, allow_loopback=False, timeout=5, lease_seconds=30,
             base_delay=2):
    if lease_seconds <= timeout:
        raise ValueError("lease_seconds must be longer than the network timeout")
    claim = store.claim(lease_seconds=lease_seconds)
    if claim is None:
        return None
    delivered, retryable, error = send(
        claim, secret, timeout=timeout, allow_loopback=allow_loopback)
    accepted = store.finish(claim, delivered=delivered, retryable=retryable,
                            error=error, base_delay=base_delay)
    return {"id": claim.id, "attempt": claim.attempts,
            "delivered": delivered, "state_saved": accepted, "error": error}
