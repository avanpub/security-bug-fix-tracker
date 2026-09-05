#!/usr/bin/env python3
"""Shared HTTP fetch with IPv4-only resolution and transient-error retry.

Some environments resolve dual-stack hosts with a broken IPv6 route first
(Errno 101 "Network is unreachable"); this helper forces IPv4 resolution and
retries transient failures with a short backoff. HTTPError (4xx/5xx status
responses) still propagates so callers can branch on codes like 404.
"""
import email.message
import socket
import time
import urllib.error
import urllib.request

_BROWSER_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/128.0 Safari/537.36")

_RETRY_DELAYS = (2.0, 5.0)


class _IPv4Resolver:
    """Temporarily restrict socket.getaddrinfo to AF_INET results."""

    def __enter__(self):
        self._orig = socket.getaddrinfo

        def ipv4_only(*args, **kwargs):
            return [r for r in self._orig(*args, **kwargs) if r[0] == socket.AF_INET]

        socket.getaddrinfo = ipv4_only
        return self

    def __exit__(self, *exc):
        socket.getaddrinfo = self._orig
        return False


def http_request(url: str, *, data: bytes | None = None, headers: dict | None = None,
                 timeout: int = 60, retries: int = 3) -> tuple[bytes, email.message.Message]:
    """GET/POST with forced IPv4 resolution; retries transient failures only."""
    req_headers = {"User-Agent": _BROWSER_UA, **(headers or {})}
    last_exc: BaseException | None = None
    for attempt in range(retries):
        try:
            with _IPv4Resolver():
                req = urllib.request.Request(url, data=data, headers=req_headers)
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return resp.read(), resp.headers
        except urllib.error.HTTPError:
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            last_exc = exc
            if attempt + 1 < retries:
                time.sleep(_RETRY_DELAYS[min(attempt, len(_RETRY_DELAYS) - 1)])
    assert last_exc is not None
    raise last_exc
