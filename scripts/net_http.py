#!/usr/bin/env python3
"""Shared HTTP fetch with IPv4-only resolution and transient-error retry.

Some environments resolve dual-stack hosts with a broken IPv6 route first
(Errno 101 "Network is unreachable"); this helper forces IPv4 resolution and
retries transient failures with a short backoff. HTTPError (4xx/5xx status
responses) still propagates so callers can branch on codes like 404 — except
403/429 rate-limit responses, which are retried with a backoff (honoring a
Retry-After header when present, e.g. GitHub secondary limits) before the
error finally propagates.
"""
import email.message
import socket
import sys
import time
import urllib.error
import urllib.request

_BROWSER_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/128.0 Safari/537.36")

_RETRY_DELAYS = (2.0, 5.0)

# Backoff for rate-limit style responses (403 secondary limit, 429).
_RATE_LIMIT_DELAYS = (5.0, 15.0)

_RATE_LIMIT_CODES = frozenset((403, 429))

_last_request = [0.0]


def _pace(min_interval: float) -> None:
    """Sleep so that consecutive calls are at least min_interval apart."""
    if min_interval <= 0:
        return
    now = time.monotonic()
    wait = _last_request[0] + min_interval - now
    if wait > 0:
        time.sleep(wait)
    _last_request[0] = time.monotonic()


def _log_rate_limit_response(exc: urllib.error.HTTPError, req: urllib.request.Request) -> None:
    headers = exc.headers or {}
    auth = req.has_header("Authorization")
    print(f"[net-http] HTTP {exc.code} on {req.get_method()} {req.full_url} "
          f"(authorized={auth}, "
          f"X-RateLimit-Remaining={headers.get('X-RateLimit-Remaining', '-')}, "
          f"X-RateLimit-Reset={headers.get('X-RateLimit-Reset', '-')}, "
          f"Retry-After={headers.get('Retry-After', '-')})", file=sys.stderr, flush=True)


def _rate_limit_delay(exc: urllib.error.HTTPError, attempt: int) -> float:
    """Seconds to wait after a 403/429 (Retry-After if sent, else backoff)."""
    try:
        return min(float(exc.headers.get("Retry-After", "")), 60.0)
    except (TypeError, ValueError):
        delays = _RATE_LIMIT_DELAYS
        return delays[min(attempt, len(delays) - 1)]


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
                 timeout: int = 60, retries: int = 3, tag: str | None = None,
                 pace: float = 0.0) -> tuple[bytes, email.message.Message]:
    """GET/POST with forced IPv4 resolution; retries transient failures and
    403/429 rate-limit responses, letting other HTTP errors propagate.

    tag, when set, is echoed with each request attempt to help attribute
    failures to a caller;     pace enforces a minimum interval between requests.
    """
    last_exc: BaseException | None = None
    for attempt in range(retries):
        _pace(pace)
        req_headers = {"User-Agent": _BROWSER_UA, **(headers or {})}
        req = urllib.request.Request(url, data=data, headers=req_headers)
        if tag:
            print(f"[net-http] [{tag}] attempt {attempt + 1}/{retries}: "
                  f"{req.get_method()} {url}", flush=True)
        try:
            with _IPv4Resolver():
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return resp.read(), resp.headers
        except urllib.error.HTTPError as exc:
            if exc.code in _RATE_LIMIT_CODES:
                _log_rate_limit_response(exc, req)
            if exc.code in _RATE_LIMIT_CODES and attempt + 1 < retries:
                time.sleep(_rate_limit_delay(exc, attempt))
                last_exc = exc
                continue
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            last_exc = exc
            if attempt + 1 < retries:
                time.sleep(_RETRY_DELAYS[min(attempt, len(_RETRY_DELAYS) - 1)])
    assert last_exc is not None
    raise last_exc
