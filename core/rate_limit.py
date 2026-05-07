"""Tiny rate-limiter built on Django's cache framework.

Intentional design: per-IP counters in a rolling time window. Single
gunicorn worker (our prod config) means the default LocMem cache is
shared across all requests; multi-worker setups would need a shared
cache backend (Redis/Memcached/database) for accuracy.
"""

from __future__ import annotations

from django.core.cache import cache
from django.http import HttpRequest


def client_ip(request: HttpRequest) -> str:
    xff = (request.META.get("HTTP_X_FORWARDED_FOR") or "").strip()
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR") or "unknown"


def is_rate_limited(
    request: HttpRequest,
    action: str,
    *,
    max_per_window: int,
    window_seconds: int,
    extra: str = "",
) -> bool:
    """Atomically count this hit and return True if (action, IP[, extra])
    has now exceeded max_per_window inside the rolling window_seconds."""
    ip = client_ip(request)
    key = f"rl:{action}:{ip}"
    if extra:
        key += f":{extra}"
    if cache.add(key, 1, timeout=window_seconds):
        return False
    try:
        count = cache.incr(key)
    except ValueError:
        cache.set(key, 1, timeout=window_seconds)
        return False
    return count > max_per_window
