"""Bearer-token auth for the external API.

The full token value (`mma_live_<random>`) is shown to the user exactly once
at creation. We store only:

  - `key_prefix`: the first 12 chars, indexed for O(1) lookup
  - `key_hash`:   sha256 hex of the full token

On every API call we parse the header, look up by prefix, then constant-time
compare hashes. The plaintext token never lives in the DB.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from functools import wraps
from typing import Any

from django.conf import settings
from django.http import HttpRequest
from django.utils import timezone

from ..models import APIRequestLog, APIToken
from .errors import json_error

AUTHZ_HEADER = "HTTP_AUTHORIZATION"
BEARER_PREFIX = "Bearer "
PREFIX_LEN = 12

# How often we update `last_used_at` / `last_used_ip` (per token). Debounced
# to once per minute to avoid one DB write per API call under high load.
LAST_USED_DEBOUNCE_SECONDS = 60


def _client_meta(request: HttpRequest) -> tuple[str | None, str]:
    """Best-effort (IP, user-agent) extraction."""
    xff = (request.META.get("HTTP_X_FORWARDED_FOR") or "").strip()
    ip = xff.split(",")[0].strip() if xff else (request.META.get("REMOTE_ADDR") or None)
    ua = (request.META.get("HTTP_USER_AGENT") or "")[:255]
    return ip, ua


def _hash_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _resolve_token(header_value: str) -> APIToken | None:
    """Parse a Bearer header value into an active APIToken, or None."""
    if not header_value.startswith(BEARER_PREFIX):
        return None
    raw = header_value[len(BEARER_PREFIX):].strip()
    prefix_setting = getattr(settings, "MMA_API_TOKEN_PREFIX", "mma_live_")
    if not raw.startswith(prefix_setting):
        return None
    key_prefix = raw[:PREFIX_LEN]
    candidates = APIToken.objects.filter(key_prefix=key_prefix, revoked_at__isnull=True)
    digest = _hash_token(raw)
    for token in candidates:
        if hmac.compare_digest(token.key_hash, digest):
            return token if token.is_active() else None
    return None


def _touch_last_used(token: APIToken, ip: str | None) -> None:
    """Update last_used_at / last_used_ip, but at most once per minute."""
    now = timezone.now()
    if token.last_used_at is not None:
        delta = (now - token.last_used_at).total_seconds()
        if delta < LAST_USED_DEBOUNCE_SECONDS:
            return
    APIToken.objects.filter(pk=token.pk).update(last_used_at=now, last_used_ip=ip)


def require_api_token(endpoint_name: str):
    """Decorator: parse Bearer token, attach to request, log the call.

    The wrapped view receives `request` with `request.api_token` set to the
    resolved APIToken. On failure the decorator returns a JSON error and the
    view is never called. Every call (success or failure) writes an
    APIRequestLog row in a `finally`.
    """

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request: HttpRequest, *args: Any, **kwargs: Any):
            started = time.monotonic()
            ip, ua = _client_meta(request)
            token: APIToken | None = None
            status = 500
            error_code = ""
            mailbox = None
            minutes = None
            count = None
            try:
                header = request.META.get(AUTHZ_HEADER, "")
                token = _resolve_token(header)
                if token is None:
                    status = 401
                    error_code = "invalid_token"
                    return json_error(
                        "invalid_token",
                        401,
                        "API token is missing, malformed, revoked, or expired.",
                    )

                request.api_token = token

                # Per-token rate limit. We use the existing `is_rate_limited`
                # helper but key on token.id rather than IP so per-IP bursts
                # from a CGNAT'd integration don't share a bucket.
                from ..rate_limit import is_rate_limited

                if is_rate_limited(
                    request,
                    "api",
                    max_per_window=getattr(settings, "MMA_API_RATE_PER_MINUTE", 60),
                    window_seconds=60,
                    extra=str(token.id),
                ):
                    status = 429
                    error_code = "rate_limited"
                    response = json_error(
                        "rate_limited",
                        429,
                        "Too many requests for this token. Try again shortly.",
                        retry_after=60,
                    )
                    response["Retry-After"] = "60"
                    return response

                response = view_func(request, *args, **kwargs)
                status = response.status_code
                # The view annotates these on the response when relevant so
                # the log row is informative.
                mailbox = getattr(response, "_api_mailbox", None)
                minutes = getattr(response, "_api_minutes", None)
                count = getattr(response, "_api_count", None)
                error_code = getattr(response, "_api_error_code", "") or ""
                _touch_last_used(token, ip)
                return response
            finally:
                try:
                    APIRequestLog.objects.create(
                        token=token,
                        endpoint=endpoint_name,
                        status_code=status,
                        mailbox=mailbox,
                        minutes=minutes,
                        count=count,
                        ip=ip,
                        user_agent=ua,
                        latency_ms=int((time.monotonic() - started) * 1000),
                        error_code=error_code,
                    )
                except Exception:
                    # Log-write failure must never break the response.
                    pass

        return _wrapped

    return decorator


def issue_token(plaintext_prefix: str = "") -> tuple[str, str, str]:
    """Generate a new API token. Returns (full_value, key_prefix, key_hash).

    The full value is shown to the user once; only the prefix and hash should
    be persisted. `plaintext_prefix` overrides the setting (used in tests).
    """
    import secrets

    prefix = plaintext_prefix or getattr(settings, "MMA_API_TOKEN_PREFIX", "mma_live_")
    raw = prefix + secrets.token_urlsafe(32)
    return raw, raw[:PREFIX_LEN], _hash_token(raw)
