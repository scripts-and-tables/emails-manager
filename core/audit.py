"""Append-only audit logging for authentication events.

`log_auth_event` is the only entry point. Callers pass the HttpRequest (when
available) and the event type; we record the timestamped row asynchronously
with respect to the caller's flow — failures here never propagate.
"""

from __future__ import annotations

import logging
from typing import Any

from .models import AuthEvent

logger = logging.getLogger(__name__)


def _client_ip(request: Any) -> str | None:
    """Best-effort client IP. Trust X-Forwarded-For only when present (Railway
    sets it). Fall back to REMOTE_ADDR for local / dev requests."""
    if request is None:
        return None
    xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if xff:
        return xff.split(",")[0].strip() or None
    return request.META.get("REMOTE_ADDR") or None


def _username_of(user: Any, fallback: str) -> str:
    if user is not None and hasattr(user, "get_username"):
        try:
            return (user.get_username() or "")[:150]
        except Exception:
            pass
    return (fallback or "")[:150]


def log_auth_event(
    request: Any,
    event_type: str,
    *,
    user: Any = None,
    username: str = "",
    **metadata: Any,
) -> AuthEvent | None:
    """Record one auth event. Never raises into the caller."""
    try:
        return AuthEvent.objects.create(
            event_type=event_type,
            user=user if (user is not None and getattr(user, "is_authenticated", False)) else None,
            username=_username_of(user, username),
            ip=_client_ip(request),
            user_agent=(request.META.get("HTTP_USER_AGENT", "")[:500] if request is not None else ""),
            metadata=metadata or {},
        )
    except Exception:
        logger.exception("Failed to log auth event %s", event_type)
        return None
