"""Pure dict transformers for API responses.

Kept dependency-free (no DRF) so they're trivial to unit-test and reuse.
Each function takes a domain object and returns a plain dict that's safe
to drop straight into `JsonResponse`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any


def _isoformat(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    # imap_tools sometimes returns naïve datetimes; treat them as UTC.
    return dt.isoformat()


def _addr(value: Any) -> dict[str, str] | None:
    """Normalize an imap_tools address tuple/object into {name, email}."""
    if value is None:
        return None
    name = getattr(value, "name", None) or ""
    email = getattr(value, "email", None) or ""
    if not email and isinstance(value, str):
        # Plain "Name <email>" string fallback.
        return {"name": "", "email": value}
    return {"name": str(name), "email": str(email)}


def _addr_list(values: Any) -> list[dict[str, str]]:
    if not values:
        return []
    out: list[dict[str, str]] = []
    for v in values:
        a = _addr(v)
        if a:
            out.append(a)
    return out


def attachment_to_dict(att: Any) -> dict[str, Any]:
    return {
        "filename": getattr(att, "filename", "") or "",
        "size": getattr(att, "size", 0) or 0,
        "content_type": getattr(att, "content_type", "") or "",
    }


def message_to_dict(msg: Any, *, with_body: bool) -> dict[str, Any]:
    """Map one imap_tools.MailMessage (or shimmed dict) to an API dict."""
    base = {
        "uid": getattr(msg, "uid", "") or "",
        "subject": getattr(msg, "subject", "") or "",
        "from": _addr(getattr(msg, "from_values", None) or getattr(msg, "from_", None)),
        "to": _addr_list(getattr(msg, "to_values", None) or getattr(msg, "to", None)),
        "cc": _addr_list(getattr(msg, "cc_values", None) or getattr(msg, "cc", None)),
        "date": _isoformat(getattr(msg, "date", None)),
        "message_id": getattr(msg, "headers", {}).get("message-id", [""])[0] if hasattr(msg, "headers") else "",
        "flags": list(getattr(msg, "flags", []) or []),
        "size": getattr(msg, "size", 0) or 0,
    }
    if with_body:
        base["text"] = getattr(msg, "text", "") or ""
        base["html"] = getattr(msg, "html", "") or ""
        base["attachments"] = [attachment_to_dict(a) for a in (getattr(msg, "attachments", []) or [])]
        base["has_attachments"] = bool(base["attachments"])
    else:
        base["has_attachments"] = bool(getattr(msg, "attachments", []) or [])
    return base
