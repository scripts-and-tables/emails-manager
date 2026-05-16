"""JSON error envelope for the external API.

All API endpoints return errors in a flat `{error, message, status, ...}` shape
so clients can branch on `error` (a stable machine code) rather than parsing
prose `message` text.
"""

from __future__ import annotations

from django.http import JsonResponse


def json_error(code: str, status: int, message: str, **extra) -> JsonResponse:
    payload = {"error": code, "message": message, "status": status}
    payload.update(extra)
    return JsonResponse(payload, status=status)
