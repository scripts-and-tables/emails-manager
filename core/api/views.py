"""External API views.

v1 surface: one endpoint, `GET /api/v1/messages`. Read-only, pull-only, Bearer
auth, no DRF. Everything else is v2.
"""

from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.http import HttpRequest, JsonResponse
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from .. import imap_client
from ..models import EmailAccount, EmailAlias
from .auth import require_api_token
from .errors import json_error
from .serializers import message_to_dict


def _parse_int(value: str | None, *, lo: int, hi: int) -> int | None:
    if value is None:
        return None
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    if n < lo or n > hi:
        return None
    return n


def _parse_bool(value: str | None, *, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@require_http_methods(["GET"])
@require_api_token("messages.recent")
def messages_recent(request: HttpRequest) -> JsonResponse:
    token = request.api_token

    mailbox_param = (request.GET.get("mailbox") or "").strip()
    minutes_param = request.GET.get("minutes")
    folder = (request.GET.get("folder") or "inbox").strip().lower()
    with_bodies = _parse_bool(request.GET.get("bodies"), default=True)

    max_window = getattr(settings, "MMA_API_MAX_WINDOW_MINUTES", 1440)
    max_limit = getattr(settings, "MMA_API_MAX_LIMIT", 500)

    minutes = _parse_int(minutes_param, lo=1, hi=max_window)
    if minutes is None:
        resp = json_error(
            "validation_error",
            400,
            f"`minutes` is required and must be an integer between 1 and {max_window}.",
        )
        resp._api_error_code = "validation_error"
        return resp

    limit = _parse_int(request.GET.get("limit"), lo=1, hi=max_limit) or 100

    if not mailbox_param:
        resp = json_error(
            "validation_error",
            400,
            "`mailbox` is required (the email address of one of your connected mailboxes).",
        )
        resp._api_error_code = "validation_error"
        return resp

    # Strict allow-list of semantic folder names. Anything else → 400 rather
    # than a confusing IMAP error.
    if folder not in imap_client.ALLOWED_SEMANTIC_FOLDERS:
        resp = json_error(
            "validation_error",
            400,
            f"`folder` must be one of {sorted(imap_client.ALLOWED_SEMANTIC_FOLDERS)}.",
        )
        resp._api_error_code = "validation_error"
        return resp

    # Resolve mailbox scoped to *this token's owner* — a probe with someone
    # else's email returns the same 404 as a typo (no cross-tenant oracle).
    #
    # The requested address may be either a primary account address or one of
    # its aliases. Aliases share the parent account's IMAP connection, so an
    # alias hit resolves to the parent `mailbox` plus an `alias_address` we use
    # to filter the shared inbox down to mail actually delivered to the alias.
    mailbox = EmailAccount.objects.filter(
        owner=token.owner,
        email_address__iexact=mailbox_param,
        is_enabled=True,
    ).first()
    alias_address: str | None = None
    if mailbox is None:
        alias = (
            EmailAlias.objects.select_related("account")
            .filter(
                account__owner=token.owner,
                account__is_enabled=True,
                email_address__iexact=mailbox_param,
                is_enabled=True,
            )
            .first()
        )
        if alias is not None:
            mailbox = alias.account
            alias_address = alias.email_address
    if mailbox is None:
        resp = json_error(
            "mailbox_not_found",
            404,
            "No enabled mailbox with that address is connected to your account.",
        )
        resp._api_error_code = "mailbox_not_found"
        return resp

    if not token.can_access(mailbox):
        resp = json_error(
            "scope_forbidden",
            403,
            "This token is not authorised to read that mailbox.",
        )
        resp._api_error_code = "scope_forbidden"
        resp._api_mailbox = mailbox
        return resp

    since = timezone.now() - timedelta(minutes=minutes)
    raw_msgs, truncated, error = imap_client.fetch_window(
        mailbox,
        since=since,
        folder=folder,
        with_bodies=with_bodies,
        limit=limit,
        recipient=alias_address,
    )

    if error is not None:
        resp = json_error(
            "imap_unavailable",
            503,
            "Upstream IMAP server is unavailable. Try again shortly.",
        )
        resp._api_error_code = "imap_unavailable"
        resp._api_mailbox = mailbox
        resp._api_minutes = minutes
        return resp

    messages_payload = [message_to_dict(m, with_body=with_bodies) for m in raw_msgs]

    response = JsonResponse(
        {
            # `mailbox` echoes the address that was queried (the alias, if one
            # was used); `account` is always the parent mailbox it resolves to.
            "mailbox": alias_address or mailbox.email_address,
            "account": mailbox.email_address,
            "alias": alias_address is not None,
            "folder": folder,
            "window_minutes": minutes,
            "since": since.isoformat(),
            "count": len(messages_payload),
            "truncated": truncated,
            "messages": messages_payload,
        }
    )
    response._api_mailbox = mailbox
    response._api_minutes = minutes
    response._api_count = len(messages_payload)
    return response
