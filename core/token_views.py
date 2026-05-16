"""Web UI for managing API tokens.

Tokens are issued from `/account/tokens/`, an OTP-protected page. The full
token value is shown exactly once on a confirmation page; from then on the
list view only shows the short prefix.
"""

from __future__ import annotations

from datetime import timedelta

from django.contrib import messages
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from .api.auth import issue_token
from .decorators import otp_required
from .models import APIToken, EmailAccount


@otp_required
@require_http_methods(["GET"])
def tokens_list(request: HttpRequest) -> HttpResponse:
    tokens = (
        APIToken.objects.filter(owner=request.user)
        .prefetch_related("accounts")
        .order_by("-created_at")
    )
    revealed_id = request.session.pop("revealed_token_id", None)
    revealed_value = request.session.pop("revealed_token_value", None)
    return render(
        request,
        "core/tokens/list.html",
        {
            "tokens": tokens,
            "revealed_id": revealed_id,
            "revealed_value": revealed_value,
        },
    )


@otp_required
@require_http_methods(["GET", "POST"])
def tokens_create(request: HttpRequest) -> HttpResponse:
    accounts = EmailAccount.objects.filter(owner=request.user, is_enabled=True).order_by("email_address")
    if request.method == "POST":
        name = (request.POST.get("name") or "").strip()[:120]
        if not name:
            messages.error(request, "Give the token a name so you can recognise it later.")
            return render(request, "core/tokens/create.html", {"accounts": accounts, "name": name})

        days_raw = (request.POST.get("expires_days") or "").strip()
        expires_at = None
        if days_raw:
            try:
                days = int(days_raw)
            except ValueError:
                messages.error(request, "Expiry must be a whole number of days.")
                return render(request, "core/tokens/create.html", {"accounts": accounts, "name": name})
            if days < 1 or days > 3650:
                messages.error(request, "Expiry must be between 1 and 3650 days.")
                return render(request, "core/tokens/create.html", {"accounts": accounts, "name": name})
            expires_at = timezone.now() + timedelta(days=days)

        selected_ids = request.POST.getlist("accounts")
        scoped_accounts = list(accounts.filter(pk__in=selected_ids)) if selected_ids else []

        full_value, key_prefix, key_hash = issue_token()
        token = APIToken.objects.create(
            owner=request.user,
            name=name,
            key_prefix=key_prefix,
            key_hash=key_hash,
            expires_at=expires_at,
        )
        if scoped_accounts:
            token.accounts.set(scoped_accounts)

        # Stash the plaintext value on the session for one-shot reveal,
        # then redirect so the value isn't in the form POST body forever.
        request.session["revealed_token_id"] = token.id
        request.session["revealed_token_value"] = full_value
        return redirect(reverse("core:tokens_list"))

    return render(request, "core/tokens/create.html", {"accounts": accounts, "name": ""})


@otp_required
@require_http_methods(["POST"])
def tokens_revoke(request: HttpRequest, pk: int) -> HttpResponse:
    token = get_object_or_404(APIToken, pk=pk, owner=request.user)
    if token.revoked_at is None:
        token.revoked_at = timezone.now()
        token.save(update_fields=["revoked_at"])
        messages.success(request, f"Token “{token.name}” revoked.")
    return redirect(reverse("core:tokens_list"))
