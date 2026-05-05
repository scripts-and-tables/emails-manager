from __future__ import annotations

from django.contrib import messages
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods

from .decorators import OTP_VERIFIED_SESSION_KEY, is_otp_verified, otp_required
from .email_otp import OtpDeliveryError, issue_and_send, verify
from .forms import EmailAccountForm, OtpForm
from .imap_client import check_status_bulk, fetch_body, fetch_recent_bulk
from .models import EmailAccount

User = get_user_model()

PRE_OTP_USER_KEY = "pre_otp_user_id"


def _send_otp_or_flash(request: HttpRequest, user) -> bool:
    try:
        issue_and_send(user)
        return True
    except OtpDeliveryError as exc:
        messages.error(request, f"Could not send the verification code: {exc}")
        return False


def index(request: HttpRequest) -> HttpResponse:
    if request.user.is_authenticated and is_otp_verified(request):
        return redirect("core:status")
    return redirect("core:login")


@require_http_methods(["GET", "POST"])
def login_view(request: HttpRequest) -> HttpResponse:
    if request.user.is_authenticated and is_otp_verified(request):
        return redirect("core:status")

    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            request.session[PRE_OTP_USER_KEY] = user.id
            request.session[OTP_VERIFIED_SESSION_KEY] = False
            if _send_otp_or_flash(request, user):
                masked = _mask_email(user.email)
                messages.info(request, f"We emailed a 6-digit code to {masked}.")
                return redirect("core:verify_otp")
    else:
        form = AuthenticationForm(request)

    return render(request, "core/login.html", {"form": form})


def _mask_email(email: str) -> str:
    if not email or "@" not in email:
        return email or ""
    local, _, domain = email.partition("@")
    visible = local[:2]
    return f"{visible}{'*' * max(1, len(local) - len(visible))}@{domain}"


def logout_view(request: HttpRequest) -> HttpResponse:
    auth_logout(request)
    return redirect("core:login")


@require_http_methods(["GET", "POST"])
def verify_otp(request: HttpRequest) -> HttpResponse:
    user_id = request.session.get(PRE_OTP_USER_KEY)
    if not user_id:
        return redirect("core:login")
    user = User.objects.filter(pk=user_id).first()
    if user is None:
        return redirect("core:login")

    if request.method == "POST":
        if "resend" in request.POST:
            if _send_otp_or_flash(request, user):
                masked = _mask_email(user.email)
                messages.info(request, f"New code sent to {masked}.")
            return redirect("core:verify_otp")

        form = OtpForm(request.POST)
        if form.is_valid():
            ok, error = verify(user, form.cleaned_data["token"])
            if ok:
                auth_login(request, user)
                request.session[OTP_VERIFIED_SESSION_KEY] = True
                request.session.pop(PRE_OTP_USER_KEY, None)
                return redirect("core:status")
            form.add_error("token", error)
    else:
        form = OtpForm()

    return render(
        request,
        "core/verify_otp.html",
        {"form": form, "username": user.username, "masked_email": _mask_email(user.email)},
    )


@otp_required
def accounts_list(request: HttpRequest) -> HttpResponse:
    accounts = EmailAccount.objects.filter(owner=request.user)
    return render(request, "core/accounts_list.html", {"accounts": accounts})


@otp_required
@require_http_methods(["GET", "POST"])
def account_new(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        form = EmailAccountForm(request.POST)
        if form.is_valid():
            account: EmailAccount = form.save(commit=False)
            account.owner = request.user
            account.save()
            messages.success(request, f"Added {account.email_address}.")
            return redirect("core:accounts_list")
    else:
        form = EmailAccountForm()
    return render(request, "core/account_form.html", {"form": form, "is_new": True})


@otp_required
@require_http_methods(["GET", "POST"])
def account_edit(request: HttpRequest, pk: int) -> HttpResponse:
    account = get_object_or_404(EmailAccount, pk=pk, owner=request.user)
    if request.method == "POST":
        form = EmailAccountForm(request.POST, instance=account)
        if form.is_valid():
            form.save()
            messages.success(request, f"Updated {account.email_address}.")
            return redirect("core:accounts_list")
    else:
        form = EmailAccountForm(instance=account)
    return render(request, "core/account_form.html", {"form": form, "is_new": False, "account": account})


@otp_required
@require_http_methods(["POST"])
def account_delete(request: HttpRequest, pk: int) -> HttpResponse:
    account = get_object_or_404(EmailAccount, pk=pk, owner=request.user)
    email = account.email_address
    account.delete()
    messages.success(request, f"Removed {email}.")
    return redirect("core:accounts_list")


@otp_required
def status(request: HttpRequest) -> HttpResponse:
    accounts = list(EmailAccount.objects.filter(owner=request.user))
    results = check_status_bulk(accounts)
    all_ok = bool(results) and all(r.ok for r in results)
    return render(
        request,
        "core/status.html",
        {"results": results, "has_accounts": bool(accounts), "all_ok": all_ok},
    )


@otp_required
def inbox(request: HttpRequest) -> HttpResponse:
    window = request.GET.get("window", "7d")
    days_map = {"1d": 1, "7d": 7, "30d": 30}
    days = days_map.get(window, 7)
    if window not in days_map:
        window = "7d"

    accounts = list(EmailAccount.objects.filter(owner=request.user))
    headers, errors = fetch_recent_bulk(accounts, days=days)

    error_rows = [
        {"account": acc, "message": errors[acc.id]}
        for acc in accounts
        if acc.id in errors
    ]

    return render(
        request,
        "core/inbox.html",
        {
            "headers": headers,
            "errors": error_rows,
            "window": window,
            "windows": [("1d", "Last 24 hours"), ("7d", "Last 7 days"), ("30d", "Last 30 days")],
            "has_accounts": bool(accounts),
        },
    )


@otp_required
def email_detail(request: HttpRequest, account_id: int, uid: str) -> HttpResponse:
    account = get_object_or_404(EmailAccount, pk=account_id, owner=request.user)
    try:
        message = fetch_body(account, uid)
    except Exception as exc:  # noqa: BLE001
        messages.error(request, f"Could not load email: {exc}")
        return redirect(reverse("core:inbox") + f"?window={request.GET.get('window', '7d')}")

    if message is None:
        messages.error(request, "Email not found.")
        return redirect("core:inbox")

    return render(
        request,
        "core/email_detail.html",
        {"message": message, "account": account, "back_window": request.GET.get("window", "7d")},
    )
