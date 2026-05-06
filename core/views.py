from __future__ import annotations

from django.contrib import messages
from django.contrib.auth import authenticate, get_user_model, update_session_auth_hash
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm, SetPasswordForm
from django.contrib.auth.tokens import default_token_generator
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.views.decorators.http import require_http_methods

from .decorators import OTP_VERIFIED_SESSION_KEY, is_otp_verified, otp_required
from .email_otp import OtpDeliveryError, issue_and_send, verify
from .forms import EmailAccountForm, OtpForm, PasswordResetRequestForm, ProfileInfoForm
from .imap_client import check_status, check_status_bulk, fetch_body, fetch_recent_bulk
from .models import EmailAccount
from .password_reset import ResetDeliveryError, send_reset_email

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
        return redirect("core:home")
    return redirect("core:login")


@otp_required
def home(request: HttpRequest) -> HttpResponse:
    account_count = EmailAccount.objects.filter(owner=request.user).count()
    return render(request, "core/home.html", {"account_count": account_count})


@require_http_methods(["GET", "POST"])
def login_view(request: HttpRequest) -> HttpResponse:
    if request.user.is_authenticated and is_otp_verified(request):
        return redirect("core:home")

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
                return redirect("core:home")
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
@require_http_methods(["POST"])
def account_test(request: HttpRequest, pk: int) -> JsonResponse:
    account = get_object_or_404(EmailAccount, pk=pk, owner=request.user)
    result = check_status(account)
    return JsonResponse({"ok": result.ok, "message": result.message})


@otp_required
def inbox(request: HttpRequest) -> HttpResponse:
    window = request.GET.get("window", "1d")
    days_map = {"1d": 1, "7d": 7, "30d": 30}
    days = days_map.get(window, 1)
    if window not in days_map:
        window = "1d"

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
        return redirect(reverse("core:inbox") + f"?window={request.GET.get('window', '1d')}")

    if message is None:
        messages.error(request, "Email not found.")
        return redirect("core:inbox")

    return render(
        request,
        "core/email_detail.html",
        {"message": message, "account": account, "back_window": request.GET.get("window", "1d")},
    )


@require_http_methods(["GET", "POST"])
def password_reset_request(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        form = PasswordResetRequestForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data["email"].strip()
            user = User.objects.filter(email__iexact=email).first()
            if user is not None and user.email:
                uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
                token = default_token_generator.make_token(user)
                reset_url = request.build_absolute_uri(
                    reverse("core:password_reset_confirm", args=[uidb64, token])
                )
                try:
                    send_reset_email(user.email, reset_url)
                except ResetDeliveryError:
                    pass  # logged in helper; show generic success either way
            return render(request, "core/password_reset_request.html", {"form": form, "sent": True})
    else:
        form = PasswordResetRequestForm()

    return render(request, "core/password_reset_request.html", {"form": form, "sent": False})


@require_http_methods(["GET", "POST"])
def password_reset_confirm(request: HttpRequest, uidb64: str, token: str) -> HttpResponse:
    user = None
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.filter(pk=uid).first()
    except (TypeError, ValueError, OverflowError):
        user = None

    if user is None or not default_token_generator.check_token(user, token):
        return render(request, "core/password_reset_confirm.html", {"valid_link": False})

    if request.method == "POST":
        form = SetPasswordForm(user, request.POST)
        for field in form.fields.values():
            field.widget.attrs.setdefault("class", "form-control")
        if form.is_valid():
            form.save()
            return redirect("core:password_reset_complete")
    else:
        form = SetPasswordForm(user)
        for field in form.fields.values():
            field.widget.attrs.setdefault("class", "form-control")

    return render(request, "core/password_reset_confirm.html", {"form": form, "valid_link": True})


def password_reset_complete(request: HttpRequest) -> HttpResponse:
    return render(request, "core/password_reset_complete.html")


def _add_bootstrap_class(form, css_class: str = "form-control") -> None:
    for field in form.fields.values():
        field.widget.attrs.setdefault("class", css_class)


@otp_required
@require_http_methods(["GET", "POST"])
def profile(request: HttpRequest) -> HttpResponse:
    info_form = ProfileInfoForm(instance=request.user)
    password_form = PasswordChangeForm(request.user)
    _add_bootstrap_class(password_form)

    if request.method == "POST":
        info_form = ProfileInfoForm(request.POST, instance=request.user)
        if info_form.is_valid():
            info_form.save()
            messages.success(request, "Profile updated.")
            return redirect("core:profile")

    return render(request, "core/profile.html", {"info_form": info_form, "password_form": password_form})


@otp_required
@require_http_methods(["POST"])
def profile_password_change(request: HttpRequest) -> HttpResponse:
    password_form = PasswordChangeForm(request.user, request.POST)
    _add_bootstrap_class(password_form)
    if password_form.is_valid():
        user = password_form.save()
        update_session_auth_hash(request, user)
        messages.success(request, "Password changed.")
        return redirect("core:profile")

    info_form = ProfileInfoForm(instance=request.user)
    return render(request, "core/profile.html", {"info_form": info_form, "password_form": password_form})
