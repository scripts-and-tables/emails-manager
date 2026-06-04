from __future__ import annotations

import csv
from io import StringIO

from django.contrib import messages
from django.contrib.auth import get_user_model, update_session_auth_hash
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.forms import AuthenticationForm, SetPasswordForm
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ValidationError
from django.core.signing import BadSignature, SignatureExpired
from django.core.signing import dumps as sign_dumps
from django.core.signing import loads as sign_loads
from django.core.validators import validate_email
from django.db.models import Count
from django.db.models.functions import Lower
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.views.decorators.http import require_http_methods

from .decorators import OTP_VERIFIED_SESSION_KEY, is_otp_verified, otp_required, staff_required
from .email_otp import OtpDeliveryError, issue_and_send, verify
from .email_verify import VerifyDeliveryError, send_verification_email
from .forms import (
    AliasFormSet,
    BulkAccountForm,
    EmailAccountForm,
    OtpForm,
    PasswordResetRequestForm,
    ProfileInfoForm,
    SignupForm,
)
from .imap_client import (
    ALLOWED_SEMANTIC_FOLDERS,
    check_status,
    delete_message,
    fetch_body,
    fetch_recent_bulk,
    mark_unseen,
)
from .limits import can_bulk_add, get_account_usage, is_at_account_limit, is_premium
from .models import EmailAccount, UserPreferences
from .password_reset import ResetDeliveryError, send_reset_email
from .rate_limit import is_rate_limited

User = get_user_model()

PRE_OTP_USER_KEY = "pre_otp_user_id"


def _stamp_first_login(user) -> None:
    """Record the first successful sign-in. No-op on subsequent logins."""
    prefs, _ = UserPreferences.objects.get_or_create(user=user)
    if prefs.first_login_at is None:
        prefs.first_login_at = timezone.now()
        prefs.save(update_fields=["first_login_at", "updated_at"])


def _send_otp_or_flash(request: HttpRequest, user) -> bool:
    try:
        issue_and_send(user, request=request)
        return True
    except OtpDeliveryError as exc:
        messages.error(request, f"Could not send the verification code: {exc}")
        return False


def index(request: HttpRequest) -> HttpResponse:
    if request.user.is_authenticated and is_otp_verified(request):
        return redirect("core:home")
    return render(request, "core/landing.html")


@otp_required
def home(request: HttpRequest) -> HttpResponse:
    used, limit = get_account_usage(request.user)
    return render(
        request,
        "core/home.html",
        {
            "account_count": used,
            "account_limit": limit,
            "is_premium": is_premium(request.user),
        },
    )


@otp_required
@require_http_methods(["GET"])
def guide(request: HttpRequest) -> HttpResponse:
    return render(request, "core/guide.html")


@require_http_methods(["GET", "POST"])
def login_view(request: HttpRequest) -> HttpResponse:
    if request.user.is_authenticated and is_otp_verified(request):
        return redirect("core:home")

    if request.method == "POST":
        if is_rate_limited(request, "login", max_per_window=20, window_seconds=300):
            messages.error(request, "Too many sign-in attempts. Try again in a few minutes.")
            return render(request, "core/login.html", {"form": AuthenticationForm(request)})

        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            prefs, _ = UserPreferences.objects.get_or_create(user=user)
            if not prefs.two_factor_enabled:
                auth_login(request, user)
                _stamp_first_login(user)
                request.session[OTP_VERIFIED_SESSION_KEY] = True
                request.session.pop(PRE_OTP_USER_KEY, None)
                return redirect("core:home")
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
        if is_rate_limited(request, "otp", max_per_window=15, window_seconds=300, extra=str(user_id)):
            messages.error(request, "Too many verification attempts. Sign in again.")
            request.session.pop(PRE_OTP_USER_KEY, None)
            return redirect("core:login")

        if "resend" in request.POST:
            if _send_otp_or_flash(request, user):
                masked = _mask_email(user.email)
                messages.info(request, f"New code sent to {masked}.")
            return redirect("core:verify_otp")

        form = OtpForm(request.POST)
        if form.is_valid():
            ok, error = verify(user, form.cleaned_data["token"], request=request)
            if ok:
                auth_login(request, user)
                _stamp_first_login(user)
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
    accounts = (
        EmailAccount.objects.filter(owner=request.user)
        .annotate(alias_count=Count("aliases"))
        .prefetch_related("aliases")
        .order_by(Lower("email_address"))
    )
    used, limit = get_account_usage(request.user)
    at_limit = limit is not None and used >= limit
    return render(
        request,
        "core/accounts_list.html",
        {
            "accounts": accounts,
            "account_count": used,
            "account_limit": limit,
            "at_limit": at_limit,
        },
    )


@otp_required
@require_http_methods(["GET", "POST"])
def account_new(request: HttpRequest) -> HttpResponse:
    # Cap check on both GET and POST so a stale form can't bypass via direct submit.
    # Race note: two simultaneous POSTs from the same user at limit-1 can both pass
    # this check and end up over the cap. Accepted for cap=3.
    if is_at_account_limit(request.user):
        messages.error(
            request,
            "You've reached the account limit for this instance.",
        )
        return redirect("core:accounts_list")
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
def account_detail(request: HttpRequest, pk: int) -> HttpResponse:
    account = get_object_or_404(EmailAccount, pk=pk, owner=request.user)
    return render(request, "core/account_detail.html", {"account": account})


@otp_required
@require_http_methods(["GET", "POST"])
def account_edit(request: HttpRequest, pk: int) -> HttpResponse:
    account = get_object_or_404(EmailAccount, pk=pk, owner=request.user)
    if request.method == "POST":
        form = EmailAccountForm(request.POST, instance=account)
        formset = AliasFormSet(request.POST, instance=account)
        if form.is_valid() and formset.is_valid():
            form.save()
            formset.save()
            messages.success(request, f"Updated {account.email_address}.")
            return redirect("core:accounts_list")
    else:
        form = EmailAccountForm(instance=account)
        formset = AliasFormSet(instance=account)
    return render(
        request,
        "core/account_form.html",
        {"form": form, "formset": formset, "is_new": False, "account": account},
    )


@otp_required
@require_http_methods(["POST"])
def account_delete(request: HttpRequest, pk: int) -> HttpResponse:
    account = get_object_or_404(EmailAccount, pk=pk, owner=request.user)
    email = account.email_address
    account.delete()
    messages.success(request, f"Removed {email}.")
    return redirect("core:accounts_list")


def _parse_bulk_csv(text: str) -> tuple[list[dict], list[tuple[int, str]]]:
    """Parse pasted CSV. Returns (rows, errors). Each row: line, email, password, host, port."""
    rows: list[dict] = []
    errors: list[tuple[int, str]] = []
    reader = csv.reader(StringIO(text))
    for line_num, raw in enumerate(reader, start=1):
        if not raw or all(not (c or "").strip() for c in raw):
            continue
        first = (raw[0] or "").strip()
        if first.startswith("#"):
            continue
        if line_num == 1 and first.lower() in ("email", "email_address"):
            continue
        try:
            email = first
            password = (raw[1].strip() if len(raw) > 1 else "")
            host = (raw[2].strip() if len(raw) > 2 and raw[2].strip() else "imap.mail.ru")
            port_text = (raw[3].strip() if len(raw) > 3 and raw[3].strip() else "993")
            port = int(port_text)
        except (IndexError, ValueError) as exc:
            errors.append((line_num, f"Bad row: {exc}"))
            continue
        if not email:
            errors.append((line_num, "Missing email"))
            continue
        if not password:
            errors.append((line_num, "Missing password"))
            continue
        rows.append({"line": line_num, "email": email, "password": password, "host": host, "port": port})
    return rows, errors


@otp_required
@require_http_methods(["GET", "POST"])
def account_bulk_add(request: HttpRequest) -> HttpResponse:
    if not can_bulk_add(request.user):
        messages.error(request, "Bulk add isn't available on this account.")
        return redirect("core:limits")
    used, limit = get_account_usage(request.user)
    at_limit = limit is not None and used >= limit
    ctx = {"account_count": used, "account_limit": limit, "at_limit": at_limit}
    if request.method == "POST":
        form = BulkAccountForm(request.POST)
        if form.is_valid():
            rows, parse_errors = _parse_bulk_csv(form.cleaned_data["csv_text"])
            existing = {
                e.lower()
                for e in EmailAccount.objects.filter(owner=request.user)
                .values_list("email_address", flat=True)
            }
            # remaining=None means unlimited; otherwise count down per accepted row.
            remaining = None if limit is None else max(0, limit - len(existing))
            added = 0
            skipped: list[tuple[int, str]] = []
            skipped_limit: list[tuple[int, str]] = []
            row_errors: list[tuple[int, str]] = list(parse_errors)
            for row in rows:
                email = row["email"]
                # Duplicate check first: a duplicate doesn't consume a slot, so
                # users at-cap with duplicate rows still get clean "already exists"
                # labels rather than misleading "limit reached" labels.
                if email.lower() in existing:
                    skipped.append((row["line"], email))
                    continue
                if remaining is not None and remaining <= 0:
                    skipped_limit.append((row["line"], email))
                    continue
                try:
                    validate_email(email)
                except ValidationError:
                    row_errors.append((row["line"], f"Invalid email: {email}"))
                    continue
                try:
                    account = EmailAccount(
                        owner=request.user,
                        email_address=email,
                        imap_host=row["host"],
                        imap_port=row["port"],
                    )
                    account.set_password(row["password"])
                    account.save()
                    existing.add(email.lower())
                    added += 1
                    if remaining is not None:
                        remaining -= 1
                except Exception as exc:  # noqa: BLE001
                    row_errors.append((row["line"], str(exc)))

            # Recompute usage after the bulk run for accurate context.
            used_after, _ = get_account_usage(request.user)
            at_limit_after = limit is not None and used_after >= limit
            return render(
                request,
                "core/account_bulk.html",
                {
                    "form": BulkAccountForm(),
                    "result": {
                        "total": len(rows),
                        "added": added,
                        "skipped": skipped,
                        "skipped_limit": skipped_limit,
                        "errors": row_errors,
                    },
                    "account_count": used_after,
                    "account_limit": limit,
                    "at_limit": at_limit_after,
                },
            )
    else:
        form = BulkAccountForm()
    return render(request, "core/account_bulk.html", {"form": form, **ctx})


@otp_required
@require_http_methods(["POST"])
def account_test(request: HttpRequest, pk: int) -> JsonResponse:
    account = get_object_or_404(EmailAccount, pk=pk, owner=request.user)
    result = check_status(account)
    return JsonResponse({"ok": result.ok, "message": result.message})


@otp_required
@require_http_methods(["POST"])
def account_toggle(request: HttpRequest, pk: int) -> JsonResponse:
    account = get_object_or_404(EmailAccount, pk=pk, owner=request.user)
    account.is_enabled = request.POST.get("enabled") == "1"
    account.save(update_fields=["is_enabled", "updated_at"])
    return JsonResponse({"is_enabled": account.is_enabled})


@otp_required
@require_http_methods(["POST"])
def account_update_password(request: HttpRequest, pk: int) -> JsonResponse:
    account = get_object_or_404(EmailAccount, pk=pk, owner=request.user)
    new_password = (request.POST.get("password") or "").strip()
    if not new_password:
        return JsonResponse({"ok": False, "error": "Password is required."}, status=400)
    account.set_password(new_password)
    account.save(update_fields=["encrypted_password", "updated_at"])
    return JsonResponse({"ok": True})


FOLDER_CHOICES = [
    ("inbox", "Inbox"),
    ("sent", "Sent"),
    ("drafts", "Drafts"),
    ("spam", "Spam"),
    ("trash", "Trash"),
]


def _normalize_folder(raw: str | None) -> str:
    folder = (raw or "inbox").lower()
    return folder if folder in ALLOWED_SEMANTIC_FOLDERS else "inbox"


def _resolve_inbox_params(request: HttpRequest):
    """Shared by inbox() and inbox_data(): parse window + filter_account
    + filter_group + folder + compute account-state flags. Returns a dict
    suitable for template ctx."""
    window = request.GET.get("window", "1d")
    days_map = {"1d": 1, "7d": 7, "30d": 30}
    days = days_map.get(window, 1)
    if window not in days_map:
        window = "1d"

    folder = _normalize_folder(request.GET.get("folder"))

    all_accounts = list(EmailAccount.objects.filter(owner=request.user))

    filter_account = None
    raw_filter = request.GET.get("account")
    if raw_filter:
        try:
            filter_pk = int(raw_filter)
        except (TypeError, ValueError):
            filter_pk = None
        if filter_pk is not None:
            filter_account = next((a for a in all_accounts if a.pk == filter_pk), None)

    filter_group = (request.GET.get("group") or "").strip()
    # Empty string and missing both treated as "no group filter"

    if filter_account is not None:
        accounts = [filter_account]
    elif filter_group:
        accounts = [a for a in all_accounts if a.is_enabled and a.group == filter_group]
    else:
        accounts = [a for a in all_accounts if a.is_enabled]

    return {
        "window": window,
        "days": days,
        "folder": folder,
        "all_accounts": all_accounts,
        "accounts": accounts,
        "filter_account": filter_account,
        "filter_group": filter_group,
    }


@otp_required
def inbox(request: HttpRequest) -> HttpResponse:
    """Render the inbox shell instantly (no IMAP). Real headers are loaded by
    inbox_data via fetch() once the page is up."""
    p = _resolve_inbox_params(request)
    all_accounts = p["all_accounts"]
    enabled_accounts = [a for a in all_accounts if a.is_enabled]
    data_qs = request.GET.urlencode()
    return render(
        request,
        "core/inbox.html",
        {
            "window": p["window"],
            "windows": [("1d", "Last 24 hours"), ("7d", "Last 7 days"), ("30d", "Last 30 days")],
            "folder": p["folder"],
            "folders": FOLDER_CHOICES,
            "has_accounts": bool(all_accounts),
            "all_disabled": bool(all_accounts) and not enabled_accounts and p["filter_account"] is None and not p["filter_group"],
            "filter_account": p["filter_account"],
            "filter_group": p["filter_group"],
            "data_url": reverse("core:inbox_data") + (f"?{data_qs}" if data_qs else ""),
        },
    )


@otp_required
def inbox_data(request: HttpRequest) -> HttpResponse:
    """Returns just the inbox content (errors + rows + count + empty state)
    as an HTML fragment. Called by the inbox shell via fetch()."""
    p = _resolve_inbox_params(request)
    accounts = p["accounts"]
    headers, errors = fetch_recent_bulk(accounts, days=p["days"], folder=p["folder"])
    error_rows = [
        {"account": acc, "message": errors[acc.id]}
        for acc in accounts
        if acc.id in errors
    ]
    return render(
        request,
        "core/_inbox_content.html",
        {
            "headers": headers,
            "errors": error_rows,
            "window": p["window"],
            "folder": p["folder"],
            "filter_account": p["filter_account"],
            "filter_group": p["filter_group"],
        },
    )


@otp_required
def email_detail(request: HttpRequest, account_id: int, uid: str) -> HttpResponse:
    account = get_object_or_404(EmailAccount, pk=account_id, owner=request.user)
    folder = _normalize_folder(request.GET.get("folder"))
    try:
        message = fetch_body(account, uid, folder=folder)
    except Exception as exc:  # noqa: BLE001
        messages.error(request, f"Could not load email: {exc}")
        back_qs = f"?window={request.GET.get('window', '1d')}&folder={folder}"
        if request.GET.get("account"):
            back_qs += f"&account={request.GET.get('account')}"
        return redirect(reverse("core:inbox") + back_qs)

    if message is None:
        messages.error(request, "Email not found.")
        return redirect("core:inbox")

    # Remote images are blocked by the site CSP (img-src 'self' data:) by
    # default — loading them lets a sender confirm the email was opened. The
    # user opts in per-message via ?images=1, which relaxes img-src to allow
    # https: for *this response only* (the sandboxed srcdoc iframe inherits it).
    show_images = request.GET.get("images") == "1"
    response = render(
        request,
        "core/email_detail.html",
        {
            "message": message,
            "account": account,
            "uid": uid,
            "back_window": request.GET.get("window", "1d"),
            "back_account": request.GET.get("account") or "",
            "back_folder": folder,
            "show_images": show_images,
        },
    )
    if show_images:
        response._csp_update = {"img-src": ["https:"]}
    return response


def _back_to_inbox_url(request: HttpRequest) -> str:
    qs = f"?window={request.POST.get('back_window') or request.GET.get('window') or '1d'}"
    folder = _normalize_folder(request.POST.get("back_folder") or request.GET.get("folder"))
    qs += f"&folder={folder}"
    back_account = request.POST.get("back_account") or request.GET.get("account") or ""
    if back_account:
        qs += f"&account={back_account}"
    return reverse("core:inbox") + qs


@otp_required
@require_http_methods(["POST"])
def email_mark_unread(request: HttpRequest, account_id: int, uid: str) -> HttpResponse:
    account = get_object_or_404(EmailAccount, pk=account_id, owner=request.user)
    folder = _normalize_folder(request.POST.get("back_folder"))
    try:
        mark_unseen(account, uid, folder=folder)
        messages.success(request, "Marked as unread.")
    except Exception as exc:  # noqa: BLE001
        messages.error(request, f"Couldn't mark as unread: {exc}")
    return redirect(_back_to_inbox_url(request))


@otp_required
@require_http_methods(["POST"])
def email_delete(request: HttpRequest, account_id: int, uid: str) -> HttpResponse:
    account = get_object_or_404(EmailAccount, pk=account_id, owner=request.user)
    folder = _normalize_folder(request.POST.get("back_folder"))
    try:
        delete_message(account, uid, folder=folder)
        messages.success(request, "Email deleted.")
    except Exception as exc:  # noqa: BLE001
        messages.error(request, f"Couldn't delete: {exc}")
    return redirect(_back_to_inbox_url(request))


@require_http_methods(["GET", "POST"])
def password_reset_request(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        form = PasswordResetRequestForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data["email"].strip()
            limited = is_rate_limited(
                request, "pwreset", max_per_window=5, window_seconds=3600,
                extra=email.lower(),
            )
            if not limited:
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
            auth_logout(request)
            return redirect("core:password_reset_complete")
    else:
        form = SetPasswordForm(user)
        for field in form.fields.values():
            field.widget.attrs.setdefault("class", "form-control")

    return render(request, "core/password_reset_confirm.html", {"form": form, "valid_link": True})


def password_reset_complete(request: HttpRequest) -> HttpResponse:
    return render(request, "core/password_reset_complete.html")


SIGNUP_TOKEN_SALT = "signup-verify"
SIGNUP_TOKEN_TTL = 60 * 60 * 24  # 24h


@require_http_methods(["GET", "POST"])
def signup(request: HttpRequest) -> HttpResponse:
    if request.user.is_authenticated and is_otp_verified(request):
        return redirect("core:home")

    form = SignupForm()
    _add_bootstrap_class(form)

    if request.method == "POST":
        if is_rate_limited(request, "signup", max_per_window=5, window_seconds=3600):
            messages.error(request, "Too many sign-up attempts. Try again in a few minutes.")
            return render(request, "core/signup.html", {"form": form, "sent": False})

        form = SignupForm(request.POST)
        _add_bootstrap_class(form)
        if form.is_valid():
            user = form.save()
            token = sign_dumps(user.pk, salt=SIGNUP_TOKEN_SALT)
            verify_url = request.build_absolute_uri(
                reverse("core:signup_verify", args=[token])
            )
            try:
                send_verification_email(user.email, verify_url)
            except VerifyDeliveryError:
                user.delete()
                messages.error(
                    request,
                    "We couldn't send the verification email right now. "
                    "Please try again in a few minutes, or contact support if the issue persists.",
                )
                return render(request, "core/signup.html", {"form": form, "sent": False})
            return render(
                request,
                "core/signup.html",
                {"form": SignupForm(), "sent": True, "sent_email": user.email},
            )

    return render(request, "core/signup.html", {"form": form, "sent": False})


def signup_verify(request: HttpRequest, token: str) -> HttpResponse:
    user = None
    try:
        pk = sign_loads(token, salt=SIGNUP_TOKEN_SALT, max_age=SIGNUP_TOKEN_TTL)
        user = User.objects.filter(pk=pk).first()
    except (BadSignature, SignatureExpired):
        user = None

    if user is None:
        return render(request, "core/signup_verify.html", {"valid": False})

    if user.is_active:
        messages.info(request, "Your email is already verified. Sign in to continue.")
        return redirect("core:login")

    user.is_active = True
    user.save(update_fields=["is_active"])
    return render(request, "core/signup_verify.html", {"valid": True})


def _add_bootstrap_class(form, css_class: str = "form-control") -> None:
    for field in form.fields.values():
        field.widget.attrs.setdefault("class", css_class)


@otp_required
@require_http_methods(["GET", "POST"])
def profile(request: HttpRequest) -> HttpResponse:
    info_form = ProfileInfoForm(instance=request.user)
    password_form = SetPasswordForm(request.user)
    _add_bootstrap_class(password_form)
    prefs, _ = UserPreferences.objects.get_or_create(user=request.user)

    if request.method == "POST":
        info_form = ProfileInfoForm(request.POST, instance=request.user)
        if info_form.is_valid():
            info_form.save()
            messages.success(request, "Profile updated.")
            return redirect("core:profile")

    return render(
        request,
        "core/profile.html",
        {
            "info_form": info_form,
            "password_form": password_form,
            "password_modal_open": False,
            "two_factor_enabled": prefs.two_factor_enabled,
        },
    )


@otp_required
@require_http_methods(["POST"])
def profile_password_change(request: HttpRequest) -> HttpResponse:
    if is_rate_limited(request, "pwchange", max_per_window=10, window_seconds=300, extra=str(request.user.pk)):
        messages.error(request, "Too many password changes. Try again in a few minutes.")
        return redirect("core:profile")
    password_form = SetPasswordForm(request.user, request.POST)
    _add_bootstrap_class(password_form)
    if password_form.is_valid():
        user = password_form.save()
        update_session_auth_hash(request, user)
        messages.success(request, "Password changed.")
        return redirect("core:profile")

    info_form = ProfileInfoForm(instance=request.user)
    prefs, _ = UserPreferences.objects.get_or_create(user=request.user)
    return render(
        request,
        "core/profile.html",
        {
            "info_form": info_form,
            "password_form": password_form,
            "password_modal_open": True,
            "two_factor_enabled": prefs.two_factor_enabled,
        },
    )


@otp_required
def limits(request: HttpRequest) -> HttpResponse:
    used, limit = get_account_usage(request.user)
    return render(
        request,
        "core/limits.html",
        {
            "account_count": used,
            "account_limit": limit,
            "is_premium": is_premium(request.user),
        },
    )


@staff_required
def staff_users(request: HttpRequest) -> HttpResponse:
    from django.db.models import Count, OuterRef, Subquery

    first_login_qs = UserPreferences.objects.filter(user=OuterRef("pk")).values("first_login_at")[:1]
    users = (
        User.objects.all()
        .annotate(
            account_count=Count("email_accounts", distinct=True),
            first_login_at=Subquery(first_login_qs),
        )
        .order_by("-date_joined")
    )
    return render(
        request,
        "core/staff_users.html",
        {
            "users": users,
            "user_count": users.count(),
        },
    )


@otp_required
@require_http_methods(["POST"])
def profile_2fa_toggle(request: HttpRequest) -> HttpResponse:
    enabled = request.POST.get("enabled") == "1"
    prefs, _ = UserPreferences.objects.get_or_create(user=request.user)
    prefs.two_factor_enabled = enabled
    prefs.save(update_fields=["two_factor_enabled", "updated_at"])
    if enabled:
        messages.success(request, "Two-factor authentication is on. You'll get a code on your next sign-in.")
    else:
        messages.warning(request, "Two-factor authentication is off. Sign-in now uses just username and password.")
    return redirect("core:profile")
