from __future__ import annotations

import logging
import secrets
from typing import Any

import requests
from django.conf import settings

from .audit import log_auth_event
from .models import AuthEvent, LoginOtp

logger = logging.getLogger(__name__)

OTP_LENGTH = 6
OTP_TTL_SECONDS = 600  # 10 minutes
RESEND_API_URL = "https://api.resend.com/emails"
RESEND_TIMEOUT = 10


class OtpDeliveryError(Exception):
    """Raised when the OTP email cannot be sent."""


def _generate_code() -> str:
    return f"{secrets.randbelow(10 ** OTP_LENGTH):0{OTP_LENGTH}d}"


def _send_via_resend(to_email: str, code: str) -> None:
    api_key = getattr(settings, "RESEND_API_KEY", "")
    from_email = getattr(settings, "RESEND_FROM_EMAIL", "onboarding@resend.dev")
    if not api_key:
        raise OtpDeliveryError("RESEND_API_KEY is not configured.")

    subject = "Your Mails Manager App sign-in code"
    text = (
        f"Your sign-in code is {code}.\n"
        f"It expires in {OTP_TTL_SECONDS // 60} minutes.\n\n"
        "If you didn't request this, you can safely ignore the email."
    )
    html = (
        f"<p>Your sign-in code is:</p>"
        f"<p style=\"font-size:24px; font-weight:600; letter-spacing:.2em;\">{code}</p>"
        f"<p>It expires in {OTP_TTL_SECONDS // 60} minutes.</p>"
        f"<p style=\"color:#666;font-size:12px;\">If you didn't request this, you can ignore this email.</p>"
    )

    try:
        response = requests.post(
            RESEND_API_URL,
            headers={"Authorization": f"Bearer {api_key}"},
            json={"from": from_email, "to": [to_email], "subject": subject, "text": text, "html": html},
            timeout=RESEND_TIMEOUT,
        )
    except requests.exceptions.RequestException as exc:
        logger.error("Resend OTP network error: %s", exc)
        raise OtpDeliveryError("Could not contact email provider.") from exc
    if not response.ok:
        logger.error("Resend send failed: %s %s", response.status_code, response.text[:500])
        raise OtpDeliveryError(f"Resend returned {response.status_code}.")


def issue_and_send(user, request: Any = None) -> LoginOtp:
    if not user.email:
        raise OtpDeliveryError("This user has no email address on file.")
    code = _generate_code()
    otp = LoginOtp.issue(user, code, ttl_seconds=OTP_TTL_SECONDS)
    _send_via_resend(user.email, code)
    log_auth_event(request, AuthEvent.EventType.OTP_ISSUED, user=user)
    return otp


def verify(user, submitted: str, request: Any = None) -> tuple[bool, str]:
    """Returns (ok, error_message). On success the OTP is marked consumed."""
    submitted = (submitted or "").strip()
    otp = LoginOtp.objects.filter(user=user).first()
    if otp is None:
        return False, "No code was issued for this account. Sign in again."
    if otp.is_consumed():
        return False, "This code has already been used. Sign in again."
    if otp.is_expired():
        return False, "Code has expired. Sign in to receive a new one."
    if otp.is_locked():
        return False, "Too many wrong attempts. Sign in to receive a new code."
    if not otp.matches(submitted):
        otp.attempts += 1
        otp.save(update_fields=["attempts"])
        log_auth_event(request, AuthEvent.EventType.OTP_FAILED, user=user)
        return False, "Invalid code, try again."

    from django.utils import timezone
    otp.consumed_at = timezone.now()
    otp.save(update_fields=["consumed_at"])
    log_auth_event(request, AuthEvent.EventType.OTP_VERIFIED, user=user)
    return True, ""
