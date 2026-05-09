from __future__ import annotations

import logging

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

RESEND_API_URL = "https://api.resend.com/emails"
RESEND_TIMEOUT = 10
TOKEN_TTL_MINUTES = 60


class ResetDeliveryError(Exception):
    """Raised when the password-reset email cannot be sent."""


def send_reset_email(to_email: str, reset_url: str) -> None:
    api_key = getattr(settings, "RESEND_API_KEY", "")
    from_email = getattr(settings, "RESEND_FROM_EMAIL", "onboarding@resend.dev")
    if not api_key:
        raise ResetDeliveryError("RESEND_API_KEY is not configured.")

    subject = "Reset your Mail.Ru Manager password"
    text = (
        "We received a request to reset your password.\n\n"
        f"Open this link to choose a new password:\n{reset_url}\n\n"
        f"The link is valid for {TOKEN_TTL_MINUTES} minutes.\n\n"
        "If you didn't request this, you can safely ignore this email."
    )
    html = (
        f"<p>We received a request to reset your password.</p>"
        f"<p><a href=\"{reset_url}\">Click here to choose a new password</a>.</p>"
        f"<p style=\"color:#666;font-size:13px;\">"
        f"Or copy this link into your browser:<br>"
        f"<span style=\"word-break:break-all;\">{reset_url}</span></p>"
        f"<p>The link is valid for {TOKEN_TTL_MINUTES} minutes.</p>"
        f"<p style=\"color:#666;font-size:12px;\">"
        f"If you didn't request this, you can safely ignore this email.</p>"
    )

    response = requests.post(
        RESEND_API_URL,
        headers={"Authorization": f"Bearer {api_key}"},
        json={"from": from_email, "to": [to_email], "subject": subject, "text": text, "html": html},
        timeout=RESEND_TIMEOUT,
    )
    if not response.ok:
        logger.error("Resend reset send failed: %s %s", response.status_code, response.text[:500])
        raise ResetDeliveryError(f"Resend returned {response.status_code}.")
