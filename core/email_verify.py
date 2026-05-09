"""Send signup verification emails via the Resend HTTP API.

Mirrors core/password_reset.py — same Resend client shape, separate
file because the two emails serve very different flows.
"""

from __future__ import annotations

import logging

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

RESEND_API_URL = "https://api.resend.com/emails"
RESEND_TIMEOUT = 10
TOKEN_TTL_HOURS = 24


class VerifyDeliveryError(Exception):
    """Raised when the signup verification email cannot be sent."""


def send_verification_email(to_email: str, verify_url: str) -> None:
    api_key = getattr(settings, "RESEND_API_KEY", "")
    from_email = getattr(settings, "RESEND_FROM_EMAIL", "onboarding@resend.dev")
    if not api_key:
        raise VerifyDeliveryError("RESEND_API_KEY is not configured.")

    subject = "Verify your Mails Manager App email"
    text = (
        "Welcome to Mails Manager App!\n\n"
        f"Open this link to verify your email and finish signing up:\n{verify_url}\n\n"
        f"The link is valid for {TOKEN_TTL_HOURS} hours.\n\n"
        "If you didn't sign up, you can safely ignore this email."
    )
    html = (
        f"<p>Welcome to Mails Manager App!</p>"
        f"<p><a href=\"{verify_url}\">Click here to verify your email</a> and finish signing up.</p>"
        f"<p style=\"color:#666;font-size:13px;\">"
        f"Or copy this link into your browser:<br>"
        f"<span style=\"word-break:break-all;\">{verify_url}</span></p>"
        f"<p>The link is valid for {TOKEN_TTL_HOURS} hours.</p>"
        f"<p style=\"color:#666;font-size:12px;\">"
        f"If you didn't sign up, you can safely ignore this email.</p>"
    )

    try:
        response = requests.post(
            RESEND_API_URL,
            headers={"Authorization": f"Bearer {api_key}"},
            json={"from": from_email, "to": [to_email], "subject": subject, "text": text, "html": html},
            timeout=RESEND_TIMEOUT,
        )
    except requests.exceptions.RequestException as exc:
        logger.error("Resend verify network error: %s", exc)
        raise VerifyDeliveryError("Could not contact email provider.") from exc
    if not response.ok:
        logger.error("Resend verify send failed: %s %s", response.status_code, response.text[:500])
        raise VerifyDeliveryError(f"Resend returned {response.status_code}.")
