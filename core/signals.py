"""Connect Django's built-in auth signals to the AuthEvent audit log.

Wired via `CoreConfig.ready()` so handlers register at app startup. Custom
events (OTP issued/verified/failed) are logged directly from the email_otp
module rather than via signals, because Django doesn't ship signals for the
post-password second-factor step.
"""

from __future__ import annotations

from typing import Any

from django.contrib.auth.signals import (
    user_logged_in,
    user_logged_out,
    user_login_failed,
)
from django.dispatch import receiver

from .audit import log_auth_event
from .models import AuthEvent


@receiver(user_logged_in)
def _on_logged_in(sender: Any, request: Any, user: Any, **kwargs: Any) -> None:
    log_auth_event(request, AuthEvent.EventType.LOGIN_SUCCESS, user=user)


@receiver(user_logged_out)
def _on_logged_out(sender: Any, request: Any, user: Any, **kwargs: Any) -> None:
    log_auth_event(request, AuthEvent.EventType.LOGOUT, user=user)


@receiver(user_login_failed)
def _on_login_failed(sender: Any, credentials: Any, request: Any = None, **kwargs: Any) -> None:
    username = (credentials or {}).get("username", "") if isinstance(credentials, dict) else ""
    log_auth_event(request, AuthEvent.EventType.LOGIN_FAILED, username=username)
