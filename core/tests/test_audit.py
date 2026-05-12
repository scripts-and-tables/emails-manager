"""Tests for the AuthEvent audit log.

Cover the three Django auth signals (login, logout, login_failed) and the two
direct call sites in core.email_otp (verify success / fail). The OTP_ISSUED
path isn't covered here because it requires mocking the Resend API; the
signal handlers and direct-call wiring are the load-bearing parts.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from core.email_otp import verify
from core.models import AuthEvent, LoginOtp

User = get_user_model()


class AuthEventSignalTests(TestCase):
    """The user_logged_in / user_logged_out / user_login_failed signal hooks
    wired in core.signals.py must produce AuthEvent rows."""

    def setUp(self):
        self.user = User.objects.create_user(
            username="alice", email="alice@example.com", password="correct-horse-battery"
        )

    def test_successful_login_records_event(self):
        ok = self.client.login(username="alice", password="correct-horse-battery")
        self.assertTrue(ok)
        events = list(
            AuthEvent.objects.filter(event_type=AuthEvent.EventType.LOGIN_SUCCESS)
        )
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.user, self.user)
        self.assertEqual(event.username, "alice")

    def test_logout_records_event(self):
        self.client.login(username="alice", password="correct-horse-battery")
        AuthEvent.objects.all().delete()  # clear the login event
        self.client.logout()
        events = list(AuthEvent.objects.filter(event_type=AuthEvent.EventType.LOGOUT))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].user, self.user)

    def test_failed_login_records_event_with_username(self):
        # POST to the login view with a wrong password so the auth backend
        # fires the user_login_failed signal.
        self.client.post(
            reverse("core:login"),
            {"username": "alice", "password": "wrong-password"},
        )
        events = list(
            AuthEvent.objects.filter(event_type=AuthEvent.EventType.LOGIN_FAILED)
        )
        self.assertEqual(len(events), 1)
        event = events[0]
        # No FK because the credentials didn't authenticate, but the attempted
        # username is captured for forensics.
        self.assertIsNone(event.user)
        self.assertEqual(event.username, "alice")


class OtpAuditTests(TestCase):
    """Direct calls to email_otp.verify produce OTP_VERIFIED / OTP_FAILED."""

    def setUp(self):
        self.user = User.objects.create_user(
            username="bob", email="bob@example.com", password="x"
        )
        # Issue a known OTP by going around the Resend-backed send path.
        self.code = "123456"
        LoginOtp.issue(self.user, self.code, ttl_seconds=600)

    def test_correct_code_records_otp_verified(self):
        ok, _err = verify(self.user, self.code)
        self.assertTrue(ok)
        events = list(
            AuthEvent.objects.filter(event_type=AuthEvent.EventType.OTP_VERIFIED)
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].user, self.user)

    def test_wrong_code_records_otp_failed(self):
        ok, _err = verify(self.user, "000000")
        self.assertFalse(ok)
        events = list(
            AuthEvent.objects.filter(event_type=AuthEvent.EventType.OTP_FAILED)
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].user, self.user)
