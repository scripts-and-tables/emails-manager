"""Tests for the login view.

Covers: GET rendering, the password-only happy path, the 2FA branch (where
OTP issuance is mocked so we don't depend on Resend), and the rate-limit
gate."""

from __future__ import annotations

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse

from core.models import LoginOtp, UserPreferences

User = get_user_model()

OTP_VERIFIED_SESSION_KEY = "otp_verified"
PRE_OTP_USER_KEY = "pre_otp_user_id"


class LoginViewTests(TestCase):
    def setUp(self):
        cache.clear()  # rate-limit counters are cached
        self.user = User.objects.create_user(
            username="alice", email="alice@example.com", password="correct-horse-battery"
        )

    def test_get_renders_login_form(self):
        response = self.client.get(reverse("core:login"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Welcome back")
        self.assertContains(response, 'name="username"')
        self.assertContains(response, 'name="password"')

    @patch("core.views.issue_and_send")
    def test_valid_credentials_with_2fa_redirects_to_otp(self, mock_issue):
        # 2FA is on by default for new users (UserPreferences default).
        response = self.client.post(
            reverse("core:login"),
            {"username": "alice", "password": "correct-horse-battery"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("core:verify_otp"))
        mock_issue.assert_called_once()
        # Session should hold the pre-OTP user id but NOT mark OTP verified yet.
        self.assertEqual(
            self.client.session.get(PRE_OTP_USER_KEY), self.user.pk
        )
        self.assertFalse(self.client.session.get(OTP_VERIFIED_SESSION_KEY))

    def test_valid_credentials_without_2fa_redirects_to_home(self):
        # Disable 2FA explicitly.
        UserPreferences.objects.create(user=self.user, two_factor_enabled=False)
        response = self.client.post(
            reverse("core:login"),
            {"username": "alice", "password": "correct-horse-battery"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("core:home"))
        # OTP-verified flag set so subsequent requests pass the @otp_required gate.
        self.assertTrue(self.client.session.get(OTP_VERIFIED_SESSION_KEY))
        # No OTP record should have been written.
        self.assertFalse(LoginOtp.objects.filter(user=self.user).exists())

    def test_invalid_password_does_not_authenticate(self):
        response = self.client.post(
            reverse("core:login"),
            {"username": "alice", "password": "wrong-password"},
        )
        # Form re-renders with an error rather than redirecting.
        self.assertEqual(response.status_code, 200)
        self.assertFalse(self.client.session.get(OTP_VERIFIED_SESSION_KEY))
        self.assertIsNone(self.client.session.get(PRE_OTP_USER_KEY))

    def test_rate_limit_kicks_in_after_too_many_attempts(self):
        # The login endpoint allows 20 attempts per 5min window per IP.
        for _ in range(20):
            self.client.post(
                reverse("core:login"),
                {"username": "alice", "password": "wrong"},
            )
        # 21st attempt should be rate-limited; messages framework shows an
        # error and authentication is not attempted.
        response = self.client.post(
            reverse("core:login"),
            {"username": "alice", "password": "correct-horse-battery"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Too many sign-in attempts")
        # Even with the right password, no session was minted.
        self.assertFalse(self.client.session.get(OTP_VERIFIED_SESSION_KEY))

    def test_already_logged_in_user_redirects_to_home(self):
        self.client.force_login(self.user)
        session = self.client.session
        session[OTP_VERIFIED_SESSION_KEY] = True
        session.save()

        response = self.client.get(reverse("core:login"))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("core:home"))
