"""Account toggle endpoint and the rate-limiter helper."""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from django.urls import reverse

from core.models import EmailAccount
from core.rate_limit import is_rate_limited

User = get_user_model()

OTP_VERIFIED_SESSION_KEY = "otp_verified"


class AccountToggleTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="u", email="u@x.com", password="x")
        self.account = EmailAccount.objects.create(
            owner=self.user,
            email_address="me@example.com",
            imap_host="imap.example.com",
            imap_port=993,
            encrypted_password=b"placeholder-bytes-not-decrypted-in-this-test",
            is_enabled=True,
        )
        self.client.force_login(self.user)
        # otp_required decorator checks this session key.
        session = self.client.session
        session[OTP_VERIFIED_SESSION_KEY] = True
        session.save()

    def test_toggle_off_then_on(self):
        url = reverse("core:account_toggle", args=[self.account.pk])
        response = self.client.post(url, {"enabled": "0"})
        self.assertEqual(response.status_code, 200)
        self.account.refresh_from_db()
        self.assertFalse(self.account.is_enabled)

        response = self.client.post(url, {"enabled": "1"})
        self.assertEqual(response.status_code, 200)
        self.account.refresh_from_db()
        self.assertTrue(self.account.is_enabled)

    def test_other_users_account_404s(self):
        outsider = User.objects.create_user(username="outsider", email="o@x.com", password="x")
        self.client.force_login(outsider)
        session = self.client.session
        session[OTP_VERIFIED_SESSION_KEY] = True
        session.save()
        response = self.client.post(
            reverse("core:account_toggle", args=[self.account.pk]),
            {"enabled": "0"},
        )
        self.assertEqual(response.status_code, 404)


class RateLimitTests(TestCase):
    def setUp(self):
        # Fresh cache per test so counters don't bleed.
        from django.core.cache import cache
        cache.clear()
        self.factory = RequestFactory()

    def test_first_calls_pass_then_block(self):
        request = self.factory.post("/login/")
        for i in range(3):
            self.assertFalse(is_rate_limited(request, "test", max_per_window=3, window_seconds=60))
        # 4th call exceeds the budget
        self.assertTrue(is_rate_limited(request, "test", max_per_window=3, window_seconds=60))

    def test_extra_key_isolates_counters(self):
        request = self.factory.post("/login/")
        self.assertFalse(is_rate_limited(request, "test", max_per_window=1, window_seconds=60, extra="a"))
        # Different extra → independent budget
        self.assertFalse(is_rate_limited(request, "test", max_per_window=1, window_seconds=60, extra="b"))
        # Same extra exceeds
        self.assertTrue(is_rate_limited(request, "test", max_per_window=1, window_seconds=60, extra="a"))
