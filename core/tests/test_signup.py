"""Signup flow: POST → inactive user + email sent → verify token → active."""

from __future__ import annotations

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.signing import dumps as sign_dumps
from django.test import TestCase
from django.urls import reverse

User = get_user_model()


class SignupTests(TestCase):
    def test_signup_creates_inactive_user_and_sends_email(self):
        with patch("core.views.send_verification_email") as mock_send:
            response = self.client.post(
                reverse("core:signup"),
                {
                    "username": "alice",
                    "email": "alice@example.com",
                    "first_name": "Alice",
                    "last_name": "Example",
                    "password1": "Sup3rSecr3tPass!",
                    "password2": "Sup3rSecr3tPass!",
                },
            )
        self.assertEqual(response.status_code, 200)
        user = User.objects.get(username="alice")
        self.assertFalse(user.is_active)
        self.assertEqual(user.email, "alice@example.com")
        mock_send.assert_called_once()

    def test_duplicate_email_rejected(self):
        User.objects.create_user(username="bob", email="taken@example.com", password="x")
        with patch("core.views.send_verification_email"):
            response = self.client.post(
                reverse("core:signup"),
                {
                    "username": "carol",
                    "email": "TAKEN@example.com",  # case-insensitive duplicate
                    "password1": "AnotherStr0ng!Pass",
                    "password2": "AnotherStr0ng!Pass",
                },
            )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "already exists")
        self.assertFalse(User.objects.filter(username="carol").exists())

    def test_verify_link_activates_user(self):
        user = User.objects.create_user(
            username="pending", email="pending@example.com", password="x", is_active=False,
        )
        token = sign_dumps(user.pk, salt="signup-verify")
        response = self.client.get(reverse("core:signup_verify", args=[token]))
        self.assertEqual(response.status_code, 200)
        user.refresh_from_db()
        self.assertTrue(user.is_active)

    def test_invalid_verify_token_renders_failure_page(self):
        response = self.client.get(reverse("core:signup_verify", args=["not-a-real-token"]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "invalid or expired")

    def test_already_verified_redirects_to_login(self):
        user = User.objects.create_user(
            username="active", email="active@example.com", password="x", is_active=True,
        )
        token = sign_dumps(user.pk, salt="signup-verify")
        response = self.client.get(reverse("core:signup_verify", args=[token]))
        self.assertRedirects(response, reverse("core:login"))
