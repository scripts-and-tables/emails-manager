"""Tests for the password reset request, confirm, and complete views.

The Resend network call is mocked everywhere; we don't want tests depending
on outbound email delivery."""

from __future__ import annotations

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

User = get_user_model()


def _ok_resend_response():
    class _Resp:
        ok = True
        status_code = 200
        text = ""

    return _Resp()


@override_settings(RESEND_API_KEY="test-key", RESEND_FROM_EMAIL="test@example.com")
class PasswordResetRequestTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(
            username="alice", email="alice@example.com", password="old-password"
        )

    def test_get_renders_form(self):
        response = self.client.get(reverse("core:password_reset_request"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'name="email"')

    @patch("core.password_reset.requests.post")
    def test_post_known_email_sends_reset_link(self, mock_post):
        mock_post.return_value = _ok_resend_response()

        response = self.client.post(
            reverse("core:password_reset_request"),
            {"email": "alice@example.com"},
        )

        # The view re-renders the same template with sent=True (rather than
        # redirecting) — see core/views.py.password_reset_request.
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["sent"])
        self.assertEqual(mock_post.call_count, 1)
        self.assertIn("alice@example.com", mock_post.call_args.kwargs["json"]["to"])

    @patch("core.password_reset.requests.post")
    def test_post_unknown_email_does_not_send_but_returns_same_response(self, mock_post):
        # User-enumeration defence: response is indistinguishable from the
        # success case, but no email is actually sent.
        response = self.client.post(
            reverse("core:password_reset_request"),
            {"email": "nobody@example.com"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["sent"])
        mock_post.assert_not_called()


class PasswordResetConfirmTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(
            username="alice", email="alice@example.com", password="old-password"
        )
        self.uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
        self.token = default_token_generator.make_token(self.user)

    def _url(self, uidb64=None, token=None):
        return reverse(
            "core:password_reset_confirm",
            kwargs={"uidb64": uidb64 or self.uidb64, "token": token or self.token},
        )

    def test_get_with_valid_token_renders_set_password_form(self):
        response = self.client.get(self._url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'name="new_password1"')
        self.assertContains(response, 'name="new_password2"')

    def test_post_valid_token_updates_password(self):
        response = self.client.post(
            self._url(),
            {"new_password1": "fresh-passphrase-99", "new_password2": "fresh-passphrase-99"},
        )

        self.assertEqual(response.status_code, 302)
        # User can now log in with the new password.
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("fresh-passphrase-99"))
        self.assertFalse(self.user.check_password("old-password"))

    def test_invalid_token_is_rejected(self):
        response = self.client.get(self._url(token="bogus-token"))
        # The view renders the page but the form is hidden / disabled. Exact
        # behaviour is to show a "link is invalid" message and not accept POSTs.
        self.assertEqual(response.status_code, 200)
        # Posting with the bad token must not change the password.
        self.client.post(
            self._url(token="bogus-token"),
            {"new_password1": "fresh-passphrase-99", "new_password2": "fresh-passphrase-99"},
        )
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("old-password"))

    def test_mismatched_passwords_keep_old_password(self):
        self.client.post(
            self._url(),
            {"new_password1": "fresh-passphrase-99", "new_password2": "different-passphrase-99"},
        )
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("old-password"))
