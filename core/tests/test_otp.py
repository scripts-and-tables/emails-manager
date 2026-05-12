"""Tests for the email-OTP issuance and verification helpers."""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from core.email_otp import OTP_TTL_SECONDS, OtpDeliveryError, issue_and_send, verify
from core.models import LoginOtp

User = get_user_model()


def _ok_resend_response():
    """Stand-in for a successful Resend HTTP response."""

    class _Resp:
        ok = True
        status_code = 200
        text = ""

    return _Resp()


@override_settings(RESEND_API_KEY="test-key", RESEND_FROM_EMAIL="test@example.com")
class IssueAndSendTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="alice", email="alice@example.com", password="x"
        )

    @patch("core.email_otp.requests.post")
    def test_creates_login_otp_record(self, mock_post):
        mock_post.return_value = _ok_resend_response()

        otp = issue_and_send(self.user)

        self.assertIsInstance(otp, LoginOtp)
        self.assertEqual(otp.user, self.user)
        self.assertGreater(otp.expires_at, timezone.now())
        self.assertEqual(otp.attempts, 0)
        self.assertIsNone(otp.consumed_at)
        # Code hash is populated (not the plaintext).
        self.assertEqual(len(otp.code_hash), 64)  # SHA-256 hex digest length

    @patch("core.email_otp.requests.post")
    def test_calls_resend_with_user_email(self, mock_post):
        mock_post.return_value = _ok_resend_response()

        issue_and_send(self.user)

        self.assertEqual(mock_post.call_count, 1)
        kwargs = mock_post.call_args.kwargs
        self.assertIn("alice@example.com", kwargs["json"]["to"])
        self.assertTrue(kwargs["json"]["subject"])

    def test_raises_when_user_has_no_email(self):
        no_email_user = User.objects.create_user(username="bob", email="", password="x")
        with self.assertRaises(OtpDeliveryError):
            issue_and_send(no_email_user)

    @patch("core.email_otp.requests.post")
    def test_reissue_overwrites_previous_otp(self, mock_post):
        mock_post.return_value = _ok_resend_response()

        first = issue_and_send(self.user)
        second = issue_and_send(self.user)

        # LoginOtp.issue uses update_or_create on the user PK, so the row id
        # stays the same but the code hash rotates.
        self.assertEqual(first.pk, second.pk)
        self.assertNotEqual(first.code_hash, second.code_hash)


class VerifyTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="alice", email="alice@example.com", password="x"
        )
        self.code = "654321"
        self.otp = LoginOtp.issue(self.user, self.code, ttl_seconds=OTP_TTL_SECONDS)

    def test_correct_code_succeeds_and_marks_consumed(self):
        ok, err = verify(self.user, self.code)

        self.assertTrue(ok)
        self.assertEqual(err, "")
        self.otp.refresh_from_db()
        self.assertIsNotNone(self.otp.consumed_at)

    def test_wrong_code_fails_and_increments_attempts(self):
        ok, err = verify(self.user, "111111")

        self.assertFalse(ok)
        self.assertIn("Invalid", err)
        self.otp.refresh_from_db()
        self.assertEqual(self.otp.attempts, 1)
        self.assertIsNone(self.otp.consumed_at)

    def test_already_consumed_code_fails(self):
        verify(self.user, self.code)  # consumes
        ok, err = verify(self.user, self.code)

        self.assertFalse(ok)
        self.assertIn("already been used", err)

    def test_expired_code_fails(self):
        self.otp.expires_at = timezone.now() - timedelta(minutes=1)
        self.otp.save(update_fields=["expires_at"])

        ok, err = verify(self.user, self.code)

        self.assertFalse(ok)
        self.assertIn("expired", err)

    def test_locked_after_too_many_attempts(self):
        self.otp.attempts = LoginOtp.MAX_ATTEMPTS
        self.otp.save(update_fields=["attempts"])

        ok, err = verify(self.user, self.code)

        self.assertFalse(ok)
        self.assertIn("Too many wrong attempts", err)

    def test_no_existing_otp_fails(self):
        # Different user with no OTP record.
        other = User.objects.create_user(username="bob", email="bob@example.com", password="x")
        ok, err = verify(other, self.code)

        self.assertFalse(ok)
        self.assertIn("No code was issued", err)
