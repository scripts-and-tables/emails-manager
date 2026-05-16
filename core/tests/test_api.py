"""Tests for the external read-only API at /api/v1/messages."""

from __future__ import annotations

import json
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from core import imap_client
from core.api.auth import _hash_token, issue_token
from core.models import APIRequestLog, APIToken, EmailAccount

User = get_user_model()


def _fake_message(**overrides):
    """Construct an object that quacks like imap_tools.MailMessage enough
    for `message_to_dict` to consume."""
    defaults = dict(
        uid="100",
        subject="Hi",
        from_=SimpleNamespace(name="Mom", email="mom@example.com"),
        from_values=SimpleNamespace(name="Mom", email="mom@example.com"),
        to=[SimpleNamespace(name="Alex", email="alex@example.com")],
        to_values=[SimpleNamespace(name="Alex", email="alex@example.com")],
        cc=[],
        cc_values=[],
        date=timezone.now(),
        flags=("\\Seen",),
        size=4823,
        text="Hi alex,\n\nLunch Sunday?",
        html="<p>Hi alex,</p>",
        attachments=[],
        headers={"message-id": ["<abc@example.com>"]},
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class APITokenModelTests(TestCase):
    def test_save_stores_hash_not_plaintext(self):
        user = User.objects.create_user(username="alice", password="pw")
        full, prefix, h = issue_token()
        token = APIToken.objects.create(owner=user, name="t1", key_prefix=prefix, key_hash=h)
        self.assertEqual(token.key_prefix, prefix)
        # The full value must not appear in any persisted field.
        for field in (token.key_prefix, token.key_hash):
            self.assertNotIn(full, field)
        # And the hash must match an independent recomputation.
        self.assertEqual(token.key_hash, _hash_token(full))

    def test_is_active_handles_revoked_and_expired(self):
        user = User.objects.create_user(username="alice", password="pw")
        full, prefix, h = issue_token()
        t = APIToken.objects.create(owner=user, name="t", key_prefix=prefix, key_hash=h)
        self.assertTrue(t.is_active())
        t.revoked_at = timezone.now()
        self.assertFalse(t.is_active())
        t.revoked_at = None
        t.expires_at = timezone.now() - timedelta(minutes=1)
        self.assertFalse(t.is_active())


class APIAuthTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.mailbox = EmailAccount.objects.create(
            owner=self.user,
            email_address="alex@example.com",
            imap_host="imap.example.com",
            encrypted_password=b"",
        )
        self.full, prefix, h = issue_token()
        self.token = APIToken.objects.create(
            owner=self.user, name="ci", key_prefix=prefix, key_hash=h
        )
        self.url = reverse("api:messages_recent")

    def _hit(self, *, token=None, params=None):
        params = params or {"mailbox": "alex@example.com", "minutes": 60}
        headers = {}
        if token is not None:
            headers["HTTP_AUTHORIZATION"] = f"Bearer {token}"
        return self.client.get(self.url, params, **headers)

    def test_missing_header_returns_401(self):
        resp = self._hit(token=None)
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"], "invalid_token")

    def test_wrong_token_returns_401(self):
        resp = self._hit(token="mma_live_garbage_value_with_right_prefix_xxxx")
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"], "invalid_token")

    def test_revoked_token_returns_401(self):
        self.token.revoked_at = timezone.now()
        self.token.save(update_fields=["revoked_at"])
        resp = self._hit(token=self.full)
        self.assertEqual(resp.status_code, 401)

    def test_expired_token_returns_401(self):
        self.token.expires_at = timezone.now() - timedelta(minutes=1)
        self.token.save(update_fields=["expires_at"])
        resp = self._hit(token=self.full)
        self.assertEqual(resp.status_code, 401)


class APIMailboxResolutionTests(TestCase):
    def setUp(self):
        self.alice = User.objects.create_user(username="alice", password="pw")
        self.bob = User.objects.create_user(username="bob", password="pw")
        self.alice_mb = EmailAccount.objects.create(
            owner=self.alice, email_address="alex@example.com", encrypted_password=b""
        )
        self.bob_mb = EmailAccount.objects.create(
            owner=self.bob, email_address="bob@example.com", encrypted_password=b""
        )
        self.full, prefix, h = issue_token()
        self.token = APIToken.objects.create(
            owner=self.alice, name="ci", key_prefix=prefix, key_hash=h
        )
        self.url = reverse("api:messages_recent")

    def _hit(self, mailbox):
        return self.client.get(
            self.url,
            {"mailbox": mailbox, "minutes": 60},
            HTTP_AUTHORIZATION=f"Bearer {self.full}",
        )

    def test_other_users_mailbox_returns_404_not_403(self):
        # Bob's address must not surface as 403; that would let Alice probe
        # the existence of other users' mailboxes.
        resp = self._hit("bob@example.com")
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(resp.json()["error"], "mailbox_not_found")

    def test_disabled_mailbox_returns_404(self):
        self.alice_mb.is_enabled = False
        self.alice_mb.save(update_fields=["is_enabled"])
        resp = self._hit("alex@example.com")
        self.assertEqual(resp.status_code, 404)

    def test_garbage_mailbox_returns_404(self):
        resp = self._hit("does-not-exist@nowhere.invalid")
        self.assertEqual(resp.status_code, 404)

    def test_out_of_scope_mailbox_returns_403(self):
        # Token scoped to a different EmailAccount on the same owner.
        other = EmailAccount.objects.create(
            owner=self.alice, email_address="other@example.com", encrypted_password=b""
        )
        self.token.accounts.set([other])
        resp = self._hit("alex@example.com")
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["error"], "scope_forbidden")


class APIValidationTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        EmailAccount.objects.create(
            owner=self.user, email_address="alex@example.com", encrypted_password=b""
        )
        self.full, prefix, h = issue_token()
        APIToken.objects.create(owner=self.user, name="ci", key_prefix=prefix, key_hash=h)
        self.url = reverse("api:messages_recent")
        self.auth = {"HTTP_AUTHORIZATION": f"Bearer {self.full}"}

    def test_missing_minutes_returns_400(self):
        resp = self.client.get(self.url, {"mailbox": "alex@example.com"}, **self.auth)
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()["error"], "validation_error")

    def test_minutes_out_of_range_returns_400(self):
        resp = self.client.get(
            self.url, {"mailbox": "alex@example.com", "minutes": "99999"}, **self.auth
        )
        self.assertEqual(resp.status_code, 400)

    def test_invalid_folder_returns_400(self):
        resp = self.client.get(
            self.url,
            {"mailbox": "alex@example.com", "minutes": "60", "folder": "phishing"},
            **self.auth,
        )
        self.assertEqual(resp.status_code, 400)


@patch.object(imap_client, "fetch_window")
class APIHappyPathTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.mailbox = EmailAccount.objects.create(
            owner=self.user,
            email_address="alex@example.com",
            imap_host="imap.example.com",
            imap_port=993,
            encrypted_password=b"",
        )
        self.full, prefix, h = issue_token()
        APIToken.objects.create(owner=self.user, name="ci", key_prefix=prefix, key_hash=h)
        self.url = reverse("api:messages_recent")
        self.auth = {"HTTP_AUTHORIZATION": f"Bearer {self.full}"}

    def test_happy_path_returns_expected_shape(self, mock_fetch):
        mock_fetch.return_value = ([_fake_message()], False, None)
        resp = self.client.get(
            self.url, {"mailbox": "alex@example.com", "minutes": "60"}, **self.auth
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["mailbox"], "alex@example.com")
        self.assertEqual(body["folder"], "inbox")
        self.assertEqual(body["window_minutes"], 60)
        self.assertEqual(body["count"], 1)
        self.assertFalse(body["truncated"])
        msg = body["messages"][0]
        self.assertEqual(msg["uid"], "100")
        self.assertEqual(msg["from"]["email"], "mom@example.com")
        self.assertIn("text", msg)
        self.assertIn("html", msg)
        self.assertIn("attachments", msg)

    def test_bodies_false_omits_text_and_html(self, mock_fetch):
        mock_fetch.return_value = ([_fake_message()], False, None)
        resp = self.client.get(
            self.url,
            {"mailbox": "alex@example.com", "minutes": "60", "bodies": "false"},
            **self.auth,
        )
        msg = resp.json()["messages"][0]
        self.assertNotIn("text", msg)
        self.assertNotIn("html", msg)
        self.assertNotIn("attachments", msg)
        self.assertIn("has_attachments", msg)

    def test_imap_error_returns_503(self, mock_fetch):
        mock_fetch.return_value = ([], False, "Connection refused")
        resp = self.client.get(
            self.url, {"mailbox": "alex@example.com", "minutes": "60"}, **self.auth
        )
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(resp.json()["error"], "imap_unavailable")
        # The raw IMAP error string must not leak to the caller.
        self.assertNotIn("Connection refused", json.dumps(resp.json()))

    def test_response_never_leaks_sensitive_fields(self, mock_fetch):
        mock_fetch.return_value = ([_fake_message()], False, None)
        resp = self.client.get(
            self.url, {"mailbox": "alex@example.com", "minutes": "60"}, **self.auth
        )
        dumped = json.dumps(resp.json())
        for forbidden in ("encrypted_password", "imap_host", "imap_port", "FERNET"):
            self.assertNotIn(forbidden, dumped)


class APIRateLimitTests(TestCase):
    def setUp(self):
        # Django's LocMem cache persists across TestCase classes, but the DB
        # is rolled back so token PKs collide — without this clear, prior
        # tests' rate-limit counters poison this one.
        cache.clear()
        self.user = User.objects.create_user(username="alice", password="pw")
        EmailAccount.objects.create(
            owner=self.user, email_address="alex@example.com", encrypted_password=b""
        )
        self.full, prefix, h = issue_token()
        APIToken.objects.create(owner=self.user, name="ci", key_prefix=prefix, key_hash=h)
        self.url = reverse("api:messages_recent")
        self.auth = {"HTTP_AUTHORIZATION": f"Bearer {self.full}"}

    @override_settings(MMA_API_RATE_PER_MINUTE=3)
    @patch.object(imap_client, "fetch_window", return_value=([], False, None))
    def test_rate_limit_returns_429_with_retry_after(self, mock_fetch):
        # First 3 succeed, 4th trips the limiter.
        for _ in range(3):
            resp = self.client.get(
                self.url, {"mailbox": "alex@example.com", "minutes": "60"}, **self.auth
            )
            self.assertEqual(resp.status_code, 200)
        resp = self.client.get(
            self.url, {"mailbox": "alex@example.com", "minutes": "60"}, **self.auth
        )
        self.assertEqual(resp.status_code, 429)
        self.assertEqual(resp.json()["error"], "rate_limited")
        self.assertEqual(resp["Retry-After"], "60")


class APIRequestLogTests(TestCase):
    """Every API call must leave one APIRequestLog row, success or failure."""

    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        EmailAccount.objects.create(
            owner=self.user, email_address="alex@example.com", encrypted_password=b""
        )
        self.full, prefix, h = issue_token()
        self.token = APIToken.objects.create(
            owner=self.user, name="ci", key_prefix=prefix, key_hash=h
        )
        self.url = reverse("api:messages_recent")

    @patch.object(imap_client, "fetch_window", return_value=([], False, None))
    def test_log_written_on_success(self, _):
        self.client.get(
            self.url,
            {"mailbox": "alex@example.com", "minutes": "60"},
            HTTP_AUTHORIZATION=f"Bearer {self.full}",
        )
        log = APIRequestLog.objects.get()
        self.assertEqual(log.endpoint, "messages.recent")
        self.assertEqual(log.status_code, 200)
        self.assertEqual(log.token, self.token)
        self.assertEqual(log.minutes, 60)

    def test_log_written_on_auth_failure(self):
        self.client.get(self.url, {"mailbox": "alex@example.com", "minutes": "60"})
        log = APIRequestLog.objects.get()
        self.assertEqual(log.endpoint, "messages.recent")
        self.assertEqual(log.status_code, 401)
        self.assertIsNone(log.token)
        self.assertEqual(log.error_code, "invalid_token")
