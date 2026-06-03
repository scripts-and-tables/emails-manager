"""Tests for the alias feature: model validation, recipient filtering in
imap_client.fetch_window, and alias resolution in the external API."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from core import imap_client
from core.api.auth import issue_token
from core.decorators import OTP_VERIFIED_SESSION_KEY
from core.models import APIToken, EmailAccount, EmailAlias

User = get_user_model()


def _msg(*, to=(), cc=(), headers=None, date=None, uid="1"):
    """A minimal stand-in for imap_tools.MailMessage."""
    return SimpleNamespace(
        uid=uid,
        date=date or timezone.now(),
        to_values=[SimpleNamespace(name="", email=e) for e in to],
        cc_values=[SimpleNamespace(name="", email=e) for e in cc],
        headers=headers or {},
    )


class AliasModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.account = EmailAccount.objects.create(
            owner=self.user, email_address="primary@mail.ru", encrypted_password=b""
        )

    def test_alias_can_be_attached(self):
        alias = EmailAlias(account=self.account, email_address="other@inbox.ru")
        alias.full_clean()
        alias.save()
        self.assertEqual(list(self.account.aliases.all()), [alias])

    def test_alias_cannot_collide_with_a_primary_address(self):
        # Same owner already owns primary@mail.ru as an account.
        alias = EmailAlias(account=self.account, email_address="PRIMARY@mail.ru")
        with self.assertRaises(ValidationError):
            alias.full_clean()

    def test_alias_cannot_duplicate_another_alias_of_the_owner(self):
        EmailAlias.objects.create(account=self.account, email_address="dup@inbox.ru")
        second_account = EmailAccount.objects.create(
            owner=self.user, email_address="second@mail.ru", encrypted_password=b""
        )
        alias = EmailAlias(account=second_account, email_address="Dup@inbox.ru")
        with self.assertRaises(ValidationError):
            alias.full_clean()

    def test_same_alias_allowed_for_a_different_owner(self):
        bob = User.objects.create_user(username="bob", password="pw")
        bob_account = EmailAccount.objects.create(
            owner=bob, email_address="bob@mail.ru", encrypted_password=b""
        )
        alias = EmailAlias(account=bob_account, email_address="primary@mail.ru")
        # Bob may claim it even though Alice has primary@mail.ru — validation is
        # owner-scoped so it never leaks Alice's addresses.
        alias.full_clean()


class RecipientFilterTests(TestCase):
    """fetch_window(recipient=...) keeps only mail delivered to the alias."""

    def setUp(self):
        self.account = SimpleNamespace(email_address="primary@mail.ru")

    @contextmanager
    def _fake_mailbox(self, messages):
        box = SimpleNamespace(fetch=lambda *a, **k: list(messages))

        @contextmanager
        def _cm():
            yield box

        with patch.object(
            imap_client, "_open_with_semantic_folder", return_value=(_cm(), "INBOX")
        ):
            yield

    def _run(self, messages, recipient):
        since = timezone.now() - timedelta(minutes=60)
        with self._fake_mailbox(messages):
            msgs, truncated, err = imap_client.fetch_window(
                self.account, since=since, recipient=recipient, with_bodies=False
            )
        return msgs, truncated, err

    def test_matches_alias_in_to_header(self):
        keep = _msg(to=["alias@inbox.ru"], uid="keep")
        drop = _msg(to=["someone@mail.ru"], uid="drop")
        msgs, _, err = self._run([keep, drop], "alias@inbox.ru")
        self.assertIsNone(err)
        self.assertEqual([m.uid for m in msgs], ["keep"])

    def test_match_is_case_insensitive(self):
        keep = _msg(to=["Alias@Inbox.RU"], uid="keep")
        msgs, _, _ = self._run([keep], "alias@inbox.ru")
        self.assertEqual([m.uid for m in msgs], ["keep"])

    def test_no_substring_bleed_between_aliases(self):
        # alias1@ must not match when alias10@ is requested.
        drop = _msg(to=["alias1@inbox.ru"], uid="drop")
        keep = _msg(to=["alias10@inbox.ru"], uid="keep")
        msgs, _, _ = self._run([drop, keep], "alias10@inbox.ru")
        self.assertEqual([m.uid for m in msgs], ["keep"])

    def test_matches_delivery_header_when_not_in_to(self):
        # Bcc-style delivery: alias only appears in an envelope header.
        keep = _msg(
            to=["list@example.com"],
            headers={"delivered-to": ["alias@inbox.ru"]},
            uid="keep",
        )
        msgs, _, _ = self._run([keep], "alias@inbox.ru")
        self.assertEqual([m.uid for m in msgs], ["keep"])

    def test_no_recipient_returns_everything(self):
        a = _msg(to=["x@mail.ru"], uid="a")
        b = _msg(to=["y@mail.ru"], uid="b")
        msgs, _, _ = self._run([a, b], None)
        self.assertEqual({m.uid for m in msgs}, {"a", "b"})


class AccountsListAliasDisplayTests(TestCase):
    """The accounts page lists aliases under their parent and links to it."""

    def setUp(self):
        self.user = User.objects.create_user(username="u", email="u@x.com", password="x")
        self.account = EmailAccount.objects.create(
            owner=self.user, email_address="primary@mail.ru", encrypted_password=b""
        )
        EmailAlias.objects.create(account=self.account, email_address="alias@inbox.ru")
        self.client.force_login(self.user)
        session = self.client.session
        session[OTP_VERIFIED_SESSION_KEY] = True
        session.save()

    def test_alias_row_links_to_parent_and_controls_present(self):
        resp = self.client.get(reverse("core:accounts_list"))
        self.assertEqual(resp.status_code, 200)
        body = resp.content.decode()
        # Alias is rendered as its own (alias) row.
        self.assertIn("alias@inbox.ru", body)
        self.assertIn("data-alias-row", body)
        # Clicking the alias opens the parent account page, not an alias page.
        self.assertIn(reverse("core:account_detail", args=[self.account.pk]), body)
        # Search box + show-aliases toggle are present.
        self.assertIn('id="account-search"', body)
        self.assertIn('id="show-aliases-toggle"', body)
        # Link-count badge + the unused display-name column are gone/added.
        self.assertIn("bi-link-45deg", body)
        self.assertNotIn(">Display name<", body)


class AccountsListOrderingTests(TestCase):
    """Accounts are listed in case-insensitive alphabetical order by email."""

    def setUp(self):
        self.user = User.objects.create_user(username="ord", email="ord@x.com", password="x")
        for em in ("Beta@mail.ru", "alpha@mail.ru", "Charlie@mail.ru"):
            EmailAccount.objects.create(owner=self.user, email_address=em, encrypted_password=b"")
        self.client.force_login(self.user)
        session = self.client.session
        session[OTP_VERIFIED_SESSION_KEY] = True
        session.save()

    def test_accounts_sorted_case_insensitively(self):
        body = self.client.get(reverse("core:accounts_list")).content.decode()
        positions = [body.index(e) for e in ("alpha@mail.ru", "Beta@mail.ru", "Charlie@mail.ru")]
        # Case-insensitive order is alpha < Beta < Charlie; a case-sensitive
        # sort would put the capitalised ones first and fail this.
        self.assertEqual(positions, sorted(positions))


class APIAliasResolutionTests(TestCase):
    def setUp(self):
        self.alice = User.objects.create_user(username="alice", password="pw")
        self.account = EmailAccount.objects.create(
            owner=self.alice,
            email_address="primary@mail.ru",
            imap_host="imap.mail.ru",
            imap_port=993,
            encrypted_password=b"",
        )
        self.alias = EmailAlias.objects.create(
            account=self.account, email_address="alias@inbox.ru"
        )
        self.full, prefix, h = issue_token()
        self.token = APIToken.objects.create(
            owner=self.alice, name="ci", key_prefix=prefix, key_hash=h
        )
        self.url = reverse("api:messages_recent")
        self.auth = {"HTTP_AUTHORIZATION": f"Bearer {self.full}"}

    def _hit(self, mailbox):
        return self.client.get(self.url, {"mailbox": mailbox, "minutes": 60}, **self.auth)

    @patch.object(imap_client, "fetch_window", return_value=([], False, None))
    def test_alias_resolves_to_parent_and_filters(self, mock_fetch):
        resp = self._hit("alias@inbox.ru")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["mailbox"], "alias@inbox.ru")
        self.assertEqual(body["account"], "primary@mail.ru")
        self.assertTrue(body["alias"])
        # fetch_window must be called on the parent account, filtered by alias.
        called_account = mock_fetch.call_args.args[0]
        self.assertEqual(called_account.pk, self.account.pk)
        self.assertEqual(mock_fetch.call_args.kwargs["recipient"], "alias@inbox.ru")

    @patch.object(imap_client, "fetch_window", return_value=([], False, None))
    def test_primary_address_has_no_recipient_filter(self, mock_fetch):
        resp = self._hit("primary@mail.ru")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertFalse(body["alias"])
        self.assertEqual(body["account"], "primary@mail.ru")
        self.assertIsNone(mock_fetch.call_args.kwargs["recipient"])

    def test_disabled_alias_returns_404(self):
        self.alias.is_enabled = False
        self.alias.save(update_fields=["is_enabled"])
        self.assertEqual(self._hit("alias@inbox.ru").status_code, 404)

    def test_alias_of_disabled_account_returns_404(self):
        self.account.is_enabled = False
        self.account.save(update_fields=["is_enabled"])
        self.assertEqual(self._hit("alias@inbox.ru").status_code, 404)

    def test_other_users_alias_returns_404(self):
        bob = User.objects.create_user(username="bob", password="pw")
        bob_account = EmailAccount.objects.create(
            owner=bob, email_address="bob@mail.ru", encrypted_password=b""
        )
        EmailAlias.objects.create(account=bob_account, email_address="secret@inbox.ru")
        self.assertEqual(self._hit("secret@inbox.ru").status_code, 404)

    @patch.object(imap_client, "fetch_window", return_value=([], False, None))
    def test_token_scoped_to_parent_can_read_alias(self, _):
        self.token.accounts.set([self.account])
        self.assertEqual(self._hit("alias@inbox.ru").status_code, 200)

    def test_token_scoped_to_other_account_cannot_read_alias(self):
        other = EmailAccount.objects.create(
            owner=self.alice, email_address="other@mail.ru", encrypted_password=b""
        )
        self.token.accounts.set([other])
        resp = self._hit("alias@inbox.ru")
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["error"], "scope_forbidden")
