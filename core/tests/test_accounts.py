"""Account toggle endpoint and the rate-limiter helper."""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from django.urls import reverse

from core.limits import FREE_TIER_ACCOUNT_LIMIT, PREMIUM_TIER_ACCOUNT_LIMIT
from core.models import EmailAccount, UserPreferences
from core.rate_limit import is_rate_limited

User = get_user_model()

OTP_VERIFIED_SESSION_KEY = "otp_verified"


def _make_account(owner, email):
    """EmailAccount factory bypassing the form (encrypted_password content
    doesn't matter for limit tests)."""
    return EmailAccount.objects.create(
        owner=owner,
        email_address=email,
        imap_host="imap.example.com",
        imap_port=993,
        encrypted_password=b"placeholder",
        is_enabled=True,
    )


def _new_account_post_data(email="new@example.com"):
    return {
        "email_address": email,
        "display_name": "",
        "imap_host": "imap.example.com",
        "imap_port": "993",
        "group": "",
        "password": "app-pw",
    }


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
        for _ in range(3):
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


class AccountLimitTests(TestCase):
    """Free tier: FREE_TIER_ACCOUNT_LIMIT, single-add only.
    Premium (superuser, or UserPreferences.account_limit_override set): up to
    PREMIUM_TIER_ACCOUNT_LIMIT, bulk add unlocked. Override values above the
    premium cap are clamped down."""

    def setUp(self):
        self.user = User.objects.create_user(username="u", email="u@x.com", password="x")
        self._login(self.user)

    def _login(self, user):
        self.client.force_login(user)
        session = self.client.session
        session[OTP_VERIFIED_SESSION_KEY] = True
        session.save()

    def test_premium_capped_at_100(self):
        admin = User.objects.create_superuser(username="root", email="r@x.com", password="x")
        # Below the cap: add succeeds.
        for i in range(PREMIUM_TIER_ACCOUNT_LIMIT):
            _make_account(admin, f"acct{i}@example.com")
        self._login(admin)
        # At PREMIUM_TIER_ACCOUNT_LIMIT/PREMIUM_TIER_ACCOUNT_LIMIT — next single-add is blocked.
        response = self.client.post(
            reverse("core:account_new"),
            _new_account_post_data("over@example.com"),
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("core:accounts_list"))
        self.assertEqual(
            EmailAccount.objects.filter(owner=admin).count(),
            PREMIUM_TIER_ACCOUNT_LIMIT,
        )

    def test_single_add_blocks_at_cap(self):
        for i in range(FREE_TIER_ACCOUNT_LIMIT):
            _make_account(self.user, f"existing{i}@example.com")
        response = self.client.post(
            reverse("core:account_new"),
            _new_account_post_data("blocked@example.com"),
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("core:accounts_list"))
        # No new row was created.
        self.assertEqual(EmailAccount.objects.filter(owner=self.user).count(), FREE_TIER_ACCOUNT_LIMIT)
        self.assertFalse(
            EmailAccount.objects.filter(owner=self.user, email_address="blocked@example.com").exists()
        )

    def test_bulk_add_partial_acceptance_at_threshold(self):
        # Premium user with a tight 3-account override so we can hit the cap
        # in a small CSV. Bulk add itself is premium-only.
        UserPreferences.objects.create(user=self.user, account_limit_override=3)
        # Start at 1/3.
        _make_account(self.user, "existing@example.com")
        csv = "\n".join(
            f"new{i}@example.com,pw{i},imap.example.com,993" for i in range(1, 6)
        )
        response = self.client.post(reverse("core:account_bulk_add"), {"csv_text": csv})
        self.assertEqual(response.status_code, 200)
        result = response.context["result"]
        self.assertEqual(result["added"], 2)
        # Lines 3, 4, 5 are pasted lines 3-5 (1-indexed); first two filled the cap.
        skipped_limit_lines = sorted(line for line, _email in result["skipped_limit"])
        self.assertEqual(skipped_limit_lines, [3, 4, 5])
        self.assertEqual(EmailAccount.objects.filter(owner=self.user).count(), 3)

    def test_bulk_add_duplicate_takes_priority_over_limit(self):
        # Riskiest case: premium user at 2/3, paste a duplicate then 3 fresh entries.
        # Expect line 1 → duplicate; line 2 → added (now 3/3); lines 3-4 → limit.
        UserPreferences.objects.create(user=self.user, account_limit_override=3)
        _make_account(self.user, "a@example.com")
        _make_account(self.user, "b@example.com")
        csv = "\n".join([
            "a@example.com,pw,imap.example.com,993",  # duplicate (does not consume a slot)
            "c@example.com,pw,imap.example.com,993",  # added → 3/3
            "d@example.com,pw,imap.example.com,993",  # limit
            "e@example.com,pw,imap.example.com,993",  # limit
        ])
        response = self.client.post(reverse("core:account_bulk_add"), {"csv_text": csv})
        self.assertEqual(response.status_code, 200)
        result = response.context["result"]
        self.assertEqual(result["added"], 1)
        self.assertEqual(
            sorted((line, email) for line, email in result["skipped"]),
            [(1, "a@example.com")],
        )
        self.assertEqual(
            sorted((line, email) for line, email in result["skipped_limit"]),
            [(3, "d@example.com"), (4, "e@example.com")],
        )
        self.assertTrue(EmailAccount.objects.filter(owner=self.user, email_address="c@example.com").exists())
        self.assertEqual(EmailAccount.objects.filter(owner=self.user).count(), 3)

    def test_override_grants_higher_cap(self):
        prefs = UserPreferences.objects.create(user=self.user, account_limit_override=5)
        for i in range(5):
            _make_account(self.user, f"slot{i}@example.com")
        # At 5/5 — sixth single-add is blocked.
        response = self.client.post(
            reverse("core:account_new"),
            _new_account_post_data("six@example.com"),
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("core:accounts_list"))
        self.assertEqual(EmailAccount.objects.filter(owner=self.user).count(), 5)
        # Bumping the override gives them another slot.
        prefs.account_limit_override = 6
        prefs.save(update_fields=["account_limit_override", "updated_at"])
        response = self.client.post(
            reverse("core:account_new"),
            _new_account_post_data("six@example.com"),
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(EmailAccount.objects.filter(owner=self.user).count(), 6)

    def test_override_clamped_to_premium_cap(self):
        # An override above PREMIUM_TIER_ACCOUNT_LIMIT must not raise the cap above it.
        UserPreferences.objects.create(user=self.user, account_limit_override=200)
        from core.limits import get_account_limit
        self.assertEqual(get_account_limit(self.user), PREMIUM_TIER_ACCOUNT_LIMIT)

    def test_bulk_blocked_for_free_user(self):
        response = self.client.post(
            reverse("core:account_bulk_add"),
            {"csv_text": "new@example.com,pw,imap.example.com,993"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("core:limits"))
        self.assertEqual(EmailAccount.objects.filter(owner=self.user).count(), 0)
        # GET is also gated.
        response = self.client.get(reverse("core:account_bulk_add"))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("core:limits"))

    def test_bulk_allowed_for_superuser(self):
        admin = User.objects.create_superuser(username="root", email="r@x.com", password="x")
        self._login(admin)
        response = self.client.post(
            reverse("core:account_bulk_add"),
            {"csv_text": "first@example.com,pw,imap.example.com,993"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["result"]["added"], 1)
        self.assertTrue(EmailAccount.objects.filter(owner=admin, email_address="first@example.com").exists())

    def test_bulk_allowed_for_premium_via_override(self):
        UserPreferences.objects.create(user=self.user, account_limit_override=10)
        response = self.client.post(
            reverse("core:account_bulk_add"),
            {"csv_text": "first@example.com,pw,imap.example.com,993"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["result"]["added"], 1)
