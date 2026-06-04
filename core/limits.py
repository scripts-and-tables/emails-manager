"""Per-user email-account caps and tier checks.

Two tiers today:
- Free (default): FREE_TIER_ACCOUNT_LIMIT slots, single-add only.
- Premium (superuser, OR UserPreferences.account_limit_override is set):
  up to PREMIUM_TIER_ACCOUNT_LIMIT slots, bulk-add unlocked.

A non-null UserPreferences.account_limit_override doubles as the premium flag
and as the per-user cap. Values above PREMIUM_TIER_ACCOUNT_LIMIT are clamped
down so 100 is a hard ceiling for override-based premium users. Superusers are
unlimited — get_account_limit returns None for them.

Counting includes disabled accounts: a disabled EmailAccount still occupies
a stored-credentials slot, so it counts toward the cap.
"""

from __future__ import annotations

from .models import EmailAccount, UserPreferences

FREE_TIER_ACCOUNT_LIMIT: int = 3
PREMIUM_TIER_ACCOUNT_LIMIT: int = 100


def is_premium(user) -> bool:
    """True if the user has paid-tier access (bulk add, raised cap)."""
    if user.is_superuser:
        return True
    prefs = UserPreferences.objects.filter(user=user).first()
    return prefs is not None and prefs.account_limit_override is not None


def get_account_limit(user) -> int | None:
    """Return the max number of EmailAccount rows this user may own, or None
    for an unlimited account (superusers have no cap)."""
    if user.is_superuser:
        return None
    if not is_premium(user):
        return FREE_TIER_ACCOUNT_LIMIT
    prefs = UserPreferences.objects.filter(user=user).first()
    if prefs is not None and prefs.account_limit_override is not None:
        return min(prefs.account_limit_override, PREMIUM_TIER_ACCOUNT_LIMIT)
    return PREMIUM_TIER_ACCOUNT_LIMIT


def get_account_usage(user) -> tuple[int, int | None]:
    """Return (current_count, limit). `limit` is None when the user is
    unlimited (superusers)."""
    used = EmailAccount.objects.filter(owner=user).count()
    return used, get_account_limit(user)


def is_at_account_limit(user) -> bool:
    used, limit = get_account_usage(user)
    return limit is not None and used >= limit


def can_bulk_add(user) -> bool:
    """Bulk add is gated to premium tier."""
    return is_premium(user)
