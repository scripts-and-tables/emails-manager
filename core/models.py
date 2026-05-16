import hashlib
import uuid
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone

from .encryption import decrypt, encrypt


def _hash_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


class LoginOtp(models.Model):
    """Single active email-OTP per user. Overwritten on each new login attempt."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="login_otp",
    )
    code_hash = models.CharField(max_length=64)
    sent_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    attempts = models.PositiveSmallIntegerField(default=0)
    consumed_at = models.DateTimeField(null=True, blank=True)

    MAX_ATTEMPTS = 5

    def matches(self, code: str) -> bool:
        return _hash_code(code) == self.code_hash

    def is_expired(self) -> bool:
        return timezone.now() >= self.expires_at

    def is_consumed(self) -> bool:
        return self.consumed_at is not None

    def is_locked(self) -> bool:
        return self.attempts >= self.MAX_ATTEMPTS

    @classmethod
    def issue(cls, user, code: str, ttl_seconds: int) -> "LoginOtp":
        instance, _ = cls.objects.update_or_create(
            user=user,
            defaults={
                "code_hash": _hash_code(code),
                "expires_at": timezone.now() + timedelta(seconds=ttl_seconds),
                "attempts": 0,
                "consumed_at": None,
            },
        )
        return instance


class UserPreferences(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="preferences",
    )
    # Opaque per-user identifier for any surface that needs to refer to a
    # user without leaking username/email (admin URLs, future API surfaces).
    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False, db_index=True)
    two_factor_enabled = models.BooleanField(default=True)
    # null = use the free-tier default from core.limits.FREE_TIER_ACCOUNT_LIMIT.
    # A set value overrides the default upward (paid-tier grants).
    account_limit_override = models.PositiveIntegerField(null=True, blank=True)
    # Stamped on the user's first successful login. Django's auth user model
    # only tracks last_login; this captures the *first* one for staff analytics.
    first_login_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)


class EmailAccount(models.Model):
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="email_accounts",
    )
    email_address = models.EmailField()
    display_name = models.CharField(max_length=120, blank=True)
    imap_host = models.CharField(max_length=255, default="imap.mail.ru")
    imap_port = models.PositiveIntegerField(default=993)
    encrypted_password = models.BinaryField()
    is_enabled = models.BooleanField(default=True)
    group = models.CharField(max_length=60, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("owner", "email_address")
        ordering = ("email_address",)

    def __str__(self) -> str:
        return self.email_address

    def set_password(self, plaintext: str) -> None:
        self.encrypted_password = encrypt(plaintext)

    def get_password(self) -> str:
        return decrypt(self.encrypted_password)


class AuthEvent(models.Model):
    """Append-only audit log of authentication-related events.

    Records: login success/fail, logout, OTP issued/verified/failed. Useful
    for forensics and abuse investigation. Application code never edits or
    deletes rows; rotate via a retention job if it grows.
    """

    class EventType(models.TextChoices):
        LOGIN_SUCCESS = "login_success", "Login success"
        LOGIN_FAILED = "login_failed", "Login failed"
        LOGOUT = "logout", "Logout"
        OTP_ISSUED = "otp_issued", "OTP issued"
        OTP_VERIFIED = "otp_verified", "OTP verified"
        OTP_FAILED = "otp_failed", "OTP failed"

    event_type = models.CharField(max_length=32, choices=EventType.choices)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="auth_events",
    )
    # Username supplied at login time; populated when a non-existent username
    # was tried (the user FK is null in that case but we still want a record).
    username = models.CharField(max_length=150, blank=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=500, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["user", "-created_at"]),
            models.Index(fields=["event_type", "-created_at"]),
        ]

    def __str__(self) -> str:
        who = self.user.get_username() if self.user else (self.username or "anon")
        return f"{self.created_at:%Y-%m-%d %H:%M} {self.event_type} {who}"


class APIToken(models.Model):
    """Long-lived bearer token for the external read API.

    The plaintext token value is shown to the user exactly once at creation.
    Only the SHA-256 hash and a short prefix are stored; lookup is by prefix,
    then constant-time hash compare. Tokens can be revoked (soft delete) and
    optionally scoped to specific mailboxes; empty scope = all owner's
    mailboxes.
    """

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="api_tokens",
    )
    name = models.CharField(max_length=120)
    key_prefix = models.CharField(max_length=12, db_index=True)
    key_hash = models.CharField(max_length=64)
    accounts = models.ManyToManyField(EmailAccount, blank=True, related_name="api_tokens")
    expires_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    last_used_ip = models.GenericIPAddressField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self) -> str:
        return f"{self.name} ({self.key_prefix}…)"

    def is_active(self) -> bool:
        if self.revoked_at is not None:
            return False
        if self.expires_at is not None and self.expires_at <= timezone.now():
            return False
        return True

    def can_access(self, account: EmailAccount) -> bool:
        """True if this token may read messages from `account`."""
        if account.owner_id != self.owner_id:
            return False
        scoped = self.accounts.all()
        if scoped.exists():
            return scoped.filter(pk=account.pk).exists()
        return True


class APIRequestLog(models.Model):
    """One row per API call. Append-only forensic trail."""

    token = models.ForeignKey(
        APIToken,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="requests",
    )
    endpoint = models.CharField(max_length=120)
    status_code = models.IntegerField()
    mailbox = models.ForeignKey(
        EmailAccount,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="api_requests",
    )
    minutes = models.IntegerField(null=True, blank=True)
    count = models.IntegerField(null=True, blank=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, blank=True)
    latency_ms = models.IntegerField()
    error_code = models.CharField(max_length=40, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["token", "-created_at"]),
            models.Index(fields=["endpoint", "-created_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.created_at:%Y-%m-%d %H:%M} {self.endpoint} {self.status_code}"
