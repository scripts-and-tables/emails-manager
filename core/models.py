import hashlib
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
