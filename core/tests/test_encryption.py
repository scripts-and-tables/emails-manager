"""Roundtrip and edge-case tests for core.encryption (Fernet at rest)."""

from __future__ import annotations

from cryptography.fernet import Fernet
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase, override_settings

from core import encryption


class EncryptionRoundtripTests(TestCase):
    def test_roundtrip_simple_string(self):
        ciphertext = encryption.encrypt("hunter2")
        self.assertIsInstance(ciphertext, bytes)
        self.assertNotIn(b"hunter2", ciphertext)
        self.assertEqual(encryption.decrypt(ciphertext), "hunter2")

    def test_roundtrip_unicode(self):
        # IMAP passwords sometimes carry non-ASCII chars; the round-trip must
        # preserve them byte-for-byte.
        original = "pässwört · «✓»"
        ciphertext = encryption.encrypt(original)
        self.assertEqual(encryption.decrypt(ciphertext), original)

    def test_each_encrypt_produces_distinct_ciphertext(self):
        # Fernet wraps a random 128-bit IV, so two encryptions of the same
        # plaintext must NEVER produce identical ciphertext.
        a = encryption.encrypt("hunter2")
        b = encryption.encrypt("hunter2")
        self.assertNotEqual(a, b)
        # …but both decrypt back to the same value.
        self.assertEqual(encryption.decrypt(a), encryption.decrypt(b))

    def test_decrypt_accepts_memoryview(self):
        # EmailAccount.encrypted_password is a BinaryField; on Postgres reads
        # the driver returns the column as a memoryview. The helper must cope.
        ciphertext = encryption.encrypt("hunter2")
        self.assertEqual(encryption.decrypt(memoryview(ciphertext)), "hunter2")

    def test_decrypt_corrupt_token_raises_value_error(self):
        with self.assertRaises(ValueError):
            encryption.decrypt(b"not-a-real-fernet-token")

    def test_decrypt_ciphertext_from_other_key_raises(self):
        other_key = Fernet.generate_key()
        foreign_ciphertext = Fernet(other_key).encrypt(b"hunter2")
        with self.assertRaises(ValueError):
            encryption.decrypt(foreign_ciphertext)


class EncryptionConfigTests(TestCase):
    def test_missing_key_raises_improperly_configured(self):
        # _fernet() is memoised; clear the cache so the test settings take effect.
        encryption._fernet.cache_clear()
        try:
            with override_settings(FIELD_ENCRYPTION_KEY=""):
                with self.assertRaises(ImproperlyConfigured):
                    encryption.encrypt("anything")
        finally:
            encryption._fernet.cache_clear()
