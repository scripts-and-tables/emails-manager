"""Remote images in emails are blocked by default and opt-in per message.

The email body renders in a sandboxed srcdoc iframe that inherits the page CSP.
By default img-src is 'self' data: (remote images blocked, so a sender can't
confirm the open). Adding ?images=1 relaxes img-src to allow https: for that
one response only.
"""

from __future__ import annotations

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from core.decorators import OTP_VERIFIED_SESSION_KEY
from core.imap_client import EmailFull
from core.models import EmailAccount

User = get_user_model()


def _img_src(csp: str) -> str:
    """Return just the img-src directive's value from a CSP header string."""
    for part in csp.split(";"):
        part = part.strip()
        if part.startswith("img-src"):
            return part
    return ""


class EmailImageGatingTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="u", email="u@x.com", password="x")
        self.account = EmailAccount.objects.create(
            owner=self.user, email_address="me@example.com", encrypted_password=b""
        )
        self.client.force_login(self.user)
        session = self.client.session
        session[OTP_VERIFIED_SESSION_KEY] = True
        session.save()
        self.url = reverse("core:email_detail", args=[self.account.pk, "42"])

    def _message(self):
        return EmailFull(subject="About Paul", from_="paul@example.com",
                         html="<img src='https://tracker.example/p.png'>")

    @patch("core.views.fetch_body")
    def test_images_blocked_by_default(self, mock_fetch):
        mock_fetch.return_value = self._message()
        resp = self.client.get(self.url)
        self.assertEqual(resp.status_code, 200)
        img_src = _img_src(resp.headers.get("Content-Security-Policy", ""))
        self.assertIn("img-src", img_src)
        self.assertNotIn("https:", img_src)  # remote images not allowed
        self.assertContains(resp, "Show images")

    @patch("core.views.fetch_body")
    def test_images_allowed_with_param(self, mock_fetch):
        mock_fetch.return_value = self._message()
        resp = self.client.get(self.url + "?images=1")
        self.assertEqual(resp.status_code, 200)
        img_src = _img_src(resp.headers.get("Content-Security-Policy", ""))
        self.assertIn("https:", img_src)  # remote images now allowed
        self.assertContains(resp, "Remote images are shown")

    @patch("core.views.fetch_body")
    def test_other_pages_keep_strict_img_src(self, mock_fetch):
        # The relaxation must be scoped to the opted-in email response only.
        mock_fetch.return_value = self._message()
        self.client.get(self.url + "?images=1")
        other = self.client.get(reverse("core:accounts_list"))
        self.assertNotIn("https:", _img_src(other.headers.get("Content-Security-Policy", "")))
