"""Smoke tests for the in-app Guide page."""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

User = get_user_model()

OTP_VERIFIED_SESSION_KEY = "otp_verified"


class GuidePageTests(TestCase):
    def test_guide_requires_login(self):
        response = self.client.get(reverse("core:guide"))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("core:login"), response.url)

    def test_guide_renders_for_otp_user(self):
        user = User.objects.create_user(username="u", email="u@x.com", password="x")
        self.client.force_login(user)
        session = self.client.session
        session[OTP_VERIFIED_SESSION_KEY] = True
        session.save()

        response = self.client.get(reverse("core:guide"))
        self.assertEqual(response.status_code, 200)
        body = response.content.decode()
        self.assertIn("Guide", body)
        # Anchor for the headline how-to section must be present so the in-page
        # TOC keeps working.
        self.assertIn('id="aliases-trick"', body)
