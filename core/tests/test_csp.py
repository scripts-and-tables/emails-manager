"""Smoke tests for the Content-Security-Policy header.

Don't assert on the exact policy string (django-csp's order is implementation-
defined); assert that each directive we configured is present and that the
nonce sentinel was replaced with an actual nonce value during request render.
"""

from __future__ import annotations

import re

from django.test import TestCase

CSP_HEADER = "Content-Security-Policy"


class CSPHeaderTests(TestCase):
    def test_csp_header_present_on_login_page(self):
        response = self.client.get("/login/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(CSP_HEADER, response.headers)

    def test_csp_contains_expected_directives(self):
        response = self.client.get("/login/")
        policy = response.headers[CSP_HEADER]

        # Core directives we configure
        for directive in (
            "default-src",
            "script-src",
            "style-src",
            "img-src",
            "font-src",
            "connect-src",
            "frame-ancestors",
            "base-uri",
            "form-action",
            "object-src",
        ):
            self.assertIn(directive, policy, f"missing directive {directive!r}")

        # CDN allowlisted for scripts, styles, and fonts
        self.assertIn("https://cdn.jsdelivr.net", policy)

        # Clickjacking and object embedding blocked
        self.assertIn("frame-ancestors 'none'", policy)
        self.assertIn("object-src 'none'", policy)

    def test_csp_includes_per_request_nonce(self):
        response = self.client.get("/login/")
        policy = response.headers[CSP_HEADER]

        # django-csp substitutes the NONCE sentinel with 'nonce-<base64>' when
        # request.csp_nonce is accessed during rendering.
        match = re.search(r"'nonce-([A-Za-z0-9+/=]+)'", policy)
        self.assertIsNotNone(match, "expected a 'nonce-...' value in the policy")
        nonce_value = match.group(1)
        self.assertGreaterEqual(len(nonce_value), 16)

        # The same nonce must appear in the rendered page so inline <script>
        # and <style> blocks pass CSP enforcement.
        body = response.content.decode()
        self.assertIn(f'nonce="{nonce_value}"', body)
