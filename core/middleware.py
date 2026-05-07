"""Project-specific middleware."""

from __future__ import annotations


class XRobotsTagMiddleware:
    """Add X-Robots-Tag: noindex, nofollow on every response except the
    public landing page and robots.txt itself.

    Belt-and-suspenders alongside robots.txt: well-behaved crawlers honor
    robots.txt; the header tells the rest (or any one that ignores it)
    that auth-gated content shouldn't be indexed.
    """

    PUBLIC_PATHS = frozenset({"/", "/robots.txt"})

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if request.path not in self.PUBLIC_PATHS:
            response["X-Robots-Tag"] = "noindex, nofollow"
        return response
