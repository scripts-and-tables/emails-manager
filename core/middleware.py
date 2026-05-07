"""Project-specific middleware."""

from __future__ import annotations


class NoCacheHTMLMiddleware:
    """Tell browsers not to cache HTML responses.

    Browsers heuristic-cache HTML when no Cache-Control header is set, which
    can show users a stale page after a deploy that changed asset URLs (e.g.
    moving a stylesheet behind a different {% static %} path). Static-file
    responses (CSS/JS/images served by WhiteNoise) keep their long-cache
    headers — only the HTML shell is forced to revalidate.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        ctype = (response.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if ctype == "text/html":
            response["Cache-Control"] = "no-cache, no-store, must-revalidate, private"
            response["Pragma"] = "no-cache"
        return response


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
