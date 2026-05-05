from functools import wraps

from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect

OTP_VERIFIED_SESSION_KEY = "otp_verified"


def is_otp_verified(request) -> bool:
    return bool(request.session.get(OTP_VERIFIED_SESSION_KEY))


def otp_required(view_func):
    """Requires the user to have passed the email-OTP step in this session."""

    @wraps(view_func)
    @login_required
    def _wrapped(request, *args, **kwargs):
        if not is_otp_verified(request):
            return redirect("core:login")
        return view_func(request, *args, **kwargs)

    return _wrapped
