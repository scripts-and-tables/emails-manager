from functools import wraps

from django.contrib.auth.decorators import login_required
from django.http import Http404
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


def staff_required(view_func):
    """OTP-verified + is_staff. Non-staff get a 404 so the URL doesn't leak."""

    @wraps(view_func)
    @otp_required
    def _wrapped(request, *args, **kwargs):
        if not request.user.is_staff:
            raise Http404
        return view_func(request, *args, **kwargs)

    return _wrapped
