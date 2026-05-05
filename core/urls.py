from django.urls import path

from . import views

app_name = "core"

urlpatterns = [
    path("", views.index, name="index"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("verify-otp/", views.verify_otp, name="verify_otp"),
    path("accounts/", views.accounts_list, name="accounts_list"),
    path("accounts/new/", views.account_new, name="account_new"),
    path("accounts/<int:pk>/edit/", views.account_edit, name="account_edit"),
    path("accounts/<int:pk>/delete/", views.account_delete, name="account_delete"),
    path("status/", views.status, name="status"),
    path("inbox/", views.inbox, name="inbox"),
    path("inbox/<int:account_id>/<str:uid>/", views.email_detail, name="email_detail"),
]
