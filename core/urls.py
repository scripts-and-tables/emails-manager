from django.urls import path

from . import views

app_name = "core"

urlpatterns = [
    path("", views.index, name="index"),
    path("home/", views.home, name="home"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("verify-otp/", views.verify_otp, name="verify_otp"),
    path("profile/", views.profile, name="profile"),
    path("profile/password/", views.profile_password_change, name="profile_password_change"),
    path("profile/2fa/", views.profile_2fa_toggle, name="profile_2fa_toggle"),
    path("password-reset/", views.password_reset_request, name="password_reset_request"),
    path("password-reset/done/", views.password_reset_complete, name="password_reset_complete"),
    path(
        "password-reset/<uidb64>/<token>/",
        views.password_reset_confirm,
        name="password_reset_confirm",
    ),
    path("accounts/", views.accounts_list, name="accounts_list"),
    path("accounts/new/", views.account_new, name="account_new"),
    path("accounts/bulk/", views.account_bulk_add, name="account_bulk_add"),
    path("accounts/<int:pk>/", views.account_detail, name="account_detail"),
    path("accounts/<int:pk>/edit/", views.account_edit, name="account_edit"),
    path("accounts/<int:pk>/delete/", views.account_delete, name="account_delete"),
    path("accounts/<int:pk>/test/", views.account_test, name="account_test"),
    path("accounts/<int:pk>/toggle/", views.account_toggle, name="account_toggle"),
    path("accounts/<int:pk>/password/", views.account_update_password, name="account_update_password"),
    path("inbox/", views.inbox, name="inbox"),
    path("inbox/<int:account_id>/<str:uid>/", views.email_detail, name="email_detail"),
]
