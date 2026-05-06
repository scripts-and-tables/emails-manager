from django import forms
from django.contrib.auth import get_user_model

from .models import EmailAccount


class OtpForm(forms.Form):
    token = forms.CharField(
        label="Authenticator code",
        max_length=8,
        min_length=6,
        widget=forms.TextInput(
            attrs={
                "autocomplete": "one-time-code",
                "inputmode": "numeric",
                "pattern": "[0-9]*",
                "autofocus": "autofocus",
                "class": "form-control form-control-lg text-center",
            }
        ),
    )


class PasswordResetRequestForm(forms.Form):
    email = forms.EmailField(
        label="Email address",
        widget=forms.EmailInput(
            attrs={
                "class": "form-control",
                "autocomplete": "email",
                "autofocus": "autofocus",
            }
        ),
    )


class ProfileInfoForm(forms.ModelForm):
    class Meta:
        model = get_user_model()
        fields = ["first_name", "last_name", "email"]
        widgets = {
            "first_name": forms.TextInput(attrs={"class": "form-control"}),
            "last_name": forms.TextInput(attrs={"class": "form-control"}),
            "email": forms.EmailInput(attrs={"class": "form-control"}),
        }


class EmailAccountForm(forms.ModelForm):
    password = forms.CharField(
        label="App password",
        widget=forms.PasswordInput(render_value=False, attrs={"class": "form-control"}),
        required=False,
        help_text=(
            "For mail.ru, generate an app-specific password in account security settings "
            "and make sure IMAP is enabled. Leave blank when editing to keep the existing password."
        ),
    )

    class Meta:
        model = EmailAccount
        fields = ["email_address", "display_name", "imap_host", "imap_port"]
        widgets = {
            "email_address": forms.EmailInput(attrs={"class": "form-control"}),
            "display_name": forms.TextInput(attrs={"class": "form-control"}),
            "imap_host": forms.TextInput(attrs={"class": "form-control"}),
            "imap_port": forms.NumberInput(attrs={"class": "form-control"}),
        }

    def clean(self):
        cleaned = super().clean()
        password = cleaned.get("password")
        if not self.instance.pk and not password:
            self.add_error("password", "Required when adding a new account.")
        return cleaned

    def save(self, commit: bool = True) -> EmailAccount:
        account: EmailAccount = super().save(commit=False)
        password = self.cleaned_data.get("password")
        if password:
            account.set_password(password)
        if commit:
            account.save()
        return account
