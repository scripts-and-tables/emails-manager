from django.contrib import admin

from .models import EmailAccount


@admin.register(EmailAccount)
class EmailAccountAdmin(admin.ModelAdmin):
    # The free-tier account cap (core.limits) is enforced in views, not here:
    # only superusers reach Django admin today, and superusers are unlimited.
    # If a non-superuser staff role is ever introduced, override save_model to
    # gate creation on core.limits.is_at_account_limit(obj.owner).
    list_display = ("email_address", "owner", "imap_host", "imap_port", "updated_at")
    search_fields = ("email_address", "owner__username")
    readonly_fields = ("encrypted_password", "created_at", "updated_at")
