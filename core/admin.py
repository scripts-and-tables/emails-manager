from django.contrib import admin

from .models import AuthEvent, EmailAccount, EmailAlias


class EmailAliasInline(admin.TabularInline):
    model = EmailAlias
    extra = 0
    fields = ("email_address", "is_enabled", "created_at")
    readonly_fields = ("created_at",)


@admin.register(EmailAccount)
class EmailAccountAdmin(admin.ModelAdmin):
    # The free-tier account cap (core.limits) is enforced in views, not here:
    # only superusers reach Django admin today, and superusers are unlimited.
    # If a non-superuser staff role is ever introduced, override save_model to
    # gate creation on core.limits.is_at_account_limit(obj.owner).
    list_display = ("email_address", "owner", "imap_host", "imap_port", "updated_at")
    search_fields = ("email_address", "owner__username")
    readonly_fields = ("encrypted_password", "created_at", "updated_at")
    inlines = (EmailAliasInline,)


@admin.register(AuthEvent)
class AuthEventAdmin(admin.ModelAdmin):
    """Read-only view of the auth audit log. Rows are created by signal
    handlers and never edited; the admin reflects that with all-readonly
    fields and no add permission."""

    list_display = ("created_at", "event_type", "user", "username", "ip")
    list_filter = ("event_type", "created_at")
    search_fields = ("user__username", "username", "ip")
    readonly_fields = (
        "event_type",
        "user",
        "username",
        "ip",
        "user_agent",
        "metadata",
        "created_at",
    )
    date_hierarchy = "created_at"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
