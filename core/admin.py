from django.contrib import admin

from .models import EmailAccount


@admin.register(EmailAccount)
class EmailAccountAdmin(admin.ModelAdmin):
    list_display = ("email_address", "owner", "imap_host", "imap_port", "updated_at")
    search_fields = ("email_address", "owner__username")
    readonly_fields = ("encrypted_password", "created_at", "updated_at")
