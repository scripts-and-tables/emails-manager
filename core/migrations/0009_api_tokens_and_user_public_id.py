"""Add the external read API:

- `UserPreferences.public_id` — opaque per-user UUID, used to refer to a user
  in admin URLs and any future surface without leaking username/email.
- `APIToken` — long-lived Bearer credential for the external API. Stored as
  prefix + sha256 hash; the plaintext value is shown to the owner exactly
  once at creation.
- `APIRequestLog` — one row per API call, append-only forensic trail.

The `public_id` field is added in three steps because it's both UUID-defaulted
and unique: column nullable → backfill UUIDs for existing rows → flip to
NOT NULL + unique. This is the migration shape Django itself recommends in
its docs on adding unique fields.
"""

import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


def _backfill_public_ids(apps, schema_editor):
    UserPreferences = apps.get_model("core", "UserPreferences")
    for prefs in UserPreferences.objects.filter(public_id__isnull=True):
        prefs.public_id = uuid.uuid4()
        prefs.save(update_fields=["public_id"])


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("core", "0008_authevent"),
    ]

    operations = [
        # 1. Add public_id as nullable, no unique constraint yet.
        migrations.AddField(
            model_name="userpreferences",
            name="public_id",
            field=models.UUIDField(null=True, editable=False),
        ),
        # 2. Backfill every existing row with a fresh UUID.
        migrations.RunPython(_backfill_public_ids, reverse_code=migrations.RunPython.noop),
        # 3. Tighten to the final shape: non-null, unique, indexed, default uuid4 for new rows.
        migrations.AlterField(
            model_name="userpreferences",
            name="public_id",
            field=models.UUIDField(
                default=uuid.uuid4,
                editable=False,
                unique=True,
                db_index=True,
            ),
        ),
        # New models.
        migrations.CreateModel(
            name="APIToken",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=120)),
                ("key_prefix", models.CharField(db_index=True, max_length=12)),
                ("key_hash", models.CharField(max_length=64)),
                ("expires_at", models.DateTimeField(blank=True, null=True)),
                ("last_used_at", models.DateTimeField(blank=True, null=True)),
                ("last_used_ip", models.GenericIPAddressField(blank=True, null=True)),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "owner",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="api_tokens",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "accounts",
                    models.ManyToManyField(
                        blank=True,
                        related_name="api_tokens",
                        to="core.emailaccount",
                    ),
                ),
            ],
            options={"ordering": ("-created_at",)},
        ),
        migrations.CreateModel(
            name="APIRequestLog",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False)),
                ("endpoint", models.CharField(max_length=120)),
                ("status_code", models.IntegerField()),
                ("minutes", models.IntegerField(blank=True, null=True)),
                ("count", models.IntegerField(blank=True, null=True)),
                ("ip", models.GenericIPAddressField(blank=True, null=True)),
                ("user_agent", models.CharField(blank=True, max_length=255)),
                ("latency_ms", models.IntegerField()),
                ("error_code", models.CharField(blank=True, max_length=40)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                (
                    "token",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="requests",
                        to="core.apitoken",
                    ),
                ),
                (
                    "mailbox",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="api_requests",
                        to="core.emailaccount",
                    ),
                ),
            ],
            options={"ordering": ("-created_at",)},
        ),
        migrations.AddIndex(
            model_name="apirequestlog",
            index=models.Index(fields=["token", "-created_at"], name="core_apireq_token_i_idx"),
        ),
        migrations.AddIndex(
            model_name="apirequestlog",
            index=models.Index(fields=["endpoint", "-created_at"], name="core_apireq_endpt_i_idx"),
        ),
    ]
