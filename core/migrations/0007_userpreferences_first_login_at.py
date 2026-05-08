from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0006_userpreferences_account_limit_override'),
    ]

    operations = [
        migrations.AddField(
            model_name='userpreferences',
            name='first_login_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
