import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models

import accounts.validators


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("accounts", "0002_totpdevice"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="phone_number",
            field=models.CharField(
                blank=True,
                help_text="Optional. Only used if you enable SMS-based two-factor authentication.",
                max_length=20,
                validators=[accounts.validators.phone_number_validator],
            ),
        ),
        migrations.AddField(
            model_name="user",
            name="phone_verified",
            field=models.BooleanField(default=False),
        ),
        migrations.CreateModel(
            name="SMSOTPDevice",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("phone_number", models.CharField(max_length=20, validators=[accounts.validators.phone_number_validator])),
                ("confirmed", models.BooleanField(default=False)),
                ("code_hash", models.CharField(blank=True, max_length=64)),
                ("code_expires_at", models.DateTimeField(blank=True, null=True)),
                ("failed_attempts", models.PositiveSmallIntegerField(default=0)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="sms_otp_device",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
    ]
