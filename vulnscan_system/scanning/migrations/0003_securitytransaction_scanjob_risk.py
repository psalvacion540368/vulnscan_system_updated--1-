from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [("scanning", "0002_alter_scanjob_scan_type_alter_target_ip_or_cidr")]

    operations = [
        migrations.AddField(
            model_name="scanjob", name="attacker_risk_score",
            field=models.PositiveSmallIntegerField(default=0),
        ),
        migrations.AddField(
            model_name="scanjob", name="attacker_risk_label",
            field=models.CharField(default="LOW", max_length=16),
        ),
        migrations.AddField(
            model_name="scanjob", name="attacker_risk_reasons",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.CreateModel(
            name="SecurityTransaction",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("source_ip", models.GenericIPAddressField()),
                ("amount", models.DecimalField(decimal_places=2, default=0, max_digits=12)),
                ("status", models.CharField(choices=[("APPROVED", "Approved"), ("DECLINED", "Declined"), ("BLOCKED", "Blocked")], default="APPROVED", max_length=16)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("user", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="security_transactions", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.AddIndex(
            model_name="securitytransaction",
            index=models.Index(fields=["source_ip", "-created_at"], name="scanning_se_source__3e5c6a_idx"),
        ),
    ]