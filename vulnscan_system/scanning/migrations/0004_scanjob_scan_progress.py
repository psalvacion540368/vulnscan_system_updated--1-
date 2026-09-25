from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("scanning", "0003_securitytransaction_scanjob_risk")]

    operations = [
        migrations.AddField(
            model_name="scanjob",
            name="scan_progress",
            field=models.PositiveSmallIntegerField(default=0),
        ),
    ]