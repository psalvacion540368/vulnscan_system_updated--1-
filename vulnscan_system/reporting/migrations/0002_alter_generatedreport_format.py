from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("reporting", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="generatedreport",
            name="format",
            field=models.CharField(
                choices=[("PDF", "PDF"), ("CSV", "CSV"), ("XML", "XML")],
                max_length=8,
            ),
        ),
    ]
