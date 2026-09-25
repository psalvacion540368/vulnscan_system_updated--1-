from django.conf import settings
from django.db import models

from scanning.models import ScanJob


class GeneratedReport(models.Model):
    class Format(models.TextChoices):
        PDF = "PDF", "PDF"
        CSV = "CSV", "CSV"

    job = models.ForeignKey(ScanJob, on_delete=models.CASCADE, related_name="reports")
    generated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    format = models.CharField(max_length=8, choices=Format.choices)
    file = models.FileField(upload_to="reports/")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.job} - {self.format} ({self.created_at:%Y-%m-%d})"
