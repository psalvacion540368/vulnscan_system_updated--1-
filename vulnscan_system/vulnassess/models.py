from django.db import models

from scanning.models import OpenPort, ScanJob


class Severity(models.TextChoices):
    CRITICAL = "CRITICAL", "Critical"
    HIGH = "HIGH", "High"
    MEDIUM = "MEDIUM", "Medium"
    LOW = "LOW", "Low"
    INFO = "INFO", "Informational"


class CVERecord(models.Model):
    """
    Local cache of CVE entries used for correlation. Seeded from
    vulnassess/data/cve_local_db.json (see management command
    load_cve_database) and/or refreshed from the NVD API.
    """
    cve_id = models.CharField(max_length=32, unique=True)          # e.g. CVE-2021-41773
    product_match = models.CharField(max_length=255, db_index=True)  # lowercase product keyword, e.g. "apache httpd"
    version_pattern = models.CharField(max_length=64, blank=True)    # e.g. "2.4.49" or "<2.4.51"
    description = models.TextField()
    cvss_score = models.FloatField(null=True, blank=True)             # 0.0 - 10.0
    severity = models.CharField(max_length=16, choices=Severity.choices, default=Severity.MEDIUM)
    remediation = models.TextField(blank=True)
    published_date = models.DateField(null=True, blank=True)
    source = models.CharField(max_length=32, default="local")  # local | nvd

    class Meta:
        indexes = [models.Index(fields=["product_match"])]

    def __str__(self):
        return f"{self.cve_id} ({self.severity})"


class Finding(models.Model):
    """A CVE (or configuration-flaw) match against a specific scanned port/service."""

    class FindingType(models.TextChoices):
        CVE_MATCH = "CVE_MATCH", "CVE match"
        CONFIG_FLAW = "CONFIG_FLAW", "Configuration flaw"

    job = models.ForeignKey(ScanJob, on_delete=models.CASCADE, related_name="findings")
    open_port = models.ForeignKey(OpenPort, on_delete=models.CASCADE, related_name="findings")
    finding_type = models.CharField(max_length=16, choices=FindingType.choices, default=FindingType.CVE_MATCH)
    cve = models.ForeignKey(CVERecord, null=True, blank=True, on_delete=models.SET_NULL, related_name="findings")
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=16, choices=Severity.choices)
    risk_score = models.FloatField(help_text="0-10 composite risk score")
    remediation = models.TextField(blank=True)
    detected_at = models.DateTimeField(auto_now_add=True)
    acknowledged = models.BooleanField(default=False)

    class Meta:
        ordering = ["-risk_score", "-detected_at"]
        indexes = [models.Index(fields=["severity"]), models.Index(fields=["-risk_score"])]

    def __str__(self):
        return f"{self.title} [{self.severity}] on {self.open_port}"


class ConfigurationFlaw(models.Model):
    """
    Reference table of non-CVE configuration checks the correlation engine
    evaluates directly against scan output (e.g. anonymous FTP, default
    creds banners, outdated TLS, telnet exposed).
    """
    key = models.CharField(max_length=64, unique=True)      # e.g. "telnet_exposed"
    matches_service = models.CharField(max_length=64)        # e.g. "telnet"
    title = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=16, choices=Severity.choices)
    remediation = models.TextField()

    def __str__(self):
        return self.title
