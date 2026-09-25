from django.conf import settings
from django.db import models


class Target(models.Model):
    """A host, CIDR range, or web hostname/domain authorized for scanning."""
    label = models.CharField(max_length=255)
    ip_or_cidr = models.CharField(
        max_length=255,
        verbose_name="IP or CIDR",
        help_text="e.g. 10.0.0.15 or 10.0.0.0/24",
    )
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="targets")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.label} ({self.ip_or_cidr})"


class ScanJob(models.Model):
    """A queued/running/finished scan job against a Target."""

    class ScanType(models.TextChoices):
        DISCOVERY = "DISCOVERY", "Host discovery"
        PORT_SCAN = "PORT_SCAN", "Port & service scan"
        FULL = "FULL", "Full scan (discovery + ports + OS fingerprint)"

    class Status(models.TextChoices):
        QUEUED = "QUEUED", "Queued"
        RUNNING = "RUNNING", "Running"
        COMPLETED = "COMPLETED", "Completed"
        FAILED = "FAILED", "Failed"
        CANCELLED = "CANCELLED", "Cancelled"

    target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name="jobs")
    initiated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="scan_jobs")
    scan_type = models.CharField(max_length=16, choices=ScanType.choices, default=ScanType.FULL)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.QUEUED)
    nmap_arguments = models.CharField(max_length=255, default="-sV -O --top-ports 100")
    queued_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    scan_progress = models.PositiveSmallIntegerField(default=0)
    attacker_risk_score = models.PositiveSmallIntegerField(default=0)
    attacker_risk_label = models.CharField(max_length=16, default="LOW")
    attacker_risk_reasons = models.JSONField(default=list, blank=True)

    class Meta:
        ordering = ["-queued_at"]

    def __str__(self):
        return f"ScanJob#{self.id} {self.target} [{self.status}]"


class SecurityTransaction(models.Model):
    """A transaction/security event used as one signal in risk assessment."""

    class Status(models.TextChoices):
        APPROVED = "APPROVED", "Approved"
        DECLINED = "DECLINED", "Declined"
        BLOCKED = "BLOCKED", "Blocked"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="security_transactions",
    )
    source_ip = models.GenericIPAddressField()
    amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.APPROVED)
    created_at = models.DateTimeField(auto_now_add=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["source_ip", "-created_at"])]

    def __str__(self):
        return f"{self.source_ip} {self.status} {self.amount}"


class DiscoveredHost(models.Model):
    """A single live host found within a ScanJob's target range."""
    job = models.ForeignKey(ScanJob, on_delete=models.CASCADE, related_name="hosts")
    ip_address = models.GenericIPAddressField()
    hostname = models.CharField(max_length=255, blank=True)
    state = models.CharField(max_length=16, default="up")  # up / down
    os_family = models.CharField(max_length=128, blank=True)
    os_accuracy = models.PositiveSmallIntegerField(null=True, blank=True)  # 0-100
    mac_address = models.CharField(max_length=32, blank=True)
    raw_probe_notes = models.TextField(blank=True, help_text="Notes from Scapy SYN/ACK probing")

    class Meta:
        unique_together = ("job", "ip_address")

    def __str__(self):
        return f"{self.ip_address} ({self.hostname or 'unknown'})"


class OpenPort(models.Model):
    """A single open port + identified service/version on a DiscoveredHost."""
    host = models.ForeignKey(DiscoveredHost, on_delete=models.CASCADE, related_name="ports")
    port_number = models.PositiveIntegerField()
    protocol = models.CharField(max_length=8, default="tcp")  # tcp / udp
    state = models.CharField(max_length=16, default="open")
    service_name = models.CharField(max_length=128, blank=True)   # e.g. "http", "ssh"
    product = models.CharField(max_length=255, blank=True)         # e.g. "OpenSSH"
    version = models.CharField(max_length=128, blank=True)         # e.g. "8.2p1"
    extra_info = models.CharField(max_length=255, blank=True)

    class Meta:
        unique_together = ("host", "port_number", "protocol")
        ordering = ["port_number"]

    def cpe_guess(self):
        """A rough CPE-like string used by the correlation engine to match CVEs."""
        parts = [p for p in [self.product, self.version] if p]
        return " ".join(parts) if parts else self.service_name

    def __str__(self):
        return f"{self.host.ip_address}:{self.port_number}/{self.protocol} {self.service_name}"
