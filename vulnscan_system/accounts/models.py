from django.contrib.auth.models import AbstractUser
from django.db import models


class Role(models.TextChoices):
    """The three privilege tiers described in the spec."""
    ADMIN = "ADMIN", "Admin"
    ANALYST = "ANALYST", "Security Analyst"
    VIEWER = "VIEWER", "User / Viewer"


class User(AbstractUser):
    role = models.CharField(
        max_length=16, choices=Role.choices, default=Role.VIEWER)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(
        max_length=20, blank=True, null=True, default="") 
    organization = models.CharField(max_length=255, blank=True)
    mfa_enabled = models.BooleanField(default=False)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    # --- Role convenience helpers -----------------------------------
    @property
    def is_admin_role(self):
        return self.role == Role.ADMIN or self.is_superuser

    @property
    def is_analyst_role(self):
        return self.role in (Role.ADMIN, Role.ANALYST) or self.is_superuser

    @property
    def is_viewer_role(self):
        return True  # every authenticated role has at least viewer rights

    def can_manage_accounts(self):
        return self.is_admin_role

    def can_configure_scanning(self):
        return self.is_admin_role

    def can_view_system_logs(self):
        return self.is_admin_role

    def can_run_scans(self):
        return self.is_analyst_role

    def can_analyze_vulnerabilities(self):
        return self.is_analyst_role

    def can_generate_reports(self):
        return self.is_analyst_role

    def can_view_dashboard(self):
        return self.is_viewer_role

    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"


class AuditLogEntry(models.Model):
    """
    System-wide audit trail: every authentication event and every
    privileged action (scan launched, report generated, role changed, ...)
    is recorded here for the Admin 'system-wide logs' view.
    """
    class Action(models.TextChoices):
        LOGIN_SUCCESS = "LOGIN_SUCCESS", "Login success"
        LOGIN_FAILURE = "LOGIN_FAILURE", "Login failure"
        LOGOUT = "LOGOUT", "Logout"
        REGISTER = "REGISTER", "User registered"
        ROLE_CHANGE = "ROLE_CHANGE", "Role changed"
        SCAN_LAUNCHED = "SCAN_LAUNCHED", "Scan launched"
        SCAN_COMPLETED = "SCAN_COMPLETED", "Scan completed"
        REPORT_GENERATED = "REPORT_GENERATED", "Report generated"
        ACCESS_DENIED = "ACCESS_DENIED", "Access denied"
        REQUEST = "REQUEST", "HTTP request"

    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name="audit_entries")
    action = models.CharField(max_length=32, choices=Action.choices)
    detail = models.CharField(max_length=512, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]
        indexes = [models.Index(fields=["-timestamp"]), models.Index(fields=["action"])]

    def __str__(self):
        who = self.user.username if self.user else "anonymous"
        return f"[{self.timestamp:%Y-%m-%d %H:%M:%S}] {who} - {self.action}"
