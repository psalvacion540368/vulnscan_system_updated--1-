from django.contrib import admin
from .models import CVERecord, Finding, ConfigurationFlaw


@admin.register(CVERecord)
class CVERecordAdmin(admin.ModelAdmin):
    list_display = ("cve_id", "product_match", "version_pattern", "severity", "cvss_score", "source")
    list_filter = ("severity", "source")
    search_fields = ("cve_id", "product_match", "description")


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ("title", "severity", "risk_score", "job", "open_port", "acknowledged", "detected_at")
    list_filter = ("severity", "acknowledged", "finding_type")
    search_fields = ("title", "description")


admin.site.register(ConfigurationFlaw)
