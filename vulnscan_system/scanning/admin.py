from django.contrib import admin
from .models import Target, ScanJob, DiscoveredHost, OpenPort, SecurityTransaction


class OpenPortInline(admin.TabularInline):
    model = OpenPort
    extra = 0


@admin.register(Target)
class TargetAdmin(admin.ModelAdmin):
    list_display = ("label", "ip_or_cidr", "owner", "is_active", "created_at")
    list_filter = ("is_active",)


@admin.register(ScanJob)
class ScanJobAdmin(admin.ModelAdmin):
    list_display = ("id", "target", "initiated_by", "scan_type", "status", "queued_at", "finished_at")
    list_filter = ("status", "scan_type")


@admin.register(DiscoveredHost)
class DiscoveredHostAdmin(admin.ModelAdmin):
    list_display = ("ip_address", "job", "hostname", "os_family", "os_accuracy")
    inlines = [OpenPortInline]


admin.site.register(OpenPort)


@admin.register(SecurityTransaction)
class SecurityTransactionAdmin(admin.ModelAdmin):
    list_display = ("source_ip", "status", "amount", "user", "created_at")
    list_filter = ("status", "created_at")
