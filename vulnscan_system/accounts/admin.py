from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, AuditLogEntry


@admin.register(User)
class VulnScanUserAdmin(UserAdmin):
    list_display = ("username", "email", "role", "is_active", "last_login", "last_login_ip")
    list_filter = ("role", "is_active")
    fieldsets = UserAdmin.fieldsets + (
        ("RBAC", {"fields": ("role", "organization", "mfa_enabled", "last_login_ip")}),
    )


@admin.register(AuditLogEntry)
class AuditLogEntryAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "user", "action", "ip_address", "detail")
    list_filter = ("action",)
    search_fields = ("detail", "user__username")
    readonly_fields = [f.name for f in AuditLogEntry._meta.fields]

    def has_add_permission(self, request):
        return False  # audit entries are system-generated only

    def has_change_permission(self, request, obj=None):
        return False
