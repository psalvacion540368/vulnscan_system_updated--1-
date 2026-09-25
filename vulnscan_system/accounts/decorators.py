"""
Authorization Management: dynamic, role-based routing of access.

Usage on function-based views:
    @role_required("ADMIN")
    def system_logs(request): ...

Usage on class-based views:
    class ScanLaunchView(RoleRequiredMixin, View):
        allowed_roles = ("ADMIN", "ANALYST")
"""
import logging
from functools import wraps

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect

audit_logger = logging.getLogger("vulnscan.audit")

ROLE_HIERARCHY = {"VIEWER": 0, "ANALYST": 1, "ADMIN": 2}


def _client_ip(request):
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    return xff.split(",")[0].strip() if xff else request.META.get("REMOTE_ADDR")


def role_required(*allowed_roles):
    """Grant access only to users whose role is in allowed_roles (or superusers)."""
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def _wrapped(request, *args, **kwargs):
            user = request.user
            if user.is_superuser or user.role in allowed_roles:
                return view_func(request, *args, **kwargs)

            audit_logger.warning(
                "ACCESS_DENIED user=%s role=%s path=%s required=%s",
                user.username, user.role, request.path, allowed_roles,
            )
            from accounts.models import AuditLogEntry
            AuditLogEntry.objects.create(
                user=user, action=AuditLogEntry.Action.ACCESS_DENIED,
                detail=f"path={request.path} required_roles={allowed_roles}",
                ip_address=_client_ip(request),
            )
            messages.error(request, "You do not have permission to access that area.")
            return redirect("reporting:dashboard")
        return _wrapped
    return decorator


def minimum_role(role_name):
    """Grant access to users at or above role_name in the hierarchy."""
    threshold = ROLE_HIERARCHY[role_name]
    allowed = [r for r, level in ROLE_HIERARCHY.items() if level >= threshold]
    return role_required(*allowed)


class RoleRequiredMixin:
    """Class-based-view equivalent of role_required."""
    allowed_roles = ()

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect("accounts:login")
        if request.user.is_superuser or request.user.role in self.allowed_roles:
            return super().dispatch(request, *args, **kwargs)
        raise PermissionDenied("Insufficient role privileges.")
