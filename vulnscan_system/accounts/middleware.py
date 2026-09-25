import logging

audit_logger = logging.getLogger("vulnscan.audit")

# Only log meaningful, non-static, non-polling paths to keep the audit trail readable.
_SKIP_PREFIXES = ("/static/", "/media/", "/favicon")


class AuditLogMiddleware:
    """Lightweight request logger feeding the Admin's system-wide audit view."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        path = request.path
        if request.user.is_authenticated and not path.startswith(_SKIP_PREFIXES):
            audit_logger.info(
                "REQUEST user=%s role=%s method=%s path=%s status=%s",
                request.user.username, getattr(request.user, "role", "-"),
                request.method, path, response.status_code,
            )
        return response
