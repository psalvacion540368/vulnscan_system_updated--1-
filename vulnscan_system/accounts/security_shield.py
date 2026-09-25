"""
Security Shield -- application-layer protection against automated attack
tools and brute-force credential guessing.

This complements Django's built-in `SecurityMiddleware` /
`XFrameOptionsMiddleware` (already in MIDDLEWARE) with three extra layers:

  1. Brute-force lockout   -- an IP that racks up repeated failed logins is
                               temporarily locked out, independent of any
                               per-account lockout, using Django's cache
                               framework as a lightweight counter store.
  2. Malicious-payload scan -- request paths/query strings/POST bodies are
                               checked against a set of well-known SQL
                               injection / XSS / path-traversal / command-
                               injection signatures. A match is blocked
                               with 403 and written to the audit trail
                               instead of ever reaching a view.
  3. Known-scanner blocking -- User-Agent strings belonging to common
                               automated vulnerability/attack tools
                               (sqlmap, nikto, nessus, acunetix, nmap
                               scripting engine, masscan, etc.) are
                               rejected outright. Legitimate vulnerability
                               scanning still happens -- through this
                               application's own authorized Scanning
                               Engine -- so blocking *other* scanners from
                               probing the app itself is a pure win.

None of this replaces host-level protections (firewall, IDS/IPS, antivirus
on the server itself) -- it's the extra layer that lives with the
application and can reason about VulnScan-specific context (which user,
which role, which audit trail).
"""
import logging
import re
import time

from django.core.cache import cache
from django.http import HttpResponseForbidden, HttpResponse

audit_logger = logging.getLogger("vulnscan.audit")

# ---------------------------------------------------------------------------
# 1. Brute-force lockout
# ---------------------------------------------------------------------------
FAILED_LOGIN_WINDOW_SECONDS = 15 * 60
FAILED_LOGIN_MAX_ATTEMPTS = 8
LOGIN_PATHS = ("/accounts/login/",)


def _cache_key(prefix, ip):
    return f"secshield:{prefix}:{ip}"


def register_failed_login(ip: str):
    key = _cache_key("failed_login", ip)
    attempts = cache.get(key, 0) + 1
    cache.set(key, attempts, timeout=FAILED_LOGIN_WINDOW_SECONDS)
    return attempts


def is_locked_out(ip: str) -> bool:
    return cache.get(_cache_key("failed_login", ip), 0) >= FAILED_LOGIN_MAX_ATTEMPTS


def clear_failed_logins(ip: str):
    cache.delete(_cache_key("failed_login", ip))


# ---------------------------------------------------------------------------
# 2. Malicious-payload signatures (SQLi / XSS / traversal / command-injection)
# ---------------------------------------------------------------------------
_ATTACK_PATTERNS = [
    re.compile(r"union\s+select", re.I),
    re.compile(r"select\s.+\sfrom\s", re.I),
    re.compile(r"['\"]\s*or\s+['\"]?1['\"]?\s*=\s*['\"]?1", re.I),
    re.compile(r"drop\s+table", re.I),
    re.compile(r"insert\s+into", re.I),
    re.compile(r"--\s*$"),
    re.compile(r"<script[\s>]", re.I),
    re.compile(r"javascript\s*:", re.I),
    re.compile(r"onerror\s*=", re.I),
    re.compile(r"\.\./\.\./"),
    re.compile(r"etc/passwd", re.I),
    re.compile(r";\s*(cat|wget|curl|nc|bash|sh)\s", re.I),
    re.compile(r"\$\(.*\)"),
]

# ---------------------------------------------------------------------------
# 3. Known automated-attack / vulnerability-scanning tool signatures
# ---------------------------------------------------------------------------
_BLOCKED_USER_AGENTS = (
    "sqlmap", "nikto", "acunetix", "nessus", "nmap scripting engine",
    "masscan", "havij", "wpscan", "dirbuster", "gobuster", "hydra",
    "metasploit",
)


def _values_to_scan(request):
    yield request.path
    yield request.META.get("QUERY_STRING", "")
    if request.method == "POST":
        for value in request.POST.values():
            yield str(value)


def _matches_attack_signature(request) -> str | None:
    for value in _values_to_scan(request):
        if not value:
            continue
        for pattern in _ATTACK_PATTERNS:
            if pattern.search(value):
                return pattern.pattern
    return None


def _matches_blocked_user_agent(request) -> str | None:
    ua = request.META.get("HTTP_USER_AGENT", "").lower()
    for tool in _BLOCKED_USER_AGENTS:
        if tool in ua:
            return tool
    return None


class SecurityShieldMiddleware:
    """
    Blocks known attack-tool traffic and malicious-looking payloads before
    they reach any view, and locks out IPs hammering the login endpoint.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = self._client_ip(request)

        # --- Brute-force lockout on the login endpoint ------------------
        if request.path in LOGIN_PATHS and request.method == "POST" and is_locked_out(ip):
            self._log_block(request, ip, "RATE_LIMITED", "Too many failed login attempts")
            return HttpResponse(
                "Too many failed login attempts. Please try again later.",
                status=429,
            )

        # --- Known scanner / attack tool user agents ---------------------
        blocked_tool = _matches_blocked_user_agent(request)
        if blocked_tool:
            self._log_block(request, ip, "INTRUSION_BLOCKED", f"Blocked tool user-agent: {blocked_tool}")
            return HttpResponseForbidden("Request blocked.")

        # --- Malicious payload signatures (SQLi/XSS/traversal/etc.) ------
        signature = _matches_attack_signature(request)
        if signature:
            self._log_block(request, ip, "INTRUSION_BLOCKED", f"Payload matched signature: {signature}")
            return HttpResponseForbidden("Request blocked.")

        response = self.get_response(request)
        return response

    @staticmethod
    def _client_ip(request):
        xff = request.META.get("HTTP_X_FORWARDED_FOR")
        return xff.split(",")[0].strip() if xff else request.META.get("REMOTE_ADDR", "unknown")

    @staticmethod
    def _log_block(request, ip, action_name, detail):
        audit_logger.warning(
            "SECURITY_SHIELD action=%s ip=%s path=%s detail=%s",
            action_name, ip, request.path, detail,
        )
        try:
            from .models import AuditLogEntry
            user = request.user if getattr(request, "user", None) and request.user.is_authenticated else None
            AuditLogEntry.objects.create(
                user=user,
                action=getattr(AuditLogEntry.Action, action_name),
                detail=f"{detail} path={request.path}",
                ip_address=ip if ip != "unknown" else None,
            )
        except Exception:
            # Never let audit-logging failures take the request down --
            # the block itself has already happened above.
            audit_logger.exception("Failed to write SecurityShield audit entry")


class SecurityHeadersMiddleware:
    """
    Adds response headers that harden the browser against drive-by
    exploitation (XSS, clickjacking, MIME-sniffing, referrer leakage) --
    a lightweight, application-side complement to running an antivirus /
    endpoint-protection agent on the host itself.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.setdefault("X-Content-Type-Options", "nosniff")
        response.setdefault("Referrer-Policy", "same-origin")
        response.setdefault(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=()",
        )
        response.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' fonts.googleapis.com; "
            "font-src 'self' fonts.gstatic.com; "
            "img-src 'self' data:; "
            "script-src 'self';",
        )
        return response
