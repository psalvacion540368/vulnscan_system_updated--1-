"""
Vulnerability Assessment & Correlation Engine.

Pipeline:
  1. For every OpenPort discovered in a ScanJob, build a normalized
     "product signature" (service + product + version).
  2. Correlate that signature against the local CVERecord table using
     fuzzy product-name matching + simple version comparison.
  3. Separately evaluate a small set of built-in configuration-flaw
     checks (e.g. Telnet exposed, anonymous FTP, outdated TLS) that
     don't map to a specific CVE but are still meaningful risk.
  4. Compute a composite risk score and severity, attach predefined
     remediation guidance, and persist a Finding row per match.
"""
import logging
import re

from django.utils import timezone

from .models import CVERecord, Finding, Severity, ConfigurationFlaw

audit_logger = logging.getLogger("vulnscan.audit")

# Built-in configuration checks -- evaluated directly against service banners,
# independent of the CVE table. Seed rows are created by load_cve_database.
_BUILTIN_CONFIG_FLAWS = {
    "telnet": {
        "title": "Telnet service exposed",
        "description": "Telnet transmits credentials and data in plaintext and should not be exposed.",
        "severity": Severity.HIGH,
        "remediation": "Disable Telnet and use SSH instead. Restrict port 23 at the firewall if legacy support is required.",
    },
    "ftp": {
        "title": "FTP service exposed",
        "description": "Unencrypted FTP is vulnerable to credential sniffing and man-in-the-middle attacks.",
        "severity": Severity.MEDIUM,
        "remediation": "Migrate to SFTP/FTPS, disable anonymous login, and restrict access by IP allow-list.",
    },
    "rsh": {
        "title": "Legacy remote shell (rsh/rlogin) exposed",
        "description": "rsh/rlogin use weak host-based trust and transmit data unencrypted.",
        "severity": Severity.HIGH,
        "remediation": "Disable rsh/rlogin services; replace with SSH.",
    },
    "vnc": {
        "title": "VNC service exposed without evidence of encryption",
        "description": "Unauthenticated or unencrypted VNC access can allow full remote desktop takeover.",
        "severity": Severity.HIGH,
        "remediation": "Require VNC over an SSH tunnel or VPN, enforce strong authentication, and restrict source IPs.",
    },
    "microsoft-ds": {
        "title": "SMB exposed to the scanned network",
        "description": "SMB has a long history of critical remote-code-execution vulnerabilities (e.g. EternalBlue).",
        "severity": Severity.MEDIUM,
        "remediation": "Restrict SMB (445/tcp) to trusted network segments; disable SMBv1; ensure current patches.",
    },
}


def _version_satisfies(pattern: str, actual_version: str) -> bool:
    """
    Very small version-matching helper supporting:
      ""            -> matches any version (product-only match)
      "1.2.3"       -> exact match
      "<1.2.3"      -> actual_version numerically less than pattern
    Falls back to substring match for non-numeric / malformed versions.
    """
    if not pattern:
        return True
    if not actual_version:
        return False

    def _to_tuple(v):
        nums = re.findall(r"\d+", v)
        return tuple(int(n) for n in nums) if nums else None

    if pattern.startswith("<"):
        target = _to_tuple(pattern[1:])
        actual = _to_tuple(actual_version)
        if target is None or actual is None:
            return False
        return actual < target

    return pattern in actual_version or actual_version in pattern


def _risk_score(cvss_score: float, exposure_factor: float = 1.0) -> float:
    """
    Composite score: primarily CVSS, nudged by exposure factor (e.g. whether
    the service is reachable from outside the local segment). Clamped 0-10.
    """
    base = cvss_score if cvss_score is not None else 5.0
    score = base * exposure_factor
    return round(max(0.0, min(score, 10.0)), 1)


def correlate_port(open_port):
    """
    Runs both the CVE-matching pass and the configuration-flaw pass against
    a single OpenPort. Returns a list of unsaved Finding instances.
    """
    findings = []
    signature = open_port.cpe_guess().lower()
    service = (open_port.service_name or "").lower()

    # --- CVE matching ------------------------------------------------
    candidates = CVERecord.objects.filter(product_match__icontains=service) if service else CVERecord.objects.none()
    if open_port.product:
        candidates = candidates | CVERecord.objects.filter(product_match__icontains=open_port.product.lower())

    for cve in candidates.distinct():
        if _version_satisfies(cve.version_pattern, open_port.version) or (
            not open_port.version and cve.product_match in signature
        ):
            findings.append(Finding(
                open_port=open_port,
                finding_type=Finding.FindingType.CVE_MATCH,
                cve=cve,
                title=f"{cve.cve_id}: {cve.description[:80]}",
                description=cve.description,
                severity=cve.severity,
                risk_score=_risk_score(cve.cvss_score),
                remediation=cve.remediation,
            ))

    # --- Configuration-flaw checks -------------------------------------
    flaw = _BUILTIN_CONFIG_FLAWS.get(service)
    if flaw:
        findings.append(Finding(
            open_port=open_port,
            finding_type=Finding.FindingType.CONFIG_FLAW,
            title=flaw["title"],
            description=flaw["description"],
            severity=flaw["severity"],
            risk_score=_risk_score({"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}[flaw["severity"]]),
            remediation=flaw["remediation"],
        ))

    return findings


def correlate_scan_job(job):
    """
    Entry point called by the scanning engine once a ScanJob completes.
    Wipes and recomputes findings for this job (idempotent re-run) and
    persists risk-scored Finding rows.
    """
    from scanning.models import OpenPort

    job.findings.all().delete()  # recompute cleanly on every run
    open_ports = OpenPort.objects.filter(host__job=job)

    all_findings = []
    for port in open_ports:
        for finding in correlate_port(port):
            finding.job = job
            all_findings.append(finding)

    Finding.objects.bulk_create(all_findings)
    audit_logger.info("CORRELATION_COMPLETE job=%s findings=%d", job.id, len(all_findings))
    return all_findings


def overall_risk_rating(findings_queryset):
    """Rolls a set of findings up into a single headline risk rating for dashboards."""
    if not findings_queryset.exists():
        return "None", 0.0
    top_score = max(f.risk_score for f in findings_queryset)
    if top_score >= 9.0:
        label = "Critical"
    elif top_score >= 7.0:
        label = "High"
    elif top_score >= 4.0:
        label = "Medium"
    else:
        label = "Low"
    return label, top_score
