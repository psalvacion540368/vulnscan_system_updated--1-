"""
Historical comparison for the Vulnerability Assessment & Correlation Engine.

Findings are recreated fresh on every scan run (see matcher.correlate_scan_job),
so two ScanJobs against the same Target never share Finding rows directly --
comparison has to match findings across jobs by a stable "fingerprint"
(host IP + port + protocol + CVE id / title) rather than by primary key.
"""
from dataclasses import dataclass, field


@dataclass
class ComparisonResult:
    new_findings: list = field(default_factory=list)       # present in new_job, not in old_job
    resolved_findings: list = field(default_factory=list)  # present in old_job, not in new_job
    unchanged_findings: list = field(default_factory=list) # present in both
    old_job: object = None
    new_job: object = None


def _fingerprint(finding):
    """A key that identifies 'the same' finding across two different scan runs."""
    cve_key = finding.cve.cve_id if finding.cve else finding.title
    return (finding.open_port.host.ip_address, finding.open_port.port_number,
            finding.open_port.protocol, cve_key)


def compare_jobs(old_job, new_job):
    """
    Returns a ComparisonResult diffing new_job's findings against old_job's.
    old_job should be the earlier scan, new_job the later one, both against
    the same Target -- the caller is responsible for picking a sensible pair.
    """
    old_findings = list(old_job.findings.select_related("open_port__host", "cve").all())
    new_findings = list(new_job.findings.select_related("open_port__host", "cve").all())

    old_by_fp = {_fingerprint(f): f for f in old_findings}
    new_by_fp = {_fingerprint(f): f for f in new_findings}

    old_fps = set(old_by_fp)
    new_fps = set(new_by_fp)

    result = ComparisonResult(old_job=old_job, new_job=new_job)
    result.new_findings = [new_by_fp[fp] for fp in sorted(new_fps - old_fps, key=str)]
    result.resolved_findings = [old_by_fp[fp] for fp in sorted(old_fps - new_fps, key=str)]
    result.unchanged_findings = [new_by_fp[fp] for fp in sorted(old_fps & new_fps, key=str)]

    # Sort each list by risk score (highest first) for readability.
    result.new_findings.sort(key=lambda f: f.risk_score, reverse=True)
    result.resolved_findings.sort(key=lambda f: f.risk_score, reverse=True)
    result.unchanged_findings.sort(key=lambda f: f.risk_score, reverse=True)
    return result


def previous_completed_job(job):
    """Finds the most recent completed ScanJob against the same target, before `job`."""
    from scanning.models import ScanJob
    return (
        ScanJob.objects.filter(
            target=job.target, status=ScanJob.Status.COMPLETED, queued_at__lt=job.queued_at,
        )
        .order_by("-queued_at")
        .first()
    )


def target_severity_trend(target):
    """
    Lightweight longitudinal view: for each completed job against this target,
    how many findings of each severity were present. Used for a simple trend
    table on the target/dashboard view (no charting library required).
    """
    from scanning.models import ScanJob

    jobs = ScanJob.objects.filter(target=target, status=ScanJob.Status.COMPLETED).order_by("queued_at")
    rows = []
    for job in jobs:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in job.findings.all():
            counts[f.severity] = counts.get(f.severity, 0) + 1
        rows.append({"job": job, "counts": counts, "total": sum(counts.values())})
    return rows
