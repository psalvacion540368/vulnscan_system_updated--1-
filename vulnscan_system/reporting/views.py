import json
from collections import Counter
from datetime import timedelta

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.utils import timezone
from django.db.models import Count, Avg
from django.db.models.functions import TruncDate

from accounts.decorators import role_required, _client_ip
from accounts.models import AuditLogEntry
from scanning.models import ScanJob, OpenPort
from vulnassess.models import Finding, Severity

from vulnassess.matcher import overall_risk_rating

from .generators import generate_csv_report, generate_pdf_report
from .models import GeneratedReport

SEVERITY_COLORS = {
    "CRITICAL": "#ff4d5e",
    "HIGH": "#ff9f40",
    "MEDIUM": "#ffd23f",
    "LOW": "#7488a1",
    "INFO": "#4d5c70",
}
STATUS_COLORS = {
    "COMPLETED": "#34d399",
    "RUNNING": "#ff9f40",
    "QUEUED": "#7488a1",
    "FAILED": "#ff4d5e",
    "CANCELLED": "#4d5c70",
}


@login_required
def dashboard(request):
    """
    User / Viewer: read-only access to high-level dashboard summaries,
    risk ratings, and mitigation guides. Admin/Analyst see the same view
    with extra links surfaced in the nav bar (see base.html).
    """
    recent_jobs = ScanJob.objects.select_related("target").all()[:10]
    findings = Finding.objects.all()

    severity_counts = {
        label: findings.filter(severity=value).count() for value, label in Severity.choices
    }
    overall_label, overall_score = overall_risk_rating(findings)

    top_findings = findings.select_related("open_port__host", "cve").order_by("-risk_score")[:10]

    severity_chart = {
        "labels": [label for label, count in severity_counts.items() if count],
        "data": [count for count in severity_counts.values() if count],
        "colors": [SEVERITY_COLORS[value] for value, label in Severity.choices if severity_counts[label]],
    }

    top_risk_chart = {
        "labels": [f.title[:40] for f in top_findings[:5]],
        "data": [f.risk_score for f in top_findings[:5]],
        "colors": [SEVERITY_COLORS.get(f.severity, "#7488a1") for f in top_findings[:5]],
    }

    return render(request, "reporting/dashboard.html", {
        "recent_jobs": recent_jobs,
        "severity_counts": severity_counts,
        "overall_label": overall_label,
        "overall_score": overall_score,
        "top_findings": top_findings,
        "total_findings": findings.count(),
        "severity_chart_json": json.dumps(severity_chart),
        "top_risk_chart_json": json.dumps(top_risk_chart),
    })


@role_required("ADMIN", "ANALYST")
def generate_report(request, job_id, fmt):
    job = get_object_or_404(ScanJob, pk=job_id)
    if fmt == "pdf":
        filename, content = generate_pdf_report(job)
        report_format = GeneratedReport.Format.PDF
    elif fmt == "csv":
        filename, content = generate_csv_report(job)
        report_format = GeneratedReport.Format.CSV
    else:
        messages.error(request, "Unsupported report format.")
        return redirect("scanning:job_detail", job_id=job.id)

    report = GeneratedReport.objects.create(job=job, generated_by=request.user, format=report_format)
    report.file.save(filename, content)

    AuditLogEntry.objects.create(
        user=request.user, action=AuditLogEntry.Action.REPORT_GENERATED,
        detail=f"job={job.id} format={fmt}", ip_address=_client_ip(request),
    )
    messages.success(request, f"{fmt.upper()} report generated.")
    return redirect("reporting:report_list")


@login_required
def analytics(request):
    """
    Read-only analytics: severity mix, finding/scan trends over time,
    scan-job outcome breakdown, riskiest hosts, and most frequent CVEs.
    All authenticated roles (including Viewer) can see this -- same
    visibility model as the main dashboard.
    """
    days = int(request.GET.get("days", 30))
    days = days if days in (7, 30, 90) else 30
    since = timezone.now() - timedelta(days=days)

    findings = Finding.objects.all()
    jobs = ScanJob.objects.all()

    # --- Severity distribution (donut) ---------------------------------
    severity_counts = {label: findings.filter(severity=value).count() for value, label in Severity.choices}
    severity_chart = {
        "labels": [label for label, count in severity_counts.items() if count],
        "data": [count for count in severity_counts.values() if count],
        "colors": [SEVERITY_COLORS[value] for value, label in Severity.choices if severity_counts[label]],
    }

    # --- Findings detected per day (line) -------------------------------
    findings_by_day = (
        findings.filter(detected_at__gte=since)
        .annotate(day=TruncDate("detected_at"))
        .values("day")
        .annotate(count=Count("id"))
        .order_by("day")
    )
    findings_trend = {row["day"].isoformat(): row["count"] for row in findings_by_day if row.get("day") is not None}
    day_labels = [(since + timedelta(days=i)).date().isoformat() for i in range(days + 1)]
    findings_trend_chart = {
        "labels": day_labels,
        "data": [findings_trend.get(d, 0) for d in day_labels],
    }

    # --- Scan job outcome breakdown (bar) -------------------------------
    status_counts = {
        label: jobs.filter(status=value).count() for value, label in ScanJob.Status.choices
    }
    status_chart = {
        "labels": [label for label, count in status_counts.items() if count],
        "data": [count for count in status_counts.values() if count],
        "colors": [STATUS_COLORS[value] for value, label in ScanJob.Status.choices if status_counts[label]],
    }

    # --- Top 5 riskiest hosts by finding count (horizontal bar) ---------
    host_rows = (
        findings.values("open_port__host__ip_address")
        .annotate(count=Count("id"), avg_risk=Avg("risk_score"))
        .order_by("-count")[:5]
    )
    top_hosts_chart = {
        "labels": [row["open_port__host__ip_address"] for row in host_rows],
        "data": [row["count"] for row in host_rows],
    }

    # --- Most frequent CVEs (table) -------------------------------------
    cve_counter = Counter(
        f.cve.cve_id for f in findings.select_related("cve") if f.cve_id
    )
    top_cves = cve_counter.most_common(8)

    # --- Headline stats ---------------------------------------------------
    avg_risk = findings.aggregate(avg=Avg("risk_score"))["avg"] or 0
    acknowledged = findings.filter(acknowledged=True).count()
    unacknowledged = findings.count() - acknowledged
    overall_label, overall_score = overall_risk_rating(findings)
    scans_in_range = jobs.filter(queued_at__gte=since).count()

    context = {
        "days": days,
        "overall_label": overall_label,
        "overall_score": overall_score,
        "avg_risk": round(avg_risk, 2),
        "total_findings": findings.count(),
        "acknowledged": acknowledged,
        "unacknowledged": unacknowledged,
        "scans_in_range": scans_in_range,
        "total_hosts": OpenPort.objects.values("host").distinct().count(),
        "severity_chart_json": json.dumps(severity_chart),
        "findings_trend_chart_json": json.dumps(findings_trend_chart),
        "status_chart_json": json.dumps(status_chart),
        "top_hosts_chart_json": json.dumps(top_hosts_chart),
        "top_cves": top_cves,
    }
    return render(request, "reporting/analytics.html", context)


@login_required
def report_list(request):
    """Viewers can see/download past reports (read-only); generation itself is gated above."""
    reports = GeneratedReport.objects.select_related("job__target", "generated_by").all()[:100]
    return render(request, "reporting/report_list.html", {"reports": reports})
