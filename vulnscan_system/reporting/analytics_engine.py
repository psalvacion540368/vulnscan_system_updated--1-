"""
Analytics Engine
================

Sits between the Persistence Layer (Database -- ScanJob/OpenPort/Finding
via the Django ORM) and the Presentation Layer (GUI/Dashboard templates).

Flow:

    Assess & Correlate phase (vulnassess) writes structured scan results
    (findings mapped to CVEs/CVSS scores) into the database
        -> Analytics Engine (this module) queries that data and computes
           KPIs: severity/threat distribution, top vulnerable hosts, scan
           outcome trends, open-port trends, most frequent CVEs
        -> dashboard() / analytics() views (reporting/views.py) hand the
           computed KPIs straight to the templates for the interactive
           real-time dashboard
        -> On-demand Export Reports (PDF/CSV/XML, reporting/generators.py)
           are built from both the raw scan logs *and* these same computed
           summaries, so an exported report always matches what the
           dashboard showed.

Views should never query models directly for chart/KPI data -- that logic
lives here so it has exactly one implementation, is unit-testable on its
own, and can be reused by exports.
"""
import json
from collections import Counter
from datetime import timedelta

from django.db.models import Avg, Count
from django.db.models.functions import TruncDate
from django.utils import timezone

from scanning.models import OpenPort, ScanJob
from vulnassess.matcher import overall_risk_rating
from vulnassess.models import Finding, Severity

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


def get_dashboard_kpis():
    """KPIs for the top-level Security Dashboard."""
    recent_jobs = ScanJob.objects.select_related("target").all()[:10]
    findings = Finding.objects.all()

    severity_counts = {
        label: findings.filter(severity=value).count() for value, label in Severity.choices
    }
    overall_label, overall_score = overall_risk_rating(findings)
    top_findings = findings.select_related("open_port__host", "cve").order_by("-risk_score")[:10]

    return {
        "recent_jobs": recent_jobs,
        "severity_counts": severity_counts,
        "overall_label": overall_label,
        "overall_score": overall_score,
        "top_findings": top_findings,
        "total_findings": findings.count(),
    }


def get_analytics_kpis(days: int = 30):
    """
    KPIs for the Analytics page: severity mix, finding/scan trends over
    time, scan-job outcome breakdown, riskiest hosts, most frequent CVEs,
    and headline aggregate stats.
    """
    days = days if days in (7, 30, 90) else 30
    since = timezone.now() - timedelta(days=days)

    findings = Finding.objects.all()
    jobs = ScanJob.objects.all()

    # --- Severity / threat distribution (donut) -------------------------
    severity_counts = {label: findings.filter(severity=value).count() for value, label in Severity.choices}
    severity_chart = {
        "labels": [label for label, count in severity_counts.items() if count],
        "data": [count for count in severity_counts.values() if count],
        "colors": [SEVERITY_COLORS[value] for value, label in Severity.choices if severity_counts[label]],
    }

    # --- Findings detected per day (line) --------------------------------
    findings_by_day = (
        findings.filter(detected_at__gte=since)
        .annotate(day=TruncDate("detected_at"))
        .values("day")
        .annotate(count=Count("id"))
        .order_by("day")
    )
    findings_trend = {row["day"].isoformat(): row["count"] for row in findings_by_day}
    day_labels = [(since + timedelta(days=i)).date().isoformat() for i in range(days + 1)]
    findings_trend_chart = {
        "labels": day_labels,
        "data": [findings_trend.get(d, 0) for d in day_labels],
    }

    # --- Scan job outcome breakdown (bar) --------------------------------
    status_counts = {label: jobs.filter(status=value).count() for value, label in ScanJob.Status.choices}
    status_chart = {
        "labels": [label for label, count in status_counts.items() if count],
        "data": [count for count in status_counts.values() if count],
        "colors": [STATUS_COLORS[value] for value, label in ScanJob.Status.choices if status_counts[label]],
    }

    # --- Top vulnerable / riskiest hosts (horizontal bar) ----------------
    host_rows = (
        findings.values("open_port__host__ip_address")
        .annotate(count=Count("id"), avg_risk=Avg("risk_score"))
        .order_by("-count")[:5]
    )
    top_hosts_chart = {
        "labels": [row["open_port__host__ip_address"] for row in host_rows],
        "data": [row["count"] for row in host_rows],
    }

    # --- Open-port trend: most commonly seen open ports ------------------
    open_port_rows = (
        OpenPort.objects.values("port_number", "protocol")
        .annotate(count=Count("id"))
        .order_by("-count")[:8]
    )
    open_port_trend = [
        {"port": row["port_number"], "protocol": row["protocol"], "count": row["count"]}
        for row in open_port_rows
    ]

    # --- Most frequent CVEs (table) ---------------------------------------
    cve_counter = Counter(f.cve.cve_id for f in findings.select_related("cve") if f.cve_id)
    top_cves = cve_counter.most_common(8)

    # --- Headline stats -----------------------------------------------------
    avg_risk = findings.aggregate(avg=Avg("risk_score"))["avg"] or 0
    acknowledged = findings.filter(acknowledged=True).count()
    unacknowledged = findings.count() - acknowledged
    overall_label, overall_score = overall_risk_rating(findings)
    scans_in_range = jobs.filter(queued_at__gte=since).count()

    return {
        "days": days,
        "overall_label": overall_label,
        "overall_score": overall_score,
        "avg_risk": round(avg_risk, 2),
        "total_findings": findings.count(),
        "acknowledged": acknowledged,
        "unacknowledged": unacknowledged,
        "scans_in_range": scans_in_range,
        "total_hosts": OpenPort.objects.values("host").distinct().count(),
        "open_port_trend": open_port_trend,
        "severity_chart_json": json.dumps(severity_chart),
        "findings_trend_chart_json": json.dumps(findings_trend_chart),
        "status_chart_json": json.dumps(status_chart),
        "top_hosts_chart_json": json.dumps(top_hosts_chart),
        "top_cves": top_cves,
    }


def get_export_summary():
    """
    The computed-KPI half of an export: used alongside a job's raw
    findings (reporting/generators.py::_findings_for_job) so PDF/CSV/XML
    exports carry the same analytical summary the dashboard shows, not a
    second, possibly-divergent calculation.
    """
    kpis = get_analytics_kpis(days=30)
    return {
        "overall_label": kpis["overall_label"],
        "overall_score": kpis["overall_score"],
        "avg_risk": kpis["avg_risk"],
        "total_findings": kpis["total_findings"],
        "acknowledged": kpis["acknowledged"],
        "unacknowledged": kpis["unacknowledged"],
        "total_hosts": kpis["total_hosts"],
        "top_cves": kpis["top_cves"],
    }
