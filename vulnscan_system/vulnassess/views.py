from django.shortcuts import render, get_object_or_404
from django.db.models import Q

from accounts.decorators import role_required
from .models import Finding, Severity


@role_required("ADMIN", "ANALYST")
def findings_list(request):
    """Security Analyst: analyze vulnerabilities."""
    findings = Finding.objects.select_related("open_port__host", "cve", "job").all()

    severity = request.GET.get("severity")
    search = request.GET.get("q")
    if severity:
        findings = findings.filter(severity=severity)
    if search:
        findings = findings.filter(
            Q(title__icontains=search) | Q(description__icontains=search) | Q(cve__cve_id__icontains=search)
        )

    return render(request, "vulnassess/findings_list.html", {
        "findings": findings[:500], "severities": Severity.choices,
        "current_severity": severity, "search": search or "",
    })


@role_required("ADMIN", "ANALYST")
def finding_detail(request, finding_id):
    finding = get_object_or_404(
        Finding.objects.select_related("open_port__host__job", "cve"), pk=finding_id
    )
    return render(request, "vulnassess/finding_detail.html", {"finding": finding})
