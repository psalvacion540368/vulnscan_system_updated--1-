import logging
import threading

from django.contrib import messages
from django.http import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404

from accounts.decorators import role_required, _client_ip
from accounts.models import AuditLogEntry
from .engine import assert_authorized, UnauthorizedTargetError, discover_managed_wifi_targets
from .forms import TargetForm, ScanJobForm
from .models import Target, ScanJob

audit_logger = logging.getLogger("vulnscan.audit")


@role_required("ADMIN", "ANALYST")
def job_list(request):
    jobs = ScanJob.objects.select_related("target", "initiated_by").all()[:200]
    targets = Target.objects.filter(is_active=True)
    return render(request, "scanning/job_list.html", {"jobs": jobs, "targets": targets})


@role_required("ADMIN", "ANALYST")
def add_target(request):
    if request.method == "POST":
        form = TargetForm(request.POST)
        if form.is_valid():
            target = form.save(commit=False)
            target.owner = request.user
            try:
                assert_authorized(target.ip_or_cidr)
            except UnauthorizedTargetError as exc:
                messages.error(request, str(exc))
                return render(request, "scanning/add_target.html", {"form": form})
            target.save()
            messages.success(request, f"Target '{target.label}' added.")
            return redirect("scanning:job_list")
    else:
        form = TargetForm()
    return render(request, "scanning/add_target.html", {"form": form})


@role_required("ADMIN", "ANALYST")
def wifi_targets(request):
    """Return the connected local Wi-Fi network as a candidate scan target."""
    return JsonResponse({"targets": discover_managed_wifi_targets()})


@role_required("ADMIN", "ANALYST")
def launch_scan(request):
    """Security Analyst: execute active scans."""
    if request.method == "POST":
        form = ScanJobForm(request.POST)
        if form.is_valid():
            target = get_object_or_404(Target, pk=request.POST.get("target"))
            try:
                assert_authorized(target.ip_or_cidr)
            except UnauthorizedTargetError as exc:
                messages.error(request, str(exc))
                return redirect("scanning:job_list")

            job = form.save(commit=False)
            job.target = target
            job.initiated_by = request.user
            job.save()

            AuditLogEntry.objects.create(
                user=request.user, action=AuditLogEntry.Action.SCAN_LAUNCHED,
                detail=f"job={job.id} target={target.ip_or_cidr} type={job.scan_type}",
                ip_address=_client_ip(request),
            )

            # Run asynchronously so the request doesn't block on a multi-minute scan.
            # In production, replace this thread with a Celery task queue.
            from .engine import execute_scan_job
            threading.Thread(target=_run_job_safely, args=(job.id,), daemon=True).start()

            messages.success(request, f"Scan job #{job.id} queued.")
            return redirect("scanning:job_detail", job_id=job.id)
    return redirect("scanning:job_list")


def _run_job_safely(job_id):
    from .engine import execute_scan_job
    job = ScanJob.objects.get(pk=job_id)
    try:
        execute_scan_job(job)
    except Exception:
        audit_logger.exception("Unhandled error running scan job %s", job_id)


@role_required("ADMIN", "ANALYST")
def job_detail(request, job_id):
    job = get_object_or_404(ScanJob.objects.select_related("target"), pk=job_id)
    hosts = job.hosts.prefetch_related("ports").all()
    progress = 100 if job.status == ScanJob.Status.COMPLETED else job.scan_progress
    from vulnassess.models import Finding, Severity
    severity_counts = {
        value: job.findings.filter(severity=value).count()
        for value, _label in Severity.choices
    }

    from vulnassess.comparison import previous_completed_job
    previous_job = previous_completed_job(job) if job.status == ScanJob.Status.COMPLETED else None

    return render(request, "scanning/job_detail.html", {
        "job": job, "hosts": hosts, "previous_job": previous_job,
        "severity_counts": severity_counts, "scan_progress": progress,
    })


@role_required("ADMIN", "ANALYST")
def job_status(request, job_id):
    """
    Lightweight JSON polling endpoint used by job_detail.html while a scan is
    QUEUED/RUNNING, so the page can update live without a full reload.
    """
    from django.http import JsonResponse
    job = get_object_or_404(ScanJob, pk=job_id)
    return JsonResponse({
        "status": job.status,
        "status_display": job.get_status_display(),
        "progress": 100 if job.status == ScanJob.Status.COMPLETED else job.scan_progress,
        "host_count": job.hosts.count(),
        "error_message": job.error_message,
    })


@role_required("ADMIN", "ANALYST")
def job_compare(request, job_id):
    """Diffs this job's findings against the previous completed scan of the same target."""
    from vulnassess.comparison import compare_jobs, previous_completed_job

    new_job = get_object_or_404(ScanJob.objects.select_related("target"), pk=job_id)

    compare_to_id = request.GET.get("against")
    if compare_to_id:
        old_job = get_object_or_404(ScanJob, pk=compare_to_id, target=new_job.target)
    else:
        old_job = previous_completed_job(new_job)

    if old_job is None:
        messages.info(request, "There's no earlier completed scan of this target to compare against yet.")
        return redirect("scanning:job_detail", job_id=new_job.id)

    result = compare_jobs(old_job, new_job)

    other_jobs = ScanJob.objects.filter(
        target=new_job.target, status=ScanJob.Status.COMPLETED
    ).exclude(pk=new_job.id).order_by("-queued_at")

    return render(request, "scanning/job_compare.html", {
        "new_job": new_job, "old_job": old_job, "result": result, "other_jobs": other_jobs,
    })


@role_required("ADMIN", "ANALYST")
def target_trend(request, target_id):
    """Longitudinal severity-count view across all completed scans of a target."""
    from vulnassess.comparison import target_severity_trend

    target = get_object_or_404(Target, pk=target_id)
    rows = target_severity_trend(target)
    return render(request, "scanning/target_trend.html", {"target": target, "rows": rows})
