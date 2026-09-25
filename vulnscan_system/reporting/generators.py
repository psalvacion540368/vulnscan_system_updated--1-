"""
Presentation & Reporting Engine -- backend PDF/CSV generation.

Both generators pull directly from the database (ScanJob -> Finding chain)
so a report is always a faithful export of what's already stored, never a
separate source of truth.
"""
import csv
import io

from django.core.files.base import ContentFile
from django.utils import timezone


def _findings_for_job(job):
    return job.findings.select_related("open_port__host", "cve").order_by("-risk_score")


def generate_csv_report(job) -> ContentFile:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([
        "Host", "Port", "Protocol", "Service", "Severity", "Risk Score",
        "CVE ID", "Title", "Description", "Remediation", "Detected At",
    ])
    for f in _findings_for_job(job):
        writer.writerow([
            f.open_port.host.ip_address, f.open_port.port_number, f.open_port.protocol,
            f.open_port.service_name, f.get_severity_display(), f.risk_score,
            f.cve.cve_id if f.cve else "", f.title, f.description, f.remediation,
            f.detected_at.strftime("%Y-%m-%d %H:%M"),
        ])
    filename = f"scan_{job.id}_report_{timezone.now():%Y%m%d%H%M%S}.csv"
    return filename, ContentFile(buffer.getvalue().encode("utf-8"))


def generate_pdf_report(job) -> ContentFile:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    )

    styles = getSampleStyleSheet()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    story = []

    story.append(Paragraph("Vulnerability Assessment Report", styles["Title"]))
    story.append(Paragraph(
        f"Target: {job.target.label} ({job.target.ip_or_cidr})<br/>"
        f"Scan type: {job.get_scan_type_display()}<br/>"
        f"Completed: {job.finished_at:%Y-%m-%d %H:%M UTC}" if job.finished_at else "In progress",
        styles["Normal"],
    ))
    story.append(Spacer(1, 0.25 * inch))

    findings = list(_findings_for_job(job))
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    summary_data = [["Severity", "Count"]] + [[k.title(), str(v)] for k, v in counts.items() if v]
    summary_table = Table(summary_data, colWidths=[2 * inch, 1 * inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.3 * inch))

    story.append(Paragraph("Detailed Findings", styles["Heading2"]))
    severity_colors = {
        "CRITICAL": colors.HexColor("#7f1d1d"), "HIGH": colors.HexColor("#b91c1c"),
        "MEDIUM": colors.HexColor("#b45309"), "LOW": colors.HexColor("#374151"),
        "INFO": colors.HexColor("#6b7280"),
    }
    for f in findings:
        story.append(Paragraph(
            f"<b>{f.title}</b> — <font color='{severity_colors.get(f.severity, colors.black).hexval()}'>"
            f"{f.get_severity_display()}</font> (risk {f.risk_score}/10)",
            styles["Heading4"],
        ))
        story.append(Paragraph(
            f"Host: {f.open_port.host.ip_address}:{f.open_port.port_number}/{f.open_port.protocol} "
            f"({f.open_port.service_name or 'unknown service'})", styles["Normal"],
        ))
        if f.cve:
            story.append(Paragraph(f"Reference: {f.cve.cve_id} (CVSS {f.cve.cvss_score})", styles["Normal"]))
        story.append(Paragraph(f.description, styles["Normal"]))
        story.append(Paragraph(f"<b>Remediation:</b> {f.remediation}", styles["Normal"]))
        story.append(Spacer(1, 0.15 * inch))

    if not findings:
        story.append(Paragraph("No findings were recorded for this scan.", styles["Normal"]))

    doc.build(story)
    filename = f"scan_{job.id}_report_{timezone.now():%Y%m%d%H%M%S}.pdf"
    return filename, ContentFile(buffer.getvalue())
