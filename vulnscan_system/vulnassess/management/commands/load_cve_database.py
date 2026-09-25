import json
from django.conf import settings
from django.core.management.base import BaseCommand

from vulnassess.models import CVERecord


class Command(BaseCommand):
    help = "Loads/refreshes the local CVE correlation database from vulnassess/data/cve_local_db.json"

    def handle(self, *args, **options):
        with open(settings.CVE_LOCAL_DB_PATH) as f:
            records = json.load(f)

        created, updated = 0, 0
        for r in records:
            obj, was_created = CVERecord.objects.update_or_create(
                cve_id=r["cve_id"],
                defaults={
                    "product_match": r["product_match"].lower(),
                    "version_pattern": r.get("version_pattern", ""),
                    "description": r["description"],
                    "cvss_score": r.get("cvss_score"),
                    "severity": r["severity"],
                    "remediation": r.get("remediation", ""),
                    "published_date": r.get("published_date") or None,
                    "source": "local",
                },
            )
            created += was_created
            updated += not was_created

        self.stdout.write(self.style.SUCCESS(f"CVE database loaded: {created} created, {updated} updated."))
