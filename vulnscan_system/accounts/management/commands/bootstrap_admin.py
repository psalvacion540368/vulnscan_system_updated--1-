from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from accounts.models import Role


class Command(BaseCommand):
    help = (
        "Creates (or promotes) the first Admin account for a fresh deployment."
    )

    def add_arguments(self, parser):
        parser.add_argument("--username", required=True)
        parser.add_argument("--email", required=True)
        parser.add_argument("--password", required=True)
        parser.add_argument("--phone", required=False, default="")

    def handle(self, *args, **options):
        User = get_user_model()
        username = options["username"]

        user, created = User.objects.get_or_create(
            username=username,
            defaults={
                "email": options["email"],
                "phone_number": options["phone"],  # Fulfills NOT NULL constraint
            },
        )
        user.role = Role.ADMIN
        user.is_staff = True
        user.is_superuser = True
        user.set_password(options["password"])
        user.save()

        verb = "Created" if created else "Promoted"
        self.stdout.write(self.style.SUCCESS(f"{verb} '{username}' to Admin."))