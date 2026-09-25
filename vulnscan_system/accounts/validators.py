import re
from django.core.exceptions import ValidationError


def phone_number_validator(value):
    """Validates standard phone number formats."""
    pattern = r"^\+?[1-9]\d{1,14}$"  # E.164 standard format
    if not re.match(pattern, value):
        raise ValidationError("Enter a valid phone number.")


class ComplexityValidator:
    """Requires upper, lower, digit, and symbol -- on top of Django's built-in validators."""

    def validate(self, password, user=None):
        errors = []
        if not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lowercase letter.")
        if not re.search(r"\d", password):
            errors.append("Password must contain at least one digit.")
        if not re.search(r"[^\w\s]", password):
            errors.append("Password must contain at least one special character.")
        if errors:
            raise ValidationError(errors)

    def get_help_text(self):
        return "Password must include upper/lowercase letters, a digit, and a special character."