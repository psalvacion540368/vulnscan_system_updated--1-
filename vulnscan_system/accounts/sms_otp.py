"""
SMS One-Time-Password utilities.

Why this exists alongside TOTP
-------------------------------
Google's own account-security guidance (echoed in accounts/totp.py) is
that SMS codes are the *weakest* common second factor -- vulnerable to
SIM-swapping and interception -- and that an authenticator app or a
FIDO2 hardware key should be preferred wherever possible.

Some users, though, don't have a compatible device or simply prefer a
text message, and offering *a* second factor is still far better than
offering none. This module implements that fallback with several
independent safeguards stacked together, rather than a single
"generate and text a code" call:

  1. Random, short-lived code   -- a fresh 6-digit numeric code, valid
                                    for a short window (default 5 min).
  2. Hashed-at-rest storage     -- only the SHA-256 hash of the code is
                                    ever persisted (models.SMSOTPDevice),
                                    matching the backup-code pattern in
                                    accounts/totp.py.
  3. Attempt limiting           -- a device locks itself after a small
                                    number of wrong guesses and requires
                                    a brand-new code, blocking online
                                    brute-forcing of the 6-digit space.
  4. Pluggable delivery backend -- the actual "send this text message"
                                    call is isolated behind `send_sms`
                                    so a real carrier/gateway integration
                                    (Twilio, Vonage, AWS SNS, ...) can be
                                    dropped in later via settings without
                                    touching any view or model code.
"""
import hashlib
import logging
import secrets
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

audit_logger = logging.getLogger("vulnscan.audit")

CODE_LENGTH = 6
CODE_TTL_SECONDS = getattr(settings, "SMS_OTP_TTL_SECONDS", 5 * 60)
MAX_FAILED_ATTEMPTS = getattr(settings, "SMS_OTP_MAX_ATTEMPTS", 5)


def generate_code() -> str:
    """Component 1: a fresh random numeric code, zero-padded to CODE_LENGTH."""
    return f"{secrets.randbelow(10 ** CODE_LENGTH):0{CODE_LENGTH}d}"


def _hash_code(code: str) -> str:
    return hashlib.sha256(code.strip().encode("utf-8")).hexdigest()


def issue_code(device) -> str:
    """
    Component 2: generate a code, store only its hash + expiry on the
    device, reset the attempt counter, and return the PLAINTEXT code so
    the caller can send it. The plaintext is never saved anywhere.
    """
    code = generate_code()
    device.code_hash = _hash_code(code)
    device.code_expires_at = timezone.now() + timedelta(seconds=CODE_TTL_SECONDS)
    device.failed_attempts = 0
    device.save(update_fields=["code_hash", "code_expires_at", "failed_attempts"])
    return code


def verify_code(device, submitted_code: str) -> bool:
    """
    Component 3: check a submitted code against the stored hash, honoring
    expiry and the attempt-limit lockout. Successful verification
    invalidates the code (one-time use).
    """
    if not submitted_code or not device.code_hash or not device.code_expires_at:
        return False

    if device.failed_attempts >= MAX_FAILED_ATTEMPTS:
        return False  # locked -- caller must issue a new code

    if timezone.now() > device.code_expires_at:
        return False  # expired

    submitted = submitted_code.strip().replace(" ", "")
    if _hash_code(submitted) == device.code_hash:
        # One-time use: clear the code so it can't be replayed.
        device.code_hash = ""
        device.code_expires_at = None
        device.failed_attempts = 0
        device.save(update_fields=["code_hash", "code_expires_at", "failed_attempts"])
        return True

    device.failed_attempts += 1
    device.save(update_fields=["failed_attempts"])
    return False


def mask_phone(phone_number: str) -> str:
    """Display helper: '+15551234567' -> '+*******4567'."""
    if not phone_number or len(phone_number) < 4:
        return "****"
    return "*" * (len(phone_number) - 4) + phone_number[-4:]


def send_sms(phone_number: str, code: str) -> None:
    """
    Component 4: pluggable delivery backend.

    Real deployments should set SMS_GATEWAY_URL / SMS_GATEWAY_API_KEY in
    the environment and swap in a real provider call here (Twilio, AWS
    SNS, Vonage, etc. -- all take a destination number, a message body,
    and an API credential). Until that's configured, codes are written
    to the audit log only, exactly like Django's console email backend
    does for development -- never text a real user without a configured
    provider.
    """
    gateway_url = getattr(settings, "SMS_GATEWAY_URL", "")

    if not gateway_url:
        audit_logger.info(
            "SMS_OTP_DEV_BACKEND to=%s code=%s (no SMS_GATEWAY_URL configured -- "
            "code logged instead of sent; configure a real gateway for production)",
            mask_phone(phone_number), code,
        )
        return

    import requests  # local import: only needed when a real gateway is configured

    api_key = getattr(settings, "SMS_GATEWAY_API_KEY", "")
    try:
        requests.post(
            gateway_url,
            json={"to": phone_number, "message": f"Your VulnScan verification code is {code}"},
            headers={"Authorization": f"Bearer {api_key}"} if api_key else {},
            timeout=5,
        )
    except requests.RequestException:
        audit_logger.exception("SMS_OTP_SEND_FAILED to=%s", mask_phone(phone_number))
        raise
