"""
Two-Factor Authentication (TOTP) utilities.

Why TOTP instead of SMS / email OTP
------------------------------------
SMS one-time-passwords can be intercepted via SIM-swap attacks or SS7
exploitation, and email OTPs are only as safe as the (often less-protected)
recovery mailbox they land in. Google itself now steers accounts away from
SMS/email codes toward Google Prompt or FIDO2 hardware keys because both
resist phishing and number-porting attacks.

This project implements the same class of protection using the open
RFC 6238 Time-based One-Time Password algorithm (the standard behind
Google Authenticator / Authy / Microsoft Authenticator). It is:

  * unique       -- generated per-user, never transmitted over SMS/email
  * popular      -- the de-facto standard for authenticator-app 2FA
  * rarely built from scratch -- almost everyone reaches for a library
    instead of implementing the HMAC/time-step math by hand

The scheme is made up of three-plus independent components, all required
together before an attacker who only has a stolen password can get in:

  1. Shared secret      -- a random Base32 key issued once per user and
                            never sent over the network again.
  2. Time-step HMAC OTP -- the actual RFC 6238 algorithm: HMAC-SHA1 over
                            the 30-second time counter, truncated to a
                            6-digit code.
  3. QR provisioning    -- an otpauth:// URI (rendered as a QR code) that
                            lets an authenticator app enroll the secret
                            without the user ever having to type it.
  4. Backup codes       -- one-time-use recovery codes (hashed at rest)
                            so a lost device doesn't lock the user out
                            permanently.
"""
import base64
import hashlib
import io
import secrets

import pyotp
import qrcode

TOTP_ISSUER = "VulnScan"
BACKUP_CODE_COUNT = 10


def generate_secret() -> str:
    """Component 1: a fresh random Base32 shared secret."""
    return pyotp.random_base32()


def totp_for(secret: str) -> pyotp.TOTP:
    return pyotp.TOTP(secret)


def verify_totp_code(secret: str, code: str) -> bool:
    """Component 2: verify a 6-digit time-step code (allow +/-1 step of drift)."""
    if not secret or not code:
        return False
    code = code.strip().replace(" ", "")
    if not code.isdigit():
        return False
    return totp_for(secret).verify(code, valid_window=1)


def provisioning_uri(secret: str, account_name: str) -> str:
    """Component 3: otpauth:// URI for enrollment in an authenticator app."""
    return totp_for(secret).provisioning_uri(name=account_name, issuer_name=TOTP_ISSUER)


def qr_code_data_uri(uri: str) -> str:
    """Render the provisioning URI as a base64 PNG data URI for <img src=...>."""
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    encoded = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def _hash_backup_code(code: str) -> str:
    return hashlib.sha256(code.strip().lower().encode("utf-8")).hexdigest()


def generate_backup_codes(count: int = BACKUP_CODE_COUNT):
    """Component 4: single-use recovery codes. Returns the PLAINTEXT codes
    (shown to the user exactly once) -- callers must store only the hashes."""
    return [secrets.token_hex(4) for _ in range(count)]


def hash_backup_codes(plain_codes):
    return [_hash_backup_code(c) for c in plain_codes]


def consume_backup_code(device, submitted_code: str) -> bool:
    """Check submitted_code against the device's stored hashes; if it matches,
    remove it (one-time use) and persist. Returns True on success."""
    if not submitted_code:
        return False
    hashed = _hash_backup_code(submitted_code)
    codes = list(device.backup_codes or [])
    if hashed in codes:
        codes.remove(hashed)
        device.backup_codes = codes
        device.save(update_fields=["backup_codes"])
        return True
    return False
