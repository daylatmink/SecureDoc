"""Email OTP and TOTP helpers for Phase 1 stabilization."""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from datetime import timedelta

from sqlalchemy.orm import Session

from .crypto_utils import utc_now
from .models import EmailOtpToken, UserMfaSetting

OTP_PURPOSES = {"REGISTER", "RESET_PASSWORD", "CHANGE_EMAIL", "SENSITIVE_ACTION", "LOGIN_MFA", "SIGNING_CONFIRMATION"}
OTP_TTL_SECONDS = 600
OTP_MAX_ATTEMPTS = 5
OTP_CODE_DIGITS = 6
TOTP_PERIOD_SECONDS = 30
TOTP_DIGITS = 6


def _hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _encode_totp_secret(secret: str) -> str:
    return "demo-b64:" + base64.b64encode(secret.encode("utf-8")).decode("ascii")


def _decode_totp_secret(stored: str) -> str | None:
    if not stored.startswith("demo-b64:"):
        return None
    try:
        return base64.b64decode(stored.removeprefix("demo-b64:")).decode("utf-8")
    except Exception:
        return None


def _otp_hash(
    email: str,
    purpose: str,
    otp: str,
    *,
    signing_request_id: str | None = None,
    document_hash: str | None = None,
    certificate_serial: str | None = None,
    signing_purpose: str | None = None,
    nonce: str | None = None,
) -> str:
    parts = [
        email.lower(),
        purpose,
        signing_request_id or "",
        (document_hash or "").lower(),
        certificate_serial or "",
        signing_purpose or "",
        nonce or "",
        otp,
    ]
    return hashlib.sha256(":".join(parts).encode("utf-8")).hexdigest()


def create_email_otp(db: Session, email: str, purpose: str) -> tuple[EmailOtpToken, str]:
    normalized_purpose = normalize_otp_purpose(purpose)
    normalized_email = email.strip().lower()
    otp = f"{secrets.randbelow(10 ** OTP_CODE_DIGITS):0{OTP_CODE_DIGITS}d}"
    now = utc_now().replace(tzinfo=None)
    token = EmailOtpToken(
        email=normalized_email,
        purpose=normalized_purpose,
        otp_hash=_otp_hash(normalized_email, normalized_purpose, otp),
        expires_at=now + timedelta(seconds=OTP_TTL_SECONDS),
        used_at=None,
        attempt_count=0,
        max_attempts=OTP_MAX_ATTEMPTS,
        created_at=now,
    )
    db.add(token)
    db.flush()
    return token, otp


def create_signing_email_otp(
    db: Session,
    *,
    email: str,
    signing_request_id: str,
    document_hash: str,
    certificate_serial: str,
    signing_purpose: str,
    nonce: str,
) -> tuple[EmailOtpToken, str]:
    normalized_email = email.strip().lower()
    normalized_purpose = "SIGNING_CONFIRMATION"
    normalized_document_hash = document_hash.lower()
    otp = f"{secrets.randbelow(10 ** OTP_CODE_DIGITS):0{OTP_CODE_DIGITS}d}"
    now = utc_now().replace(tzinfo=None)
    token = EmailOtpToken(
        email=normalized_email,
        purpose=normalized_purpose,
        signing_request_id=signing_request_id,
        document_hash=normalized_document_hash,
        certificate_serial=certificate_serial,
        signing_purpose=signing_purpose,
        nonce=nonce,
        otp_hash=_otp_hash(
            normalized_email,
            normalized_purpose,
            otp,
            signing_request_id=signing_request_id,
            document_hash=normalized_document_hash,
            certificate_serial=certificate_serial,
            signing_purpose=signing_purpose,
            nonce=nonce,
        ),
        expires_at=now + timedelta(seconds=OTP_TTL_SECONDS),
        used_at=None,
        attempt_count=0,
        max_attempts=OTP_MAX_ATTEMPTS,
        created_at=now,
    )
    db.add(token)
    db.flush()
    return token, otp


def verify_email_otp(db: Session, email: str, purpose: str, otp: str) -> tuple[bool, str]:
    normalized_purpose = normalize_otp_purpose(purpose)
    normalized_email = email.strip().lower()
    token = (
        db.query(EmailOtpToken)
        .filter_by(email=normalized_email, purpose=normalized_purpose)
        .order_by(EmailOtpToken.id.desc())
        .first()
    )
    if not token:
        return False, "OTP not found"
    if token.used_at is not None:
        return False, "OTP already used"
    if token.expires_at < utc_now().replace(tzinfo=None):
        return False, "OTP expired"
    if token.attempt_count >= token.max_attempts:
        return False, "OTP attempt limit exceeded"

    token.attempt_count += 1
    expected = _otp_hash(normalized_email, normalized_purpose, otp)
    if not hmac.compare_digest(token.otp_hash, expected):
        db.flush()
        return False, "Invalid OTP"

    token.used_at = utc_now().replace(tzinfo=None)
    db.flush()
    return True, "OTP verified"


def verify_signing_email_otp(
    db: Session,
    *,
    email: str,
    signing_request_id: str,
    document_hash: str,
    certificate_serial: str,
    signing_purpose: str,
    nonce: str,
    otp: str,
) -> tuple[bool, str]:
    normalized_email = email.strip().lower()
    normalized_document_hash = document_hash.lower()
    token = (
        db.query(EmailOtpToken)
        .filter_by(
            email=normalized_email,
            purpose="SIGNING_CONFIRMATION",
            signing_request_id=signing_request_id,
            document_hash=normalized_document_hash,
            certificate_serial=certificate_serial,
            signing_purpose=signing_purpose,
            nonce=nonce,
        )
        .order_by(EmailOtpToken.id.desc())
        .first()
    )
    if not token:
        return False, "OTP not found for this signing request"
    if token.used_at is not None:
        return False, "OTP already used"
    if token.expires_at < utc_now().replace(tzinfo=None):
        return False, "OTP expired"
    if token.attempt_count >= token.max_attempts:
        return False, "OTP attempt limit exceeded"

    token.attempt_count += 1
    expected = _otp_hash(
        normalized_email,
        "SIGNING_CONFIRMATION",
        otp,
        signing_request_id=signing_request_id,
        document_hash=normalized_document_hash,
        certificate_serial=certificate_serial,
        signing_purpose=signing_purpose,
        nonce=nonce,
    )
    if not hmac.compare_digest(token.otp_hash, expected):
        db.flush()
        return False, "Invalid OTP"

    token.used_at = utc_now().replace(tzinfo=None)
    db.flush()
    return True, "OTP verified"


def normalize_otp_purpose(purpose: str) -> str:
    normalized = purpose.strip().upper()
    if normalized not in OTP_PURPOSES:
        raise ValueError("Invalid OTP purpose")
    return normalized


def create_totp_setting(db: Session, email: str) -> tuple[UserMfaSetting, str, str]:
    normalized_email = email.strip().lower()
    secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
    now = utc_now().replace(tzinfo=None)
    setting = db.query(UserMfaSetting).filter_by(email=normalized_email).first()
    if setting:
        setting.secret_encrypted = _encode_totp_secret(secret)
        setting.enabled = 0
        setting.verified_at = None
        setting.updated_at = now
    else:
        setting = UserMfaSetting(
            email=normalized_email,
            type="TOTP",
            secret_encrypted=_encode_totp_secret(secret),
            enabled=0,
            verified_at=None,
            created_at=now,
            updated_at=now,
        )
        db.add(setting)
    db.flush()
    uri = f"otpauth://totp/SecureDoc:{normalized_email}?secret={secret}&issuer=SecureDoc&digits={TOTP_DIGITS}&period={TOTP_PERIOD_SECONDS}"
    return setting, secret, uri


def verify_totp_setup(db: Session, email: str, secret: str, code: str) -> tuple[bool, str]:
    normalized_email = email.strip().lower()
    setting = db.query(UserMfaSetting).filter_by(email=normalized_email).first()
    if not setting:
        return False, "TOTP setup not found"
    stored_secret = _decode_totp_secret(setting.secret_encrypted)
    if stored_secret is None:
        if not hmac.compare_digest(setting.secret_encrypted, _hash_secret(secret)):
            return False, "TOTP secret mismatch"
        stored_secret = secret
    if not hmac.compare_digest(stored_secret, secret):
        return False, "TOTP secret mismatch"
    if not verify_totp_code(secret, code):
        return False, "Invalid TOTP code"
    now = utc_now().replace(tzinfo=None)
    setting.enabled = 1
    setting.verified_at = now
    setting.updated_at = now
    setting.last_used_at = now
    db.flush()
    return True, "TOTP enabled"


def verify_enabled_totp_for_email(db: Session, email: str, code: str) -> tuple[bool, str]:
    normalized_email = email.strip().lower()
    setting = db.query(UserMfaSetting).filter_by(email=normalized_email, type="TOTP").first()
    if not setting or setting.enabled != 1:
        return False, "TOTP is not enabled for signer"
    secret = _decode_totp_secret(setting.secret_encrypted)
    if secret is None:
        return False, "TOTP secret is not available for confirmation"
    if not verify_totp_code(secret, code):
        return False, "Invalid TOTP code"
    now = utc_now().replace(tzinfo=None)
    setting.last_used_at = now
    setting.updated_at = now
    db.flush()
    return True, "TOTP verified"


def verify_totp_code(secret: str, code: str, window: int = 1) -> bool:
    if not code.isdigit() or len(code) != TOTP_DIGITS:
        return False
    counter = int(time.time() // TOTP_PERIOD_SECONDS)
    return any(hmac.compare_digest(code, _totp_at(secret, counter + offset)) for offset in range(-window, window + 1))


def current_totp_code(secret: str) -> str:
    return _totp_at(secret, int(time.time() // TOTP_PERIOD_SECONDS))


def _totp_at(secret: str, counter: int) -> str:
    padded_secret = secret + ("=" * ((8 - len(secret) % 8) % 8))
    key = base64.b32decode(padded_secret, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{value % (10 ** TOTP_DIGITS):0{TOTP_DIGITS}d}"
