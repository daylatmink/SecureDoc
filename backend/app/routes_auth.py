"""Phase 1 authentication stabilization routes.

These endpoints model OTP/TOTP behavior without pretending to be a complete
production identity system.
"""

import smtplib
from email.message import EmailMessage

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, EmailStr
from sqlalchemy.orm import Session

from .auth_utils import create_email_otp, create_totp_setting, totp_storage_warning, verify_email_otp, verify_totp_setup
from .config import SMTP_FROM_EMAIL, SMTP_HOST, SMTP_PASSWORD, SMTP_PORT, SMTP_USERNAME, SMTP_USE_TLS
from .database import SessionLocal
from .security import SIGNER, require_roles

router = APIRouter(prefix="/api/auth", tags=["auth"])


class EmailOtpRequest(BaseModel):
    email: EmailStr
    purpose: str


class EmailOtpVerifyRequest(BaseModel):
    email: EmailStr
    purpose: str
    otp: str


class TotpSetupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pass


class TotpVerifySetupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _send_otp_email(email: str, purpose: str, otp: str) -> str:
    if not SMTP_HOST:
        return "not_configured_demo_no_otp_in_response"

    message = EmailMessage()
    message["Subject"] = f"SecureDoc OTP for {purpose}"
    message["From"] = SMTP_FROM_EMAIL
    message["To"] = email
    message.set_content(
        "Your SecureDoc one-time password is valid for 10 minutes.\n\n"
        f"OTP: {otp}\n\n"
        "Do not share this code."
    )

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
            if SMTP_USE_TLS:
                smtp.starttls()
            if SMTP_USERNAME:
                smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
            smtp.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        raise HTTPException(status_code=502, detail="OTP email delivery failed") from exc

    return "smtp_sent"


def _actor_email(actor: dict[str, str]) -> str:
    return actor["user"].strip().lower()


@router.post("/email-otp/request", include_in_schema=False)
def request_email_otp(
    body: EmailOtpRequest,
    db: Session = Depends(get_db),
    actor: dict[str, str] = Depends(require_roles(SIGNER)),
):
    if body.purpose.strip().upper() == "SIGNING_CONFIRMATION":
        raise HTTPException(status_code=400, detail="Use signing request confirmation OTP endpoint")
    if body.email.strip().lower() != _actor_email(actor):
        raise HTTPException(status_code=403, detail="Generic OTP is limited to the authenticated account")
    try:
        token, otp = create_email_otp(db, body.email, body.purpose)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    delivery = _send_otp_email(token.email, token.purpose, otp)
    db.commit()
    return {
        "otpId": token.id,
        "email": token.email,
        "purpose": token.purpose,
        "expiresAt": token.expires_at.isoformat(),
        "delivery": delivery,
        "warning": "Demo account-only OTP. Not used for signing confirmation and not returned by this API.",
    }


@router.post("/email-otp/verify", include_in_schema=False)
def verify_email_otp_route(
    body: EmailOtpVerifyRequest,
    db: Session = Depends(get_db),
    actor: dict[str, str] = Depends(require_roles(SIGNER)),
):
    if body.purpose.strip().upper() == "SIGNING_CONFIRMATION":
        raise HTTPException(status_code=400, detail="Use signing request confirmation endpoint")
    if body.email.strip().lower() != _actor_email(actor):
        raise HTTPException(status_code=403, detail="Generic OTP is limited to the authenticated account")
    try:
        ok, message = verify_email_otp(db, body.email, body.purpose, body.otp)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.commit()
    return {"verified": ok, "reason": message}


@router.post("/totp/setup")
def setup_totp(
    db: Session = Depends(get_db),
    actor: dict[str, str] = Depends(require_roles(SIGNER)),
):
    try:
        setting, secret, uri = create_totp_setting(db, _actor_email(actor))
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    db.commit()
    return {
        "mfaId": setting.id,
        "email": setting.email,
        "type": "TOTP",
        "enabled": False,
        "secret": secret,
        "otpauthUri": uri,
        "warning": f"Show this secret/QR only during setup. {totp_storage_warning()}",
    }


@router.post("/totp/verify-setup")
def verify_totp_setup_route(
    body: TotpVerifySetupRequest,
    db: Session = Depends(get_db),
    actor: dict[str, str] = Depends(require_roles(SIGNER)),
):
    ok, message = verify_totp_setup(db, _actor_email(actor), body.code)
    db.commit()
    return {"verified": ok, "reason": message}
