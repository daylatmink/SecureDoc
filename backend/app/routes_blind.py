"""Blind signature API routes.

The signer only receives and signs blinded messages in the main blind flow.
Raw token data and blinding factors are exposed only to the requester/demo UI.
"""

from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .blind_signature import (
    ALLOWED_BLIND_PURPOSES,
    BLIND_SIGNATURE_SCHEME,
    blind_token,
    create_token,
    public_key_response,
    sign_blinded_message,
    token_hash_hex,
    unblind_signature,
    verify_final_signature,
)
from .crypto_utils import isoformat, parse_iso_datetime, utc_now
from .database import SessionLocal
from .models import BlindSignatureSession

router = APIRouter(prefix="/api/blind-signature", tags=["blind-signature"])

BlindPurpose = Literal["anonymous_access_token", "e_voting_demo", "e_cash_demo"]


class BlindSessionCreateRequest(BaseModel):
    purpose: BlindPurpose = "anonymous_access_token"
    ttlSeconds: int = Field(default=600, ge=-3600, le=86400)


class BlindSignRequest(BaseModel):
    sessionId: str
    blindedMessageBase64: str


class BlindVerifyRequest(BaseModel):
    sessionId: str
    token: dict[str, Any]
    finalSignatureBase64: str


class BlindRedeemRequest(BaseModel):
    sessionId: str
    token: dict[str, Any]
    finalSignatureBase64: str


class BlindDemoRequest(BaseModel):
    message: str
    purpose: BlindPurpose = "anonymous_access_token"


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _db_time(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def _is_expired(session: BlindSignatureSession) -> bool:
    return _db_time(utc_now()) > session.expires_at


def _session_response(session: BlindSignatureSession, include_demo_secrets: bool = False) -> dict[str, Any]:
    data = {
        "sessionId": session.session_id,
        "tokenId": session.token_id,
        "purpose": session.purpose,
        "token": session.token_json_as_dict,
        "tokenHash": session.token_hash,
        "blindedMessageBase64": session.blinded_message_base64,
        "blindSignatureBase64": session.blind_signature_base64,
        "finalSignatureBase64": session.final_signature_base64,
        "status": session.status,
        "createdAt": isoformat(session.created_at.replace(tzinfo=timezone.utc)),
        "expiresAt": isoformat(session.expires_at.replace(tzinfo=timezone.utc)),
        "spentAt": isoformat(session.spent_at.replace(tzinfo=timezone.utc)) if session.spent_at else None,
        "scheme": BLIND_SIGNATURE_SCHEME,
        "publicKey": public_key_response(),
        "warnings": [
            "Educational demo only.",
            "Signer signs blindedMessage only, not the raw token.",
            "Do not log raw token contents or blinding factors in a production-like blind signature flow.",
        ],
    }
    if include_demo_secrets:
        data["demoWarning"] = "Demo reveals blindingFactorBase64 so the browser can show unblind step. Do not expose this in production."
        data["blindingFactorBase64"] = getattr(session, "_demo_blinding_factor_base64", None)
    return data


def _load_session(db: Session, session_id: str) -> BlindSignatureSession:
    session = db.get(BlindSignatureSession, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Blind signature session not found")
    return session


def _token_matches_session(session: BlindSignatureSession, token: dict[str, Any]) -> bool:
    return (
        token.get("tokenId") == session.token_id
        and token.get("purpose") == session.purpose
        and token_hash_hex(token) == session.token_hash
    )


@router.post("/sessions")
def create_blind_session(body: BlindSessionCreateRequest, db: Session = Depends(get_db)):
    if body.purpose not in ALLOWED_BLIND_PURPOSES:
        raise HTTPException(status_code=400, detail="Invalid blind signature purpose")
    token = create_token(body.purpose, body.ttlSeconds)
    blinded = blind_token(token)
    session = BlindSignatureSession(
        session_id=token["tokenId"],
        token_id=token["tokenId"],
        purpose=body.purpose,
        token_json=BlindSignatureSession.dumps_token(token),
        token_hash=blinded["tokenHash"],
        blinded_message_base64=blinded["blindedMessageBase64"],
        status="created",
        created_at=_db_time(parse_iso_datetime(token["createdAt"])),
        expires_at=_db_time(parse_iso_datetime(token["expiresAt"])),
    )
    session._demo_blinding_factor_base64 = blinded["blindingFactorBase64"]
    db.add(session)
    db.commit()
    return _session_response(session, include_demo_secrets=True)


@router.get("/sessions/{sessionId}")
def get_blind_session(sessionId: str, db: Session = Depends(get_db)):
    session = _load_session(db, sessionId)
    return _session_response(session)


@router.post("/sign")
def sign_blinded_token(body: BlindSignRequest, db: Session = Depends(get_db)):
    session = _load_session(db, body.sessionId)
    if _is_expired(session):
        session.status = "expired"
        db.commit()
        raise HTTPException(status_code=400, detail="Blind signature session expired")
    if body.blindedMessageBase64 != session.blinded_message_base64:
        raise HTTPException(status_code=400, detail="Blinded message does not match session")

    blind_signature = sign_blinded_message(body.blindedMessageBase64)
    session.blind_signature_base64 = blind_signature
    session.status = "blind_signed"
    db.commit()
    return {
        "sessionId": session.session_id,
        "blindSignatureBase64": blind_signature,
        "scheme": BLIND_SIGNATURE_SCHEME,
        "warning": "Signer signed blindedMessage only and did not receive the raw token.",
    }


@router.post("/verify")
def verify_blind_signature(body: BlindVerifyRequest, db: Session = Depends(get_db)):
    session = _load_session(db, body.sessionId)
    if not _token_matches_session(session, body.token):
        return {
            "valid": False,
            "reason": "token does not match session",
            "sessionId": session.session_id,
            "tokenId": session.token_id,
        }
    if _is_expired(session):
        session.status = "expired"
        db.commit()
        return {
            "valid": False,
            "reason": "token expired",
            "sessionId": session.session_id,
            "tokenId": session.token_id,
        }
    valid = verify_final_signature(body.token, body.finalSignatureBase64)
    if valid:
        session.final_signature_base64 = body.finalSignatureBase64
        if session.status != "spent":
            session.status = "verified"
        db.commit()
    return {
        "valid": valid,
        "reason": "blind signature valid" if valid else "invalid final signature",
        "sessionId": session.session_id,
        "tokenId": session.token_id,
        "purpose": session.purpose,
    }


@router.post("/redeem")
def redeem_blind_token(body: BlindRedeemRequest, db: Session = Depends(get_db)):
    session = _load_session(db, body.sessionId)
    if session.status == "spent" or session.spent_at is not None:
        return {
            "redeemed": False,
            "reason": "token already spent",
            "sessionId": session.session_id,
            "tokenId": session.token_id,
            "status": "spent",
        }
    if not _token_matches_session(session, body.token):
        return {
            "redeemed": False,
            "reason": "token does not match session",
            "sessionId": session.session_id,
            "tokenId": session.token_id,
            "status": session.status,
        }
    if _is_expired(session):
        session.status = "expired"
        db.commit()
        return {
            "redeemed": False,
            "reason": "token expired",
            "sessionId": session.session_id,
            "tokenId": session.token_id,
            "status": "expired",
        }
    if not verify_final_signature(body.token, body.finalSignatureBase64):
        return {
            "redeemed": False,
            "reason": "invalid final signature",
            "sessionId": session.session_id,
            "tokenId": session.token_id,
            "status": session.status,
        }

    now = utc_now()
    session.final_signature_base64 = body.finalSignatureBase64
    session.status = "spent"
    session.spent_at = _db_time(now)
    db.commit()
    return {
        "redeemed": True,
        "reason": "redeem success",
        "sessionId": session.session_id,
        "tokenId": session.token_id,
        "status": "spent",
        "spentAt": isoformat(now),
    }


@router.post("/demo")
def legacy_blind_demo(body: BlindDemoRequest, db: Session = Depends(get_db)):
    session_response = create_blind_session(
        BlindSessionCreateRequest(purpose=body.purpose, ttlSeconds=600),
        db,
    )
    sign_response = sign_blinded_token(
        BlindSignRequest(
            sessionId=session_response["sessionId"],
            blindedMessageBase64=session_response["blindedMessageBase64"],
        ),
        db,
    )
    final_signature = unblind_signature(
        sign_response["blindSignatureBase64"],
        session_response["blindingFactorBase64"],
    )
    verify_response = verify_blind_signature(
        BlindVerifyRequest(
            sessionId=session_response["sessionId"],
            token=session_response["token"],
            finalSignatureBase64=final_signature,
        ),
        db,
    )
    return {
        "scheme": BLIND_SIGNATURE_SCHEME,
        "message": body.message,
        "session": session_response,
        "blindSignatureBase64": sign_response["blindSignatureBase64"],
        "unblindedSignatureBase64": final_signature,
        "valid": verify_response["valid"],
        "warning": "Legacy demo echoes token/blinding data for education. Do not expose this in production.",
    }
