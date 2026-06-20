"""Audit log helpers shared by auth and v2 service routes."""

import secrets
from datetime import timezone
from typing import Any

from sqlalchemy.orm import Session

from .crypto_utils import build_audit_event_json, compute_audit_hash, isoformat, utc_now
from .models import AuditLog


def log_audit(
    db: Session,
    event_type: str,
    actor: str | None,
    result: str,
    details: str | None = None,
    document_hash: str | None = None,
    certificate_serial: str | None = None,
) -> None:
    now = utc_now()
    event_id = secrets.token_hex(16)
    last = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    previous_hash = last.current_log_hash if last else None
    event_json = build_audit_event_json(event_id, event_type, actor, result, details, isoformat(now))
    db.add(
        AuditLog(
            event_id=event_id,
            event_type=event_type,
            actor=actor,
            document_hash=document_hash,
            certificate_serial=certificate_serial,
            result=result,
            details=details,
            created_at=now.replace(tzinfo=None),
            previous_log_hash=previous_hash,
            current_log_hash=compute_audit_hash(event_json, previous_hash),
        )
    )
    db.flush()


def audit_log_to_response(event: AuditLog) -> dict[str, Any]:
    created_at = event.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    return {
        "id": event.id,
        "eventId": event.event_id,
        "eventType": event.event_type,
        "actor": event.actor,
        "documentHash": event.document_hash,
        "certificateSerial": event.certificate_serial,
        "result": event.result,
        "details": event.details,
        "createdAt": isoformat(created_at),
        "previousLogHash": event.previous_log_hash,
        "currentLogHash": event.current_log_hash,
    }
