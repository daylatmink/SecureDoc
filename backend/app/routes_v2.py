"""V2 client-side signing protocol endpoints."""

import base64
import hashlib
import hmac
import asyncio
import io
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from .auth_utils import create_signing_email_otp, verify_enabled_totp_for_email, verify_signing_email_otp
from .config import JWT_SECRET, RFC3161_TSA_URL, ensure_document_storage_dir
from .crypto_utils import (
    ALGORITHM_POLICY,
    ALLOWED_SIGNING_PURPOSES,
    HASH_ALGORITHM_PROFILES,
    ISSUER,
    build_audit_event_json,
    canonicalize_signing_payload,
    check_algorithm_policy,
    compute_audit_hash,
    compute_certificate_fingerprint,
    get_public_key_size,
    hash_bytes,
    isoformat,
    normalize_hash_algorithm,
    parse_iso_datetime,
    utc_now,
    verify_canonical_signature,
    verify_certificate_signature,
)
from .database import SessionLocal
from .models import (
    AuditLog,
    CertificateRecord,
    CertificateRevocation,
    DocumentObject,
    SignatureRecord,
    SigningRequest,
    UsedNonce,
)
from .pades_utils import sign_pdf_pades as sign_pdf_pades_bytes
from .schemas import (
    Certificate,
    DocumentMarkSignedResponse,
    DocumentStoredResponse,
    Rfc3161TimestampRequest,
    Rfc3161TimestampResponse,
    RevokeBySerialRequest,
    SignedPackageV2,
    SigningConfirmRequest,
    SigningConfirmResponse,
    SigningOtpRequestResponse,
    SigningPayloadV2,
    SigningRequestCreateV2,
    SigningRequestResponseV2,
    X509CertificateIssueRequest,
    X509CertificateIssueResponse,
    X509ProofChallengeRequest,
    X509ProofChallengeResponse,
)
from .routes_auth import _send_otp_email
from .security import ADMIN, AUDITOR, CA_OFFICER, SIGNER, VERIFIER, require_roles
from .x509_utils import (
    TRUSTED_DEMO_ROOT_ID,
    X509_CERTIFICATE_TYPE,
    build_signed_demo_crl,
    ensure_demo_x509_ca,
    issue_user_x509_certificate,
    issue_timestamp_token,
    parse_user_x509_details,
    verify_demo_x509_chain,
    verify_signed_demo_crl,
    verify_timestamp_token,
)

router = APIRouter()

CANONICALIZATION_METHOD = "JSON-canonical-sorted-keys"
CONFIRMED_SIGNING_REQUEST_STATUSES = {"mfa_confirmed", "completed"}


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _db_time(dt: datetime) -> datetime:
    return _as_utc(dt).replace(tzinfo=None)


def _db_iso(dt: datetime) -> str:
    return isoformat(_as_utc(dt))


def _safe_original_filename(filename: str | None) -> str:
    candidate = (filename or "document.bin").strip()
    if not candidate or candidate in {".", ".."}:
        raise HTTPException(status_code=400, detail="Invalid filename")
    if "/" in candidate or "\\" in candidate or Path(candidate).name != candidate or ".." in Path(candidate).parts:
        raise HTTPException(status_code=400, detail="Path traversal filenames are not allowed")
    return candidate


def _sniff_mime(content: bytes) -> str:
    if content.startswith(b"%PDF-"):
        return "application/pdf"
    if b"\x00" in content:
        return "application/octet-stream"
    try:
        content.decode("utf-8")
    except UnicodeDecodeError:
        return "application/octet-stream"
    return "text/plain"


def _validate_document_upload(filename: str, content_type: str | None, content: bytes) -> str:
    if not content:
        raise HTTPException(status_code=400, detail="Document is empty")
    sniffed = _sniff_mime(content)
    declared = (content_type or "").split(";", 1)[0].strip().lower()
    if filename.lower().endswith(".pdf") and sniffed != "application/pdf":
        raise HTTPException(status_code=400, detail="PDF filename does not contain PDF content")
    if declared == "application/pdf" and sniffed != "application/pdf":
        raise HTTPException(status_code=400, detail="Declared PDF MIME does not match content")
    return sniffed if declared in {"", "application/octet-stream"} else declared


def _document_storage_path(content_hash: str) -> Path:
    storage_dir = ensure_document_storage_dir()
    path = storage_dir / content_hash[:2] / f"{content_hash}.bin"
    resolved_storage = storage_dir.resolve()
    resolved_path = path.resolve()
    if resolved_storage not in resolved_path.parents:
        raise HTTPException(status_code=400, detail="Invalid document storage path")
    return path


def _document_to_response(record: DocumentObject) -> dict[str, Any]:
    return {
        "documentId": record.document_id,
        "ownerEmail": record.owner_email,
        "originalFilename": record.original_filename,
        "contentHash": record.content_hash,
        "hashAlgorithm": record.hash_algorithm,
        "mimeType": record.mime_type,
        "sizeBytes": record.size_bytes,
        "version": record.version,
        "previousDocumentId": record.previous_document_id,
        "immutable": bool(record.immutable),
        "createdAt": _db_iso(record.created_at),
        "updatedAt": _db_iso(record.updated_at),
    }


def _require_document_access(record: DocumentObject, actor: dict[str, str]) -> None:
    if actor["role"] == ADMIN:
        return
    if record.owner_email.strip().lower() != _actor_email(actor):
        raise HTTPException(status_code=403, detail="Document access denied")


def _persist_document_content(content: bytes) -> tuple[str, Path]:
    content_hash = hash_bytes(content, "SHA-256")
    path = _document_storage_path(content_hash)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_bytes(content)
    return content_hash, path


async def _read_document_upload(file: UploadFile) -> tuple[str, bytes, str]:
    filename = _safe_original_filename(file.filename)
    content = await file.read()
    mime_type = _validate_document_upload(filename, file.content_type, content)
    return filename, content, mime_type


def _log_audit(
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
            created_at=_db_time(now),
            previous_log_hash=previous_hash,
            current_log_hash=compute_audit_hash(event_json, previous_hash),
        )
    )
    db.flush()


def _step(steps: list[dict[str, str]], name: str, status: str, message: str) -> None:
    steps.append({"step": name, "status": status, "message": message})


def _record_certificate_payload(record: CertificateRecord) -> dict[str, Any]:
    payload = {
        "serialNumber": record.serial_number,
        "ownerName": record.owner_name,
        "email": record.email,
        "publicKeyPem": record.public_key_pem,
        "issuer": record.issuer,
        "issuedAt": _db_iso(record.issued_at),
        "expiresAt": _db_iso(record.expires_at),
        "status": record.status,
        "certificateType": record.certificate_type or "legacy-demo",
    }
    if (record.certificate_type or "legacy-demo") == X509_CERTIFICATE_TYPE:
        payload.update(
            {
                "certificateFingerprint": record.fingerprint_sha256,
                "userCertificatePem": record.user_certificate_pem,
                "intermediateCertificatePem": record.intermediate_certificate_pem,
                "rootCertificatePem": record.root_certificate_pem,
            }
        )
    return payload


def _record_fingerprint(record: CertificateRecord) -> str:
    if (record.certificate_type or "legacy-demo") == X509_CERTIFICATE_TYPE and record.fingerprint_sha256:
        return record.fingerprint_sha256
    return compute_certificate_fingerprint(_record_certificate_payload(record))


def _certificate_type(cert: Certificate | None, record: CertificateRecord | None = None) -> str:
    if cert and cert.certificateType:
        return cert.certificateType
    if record and record.certificate_type:
        return record.certificate_type
    return "legacy-demo"


def _root_pem_from_package(body: SignedPackageV2) -> str | None:
    if body.rootCertificatePem:
        return body.rootCertificatePem
    if body.trustedRootId == TRUSTED_DEMO_ROOT_ID:
        _, root_pem = ensure_demo_x509_ca()
        return root_pem
    return None


def _certificate_from_package(body: SignedPackageV2) -> Certificate:
    if body.signerCertificate:
        cert = body.signerCertificate.model_copy(deep=True)
        if body.userCertificatePem:
            cert.userCertificatePem = body.userCertificatePem
        if body.intermediateCertificatePem:
            cert.intermediateCertificatePem = body.intermediateCertificatePem
        root_pem = _root_pem_from_package(body)
        if root_pem:
            cert.rootCertificatePem = root_pem
        return cert

    if not body.userCertificatePem or not body.intermediateCertificatePem:
        raise ValueError("X.509 signed package requires userCertificatePem and intermediateCertificatePem")
    root_pem = _root_pem_from_package(body)
    if not root_pem:
        raise ValueError("X.509 signed package requires rootCertificatePem or trustedRootId")

    details = parse_user_x509_details(body.userCertificatePem)
    return Certificate(
        serialNumber=details.serial_number,
        ownerName=details.owner_name,
        email=details.email,
        publicKeyPem=details.public_key_pem,
        issuer=details.issuer,
        issuedAt=isoformat(details.issued_at),
        expiresAt=isoformat(details.expires_at),
        status="valid",
        certificateType=X509_CERTIFICATE_TYPE,
        certificateFingerprint=details.fingerprint_sha256,
        userCertificatePem=body.userCertificatePem,
        intermediateCertificatePem=body.intermediateCertificatePem,
        rootCertificatePem=root_pem,
    )


def _certificate_fingerprint(cert: Certificate) -> str:
    if cert.certificateType == X509_CERTIFICATE_TYPE:
        details = parse_user_x509_details(cert.userCertificatePem or "")
        return details.fingerprint_sha256
    return compute_certificate_fingerprint(cert.model_dump())


def _x509_pems(cert: Certificate) -> tuple[str, str, str]:
    if not cert.userCertificatePem or not cert.intermediateCertificatePem or not cert.rootCertificatePem:
        raise ValueError("X.509 certificate chain PEMs are required")
    return cert.userCertificatePem, cert.intermediateCertificatePem, cert.rootCertificatePem


def _verify_certificate_trust(cert: Certificate) -> tuple[bool, str]:
    if cert.certificateType == X509_CERTIFICATE_TYPE:
        try:
            return verify_demo_x509_chain(*_x509_pems(cert))
        except ValueError as exc:
            return False, str(exc)
    if verify_certificate_signature(cert.model_dump()):
        return True, "Certificate is signed by SecureDoc legacy-demo CA."
    return False, "Certificate is not signed by SecureDoc Demo CA."


def _certificate_matches_record(cert: Certificate, record: CertificateRecord) -> bool:
    certificate_type = _certificate_type(cert, record)
    if certificate_type != (record.certificate_type or "legacy-demo"):
        return False
    if cert.serialNumber != record.serial_number:
        return False
    if cert.ownerName != record.owner_name or cert.email != record.email:
        return False
    if cert.publicKeyPem != record.public_key_pem or cert.issuer != record.issuer:
        return False
    if certificate_type == X509_CERTIFICATE_TYPE:
        try:
            details = parse_user_x509_details(cert.userCertificatePem or "")
            issued = _db_time(parse_iso_datetime(cert.issuedAt))
            expires = _db_time(parse_iso_datetime(cert.expiresAt))
        except ValueError:
            return False
        return (
            details.serial_number == record.serial_number
            and details.owner_name == record.owner_name
            and details.email == record.email
            and details.public_key_pem == record.public_key_pem
            and details.issuer == record.issuer
            and details.fingerprint_sha256 == record.fingerprint_sha256
            and cert.certificateFingerprint == record.fingerprint_sha256
            and cert.userCertificatePem == record.user_certificate_pem
            and cert.intermediateCertificatePem == record.intermediate_certificate_pem
            and cert.rootCertificatePem == record.root_certificate_pem
            and issued == record.issued_at
            and expires == record.expires_at
        )
    try:
        issued = _db_time(parse_iso_datetime(cert.issuedAt))
        expires = _db_time(parse_iso_datetime(cert.expiresAt))
    except ValueError:
        return False
    return issued == record.issued_at and expires == record.expires_at


def _latest_revocation(db: Session, serial_number: str) -> CertificateRevocation | None:
    return (
        db.query(CertificateRevocation)
        .filter_by(serial_number=serial_number)
        .order_by(CertificateRevocation.id.desc())
        .first()
    )


def _hash_hex_valid(document_hash: str, hash_algorithm: str) -> bool:
    digest_bits = HASH_ALGORITHM_PROFILES[hash_algorithm]["digestBits"]
    expected_len = digest_bits // 4
    if len(document_hash) != expected_len:
        return False
    return all(ch in "0123456789abcdefABCDEF" for ch in document_hash)


def _base_report(steps: list[dict[str, str]], warnings: list[str], decision: str = "invalid") -> dict[str, Any]:
    return {
        "cryptoValid": False,
        "documentHashValid": False,
        "trustedChainValid": False,
        "revocationValid": False,
        "timestampValid": False,
        "serverAccepted": False,
        "signingRequestConfirmed": False,
        "confirmationMethod": None,
        "legalReady": False,
        "documentIntegrity": "not_checked",
        "signingPayloadValid": "not_checked",
        "signatureValid": "not_checked",
        "certificateParsed": "not_checked",
        "certificateTrusted": "not_checked",
        "certificateType": "legacy-demo",
        "certificateChainValid": "not_available",
        "certificateValidityPeriod": "not_checked",
        "certificateRevocationStatus": "not_checked",
        "revocationSource": "not_checked",
        "keyUsageValid": "not_available",
        "algorithmPolicyValid": "not_checked",
        "replayCheck": "not_checked",
        "timestampStatus": "not_checked",
        "finalDecision": decision,
        "warnings": warnings,
        "errors": [],
        "verificationSteps": steps,
    }


def _signer(payload: SigningPayloadV2 | None, cert: Certificate | None) -> dict[str, str] | None:
    if not payload or not cert:
        return None
    return {
        "name": payload.signerName,
        "email": payload.signerEmail,
        "serialNumber": cert.serialNumber,
    }


def _verification_response(
    valid: bool,
    reason: str,
    report: dict[str, Any],
    document_hash: str,
    payload: SigningPayloadV2 | None = None,
    cert: Certificate | None = None,
    signed_at: str | None = None,
) -> dict[str, Any]:
    return {
        "valid": valid,
        "reason": reason,
        "signer": _signer(payload, cert),
        "documentHash": document_hash,
        "signedAt": signed_at,
        "report": report,
    }


def _signature_message_imprint(signature_base64: str) -> str:
    try:
        signature_bytes = base64.b64decode(signature_base64)
    except (ValueError, TypeError):
        signature_bytes = signature_base64.encode("utf-8")
    return hash_bytes(signature_bytes, "SHA-256")


def _trusted_timestamp_time(
    timestamp_token: dict[str, Any] | None,
    signature_base64: str,
    expected_nonce: str | None = None,
) -> tuple[datetime | None, str, str]:
    if not timestamp_token:
        return None, "not_available", "No trusted timestamp token is present."
    timestamp_ok, timestamp_message = verify_timestamp_token(
        timestamp_token,
        _signature_message_imprint(signature_base64),
        expected_nonce,
    )
    if not timestamp_ok:
        return None, "failed", timestamp_message
    try:
        return parse_iso_datetime(str(timestamp_token["timestamp"])), "demo-tsa-valid", timestamp_message
    except (KeyError, ValueError, TypeError) as exc:
        return None, "failed", f"Malformed timestamp token time: {exc}"


def _reject_submit(
    db: Session,
    message: str,
    payload: SigningPayloadV2 | None = None,
    cert: Certificate | None = None,
) -> None:
    _log_audit(
        db,
        "signature_submitted",
        payload.signerEmail if payload else None,
        "failed",
        details=message,
        document_hash=payload.documentHash if payload else None,
        certificate_serial=cert.serialNumber if cert else None,
    )
    db.commit()
    raise HTTPException(status_code=400, detail=message)


def _actor_email(actor: dict[str, str]) -> str:
    return actor["user"].strip().lower()


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _public_key_fingerprint(public_key_pem: str) -> str:
    return hash_bytes(public_key_pem.strip().encode("utf-8"), "SHA-256")


def _subject_for_actor(body: X509ProofChallengeRequest | X509CertificateIssueRequest, actor: dict[str, str]) -> tuple[str, str]:
    subject_name = body.name.strip()
    subject_email = body.email.strip().lower()
    if not subject_name:
        raise HTTPException(status_code=400, detail="name is required")
    if actor["role"] == SIGNER and subject_email != _actor_email(actor):
        raise HTTPException(status_code=403, detail="Certificate subject email must match authenticated signer")
    return subject_name, subject_email


def _challenge_signature(payload_b64: str) -> str:
    digest = hmac.new(JWT_SECRET.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256).digest()
    return _b64url_encode(digest)


def _make_pop_challenge(subject_name: str, subject_email: str, public_key_pem: str, actor: dict[str, str]) -> tuple[str, datetime]:
    now = utc_now()
    expires_at = now + timedelta(minutes=10)
    payload = {
        "purpose": "X509_CERTIFICATE_PROOF_OF_POSSESSION",
        "subjectName": subject_name,
        "subjectEmail": subject_email,
        "publicKeyFingerprint": _public_key_fingerprint(public_key_pem),
        "actor": _actor_email(actor),
        "actorRole": actor["role"],
        "issuedAt": isoformat(now),
        "expiresAt": isoformat(expires_at),
        "nonce": secrets.token_hex(16),
    }
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload_b64 = _b64url_encode(payload_bytes)
    return f"{payload_b64}.{_challenge_signature(payload_b64)}", expires_at


def _verify_pop_challenge(challenge: str, subject_name: str, subject_email: str, public_key_pem: str) -> None:
    payload_b64, separator, signature = challenge.partition(".")
    if not separator or not payload_b64 or not signature:
        raise HTTPException(status_code=400, detail="Malformed proof challenge")
    expected_signature = _challenge_signature(payload_b64)
    if not hmac.compare_digest(expected_signature, signature):
        raise HTTPException(status_code=400, detail="Invalid proof challenge")
    try:
        payload = json.loads(_b64url_decode(payload_b64))
        expires_at = parse_iso_datetime(str(payload["expiresAt"]))
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Malformed proof challenge") from exc
    if payload.get("purpose") != "X509_CERTIFICATE_PROOF_OF_POSSESSION":
        raise HTTPException(status_code=400, detail="Invalid proof challenge purpose")
    if expires_at <= utc_now():
        raise HTTPException(status_code=400, detail="Proof challenge expired")
    if payload.get("subjectName") != subject_name or payload.get("subjectEmail") != subject_email:
        raise HTTPException(status_code=400, detail="Proof challenge subject mismatch")
    if payload.get("publicKeyFingerprint") != _public_key_fingerprint(public_key_pem):
        raise HTTPException(status_code=400, detail="Proof challenge public key mismatch")


def _verify_proof_of_possession(public_key_pem: str, challenge: str, proof_signature_base64: str) -> None:
    if not verify_canonical_signature(challenge.encode("utf-8"), proof_signature_base64, public_key_pem, "SHA-256"):
        raise HTTPException(status_code=400, detail="Proof-of-possession signature is invalid")


def _require_signing_request_owner(request: SigningRequest, actor: dict[str, str]) -> None:
    if _actor_email(actor) != request.signer_email.strip().lower():
        raise HTTPException(status_code=403, detail="Authenticated signer does not own this signing request")


def _request_context_matches_payload(request: SigningRequest, payload: SigningPayloadV2, hash_algorithm: str) -> bool:
    expected = {
        "document_name": payload.documentName,
        "document_hash": payload.documentHash.lower(),
        "hash_algorithm": hash_algorithm,
        "signer_name": payload.signerName,
        "signer_email": payload.signerEmail,
        "certificate_serial": payload.certificateSerialNumber,
        "signing_purpose": payload.signingPurpose,
        "nonce": payload.nonce,
    }
    return all(getattr(request, attr) == expected_value for attr, expected_value in expected.items())


def _confirmation_state(
    db: Session,
    payload: SigningPayloadV2,
    hash_algorithm: str,
) -> tuple[SigningRequest | None, bool, str | None, bool]:
    request = db.get(SigningRequest, payload.requestId)
    if not request:
        return None, False, None, False
    context_matches = _request_context_matches_payload(request, payload, hash_algorithm)
    confirmed = context_matches and request.status in CONFIRMED_SIGNING_REQUEST_STATUSES
    return request, confirmed, request.confirmation_method, context_matches


@router.post("/api/certificates/x509/proof-challenge", response_model=X509ProofChallengeResponse)
def create_x509_proof_challenge(
    body: X509ProofChallengeRequest,
    actor: dict[str, str] = Depends(require_roles(CA_OFFICER, SIGNER)),
):
    subject_name, subject_email = _subject_for_actor(body, actor)
    try:
        key_size = get_public_key_size(body.publicKeyPem)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid public key PEM") from exc
    if key_size < ALGORITHM_POLICY["minimumRsaKeyBits"]:
        raise HTTPException(status_code=400, detail="RSA key size is below policy minimum")

    challenge, expires_at = _make_pop_challenge(subject_name, subject_email, body.publicKeyPem, actor)
    return {
        "challenge": challenge,
        "expiresAt": isoformat(expires_at),
        "subjectName": subject_name,
        "subjectEmail": subject_email,
        "publicKeyFingerprint": _public_key_fingerprint(body.publicKeyPem),
        "warning": "Sign this challenge with the private key matching publicKeyPem before certificate issuance.",
    }


@router.post("/api/certificates/x509/issue", response_model=X509CertificateIssueResponse)
def issue_x509_certificate(
    body: X509CertificateIssueRequest,
    db: Session = Depends(get_db),
    actor: dict[str, str] = Depends(require_roles(CA_OFFICER, SIGNER)),
):
    subject_name, subject_email = _subject_for_actor(body, actor)
    _verify_pop_challenge(body.proofChallenge, subject_name, subject_email, body.publicKeyPem)
    _verify_proof_of_possession(body.publicKeyPem, body.proofChallenge, body.proofSignatureBase64)
    try:
        issued = issue_user_x509_certificate(subject_name, subject_email, body.publicKeyPem)
        certificate = issued["certificate"]
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    record = CertificateRecord(
        serial_number=certificate["serialNumber"],
        owner_name=certificate["ownerName"],
        email=certificate["email"],
        public_key_pem=certificate["publicKeyPem"],
        issuer=certificate["issuer"],
        issued_at=_db_time(parse_iso_datetime(certificate["issuedAt"])),
        expires_at=_db_time(parse_iso_datetime(certificate["expiresAt"])),
        status=certificate["status"],
        certificate_type=X509_CERTIFICATE_TYPE,
        fingerprint_sha256=certificate["certificateFingerprint"],
        key_size_bits=get_public_key_size(certificate["publicKeyPem"]),
        user_certificate_pem=certificate["userCertificatePem"],
        intermediate_certificate_pem=certificate["intermediateCertificatePem"],
        root_certificate_pem=certificate["rootCertificatePem"],
    )
    db.add(record)
    _log_audit(
        db,
        "certificate_issued",
        certificate["email"],
        "success",
        details="x509-demo certificate issued after proof-of-possession verification",
        certificate_serial=certificate["serialNumber"],
    )
    db.commit()
    return issued


@router.post("/api/documents/store", response_model=DocumentStoredResponse)
async def store_document(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    actor: dict[str, str] = Depends(require_roles(SIGNER)),
):
    filename, content, mime_type = await _read_document_upload(file)
    content_hash, path = _persist_document_content(content)
    now = utc_now()
    record = DocumentObject(
        document_id=secrets.token_hex(16),
        owner_email=_actor_email(actor),
        original_filename=filename,
        content_hash=content_hash,
        hash_algorithm="SHA-256",
        mime_type=mime_type,
        storage_path=str(path),
        size_bytes=len(content),
        version=1,
        previous_document_id=None,
        immutable=0,
        created_at=_db_time(now),
        updated_at=_db_time(now),
    )
    db.add(record)
    _log_audit(
        db,
        "document_stored",
        _actor_email(actor),
        "success",
        details=f"documentId={record.document_id}; mimeType={mime_type}; sizeBytes={len(content)}",
        document_hash=content_hash,
    )
    db.commit()
    return _document_to_response(record)


@router.get("/api/documents/{document_id}", response_model=DocumentStoredResponse)
def get_document_metadata(
    document_id: str,
    db: Session = Depends(get_db),
    actor: dict[str, str] = Depends(require_roles(SIGNER, VERIFIER, AUDITOR)),
):
    record = db.get(DocumentObject, document_id)
    if not record:
        raise HTTPException(status_code=404, detail="Document not found")
    _require_document_access(record, actor)
    return _document_to_response(record)


@router.put("/api/documents/{document_id}/content", response_model=DocumentStoredResponse)
async def update_document_content(
    document_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    actor: dict[str, str] = Depends(require_roles(SIGNER)),
):
    record = db.get(DocumentObject, document_id)
    if not record:
        raise HTTPException(status_code=404, detail="Document not found")
    _require_document_access(record, actor)
    filename, content, mime_type = await _read_document_upload(file)
    content_hash, path = _persist_document_content(content)
    now = utc_now()
    if record.immutable:
        new_record = DocumentObject(
            document_id=secrets.token_hex(16),
            owner_email=record.owner_email,
            original_filename=filename,
            content_hash=content_hash,
            hash_algorithm="SHA-256",
            mime_type=mime_type,
            storage_path=str(path),
            size_bytes=len(content),
            version=record.version + 1,
            previous_document_id=record.document_id,
            immutable=0,
            created_at=_db_time(now),
            updated_at=_db_time(now),
        )
        db.add(new_record)
        _log_audit(
            db,
            "document_version_created",
            _actor_email(actor),
            "success",
            details=f"previousDocumentId={record.document_id}; documentId={new_record.document_id}",
            document_hash=content_hash,
        )
        db.commit()
        return _document_to_response(new_record)

    record.original_filename = filename
    record.content_hash = content_hash
    record.mime_type = mime_type
    record.storage_path = str(path)
    record.size_bytes = len(content)
    record.updated_at = _db_time(now)
    _log_audit(
        db,
        "document_updated",
        _actor_email(actor),
        "success",
        details=f"documentId={record.document_id}",
        document_hash=content_hash,
    )
    db.commit()
    return _document_to_response(record)


@router.post("/api/documents/{document_id}/mark-signed", response_model=DocumentMarkSignedResponse)
def mark_document_signed(
    document_id: str,
    db: Session = Depends(get_db),
    actor: dict[str, str] = Depends(require_roles(SIGNER)),
):
    record = db.get(DocumentObject, document_id)
    if not record:
        raise HTTPException(status_code=404, detail="Document not found")
    _require_document_access(record, actor)
    now = utc_now()
    record.immutable = 1
    record.updated_at = _db_time(now)
    _log_audit(
        db,
        "document_marked_signed",
        _actor_email(actor),
        "success",
        details=f"documentId={record.document_id}",
        document_hash=record.content_hash,
    )
    db.commit()
    return {"documentId": record.document_id, "immutable": True, "updatedAt": isoformat(now)}


@router.post("/api/sign/v2/prepare", response_model=SigningRequestResponseV2)
def prepare_signing_request(
    body: SigningRequestCreateV2,
    db: Session = Depends(get_db),
    actor: dict[str, str] = Depends(require_roles(SIGNER)),
):
    try:
        hash_algorithm = normalize_hash_algorithm(body.hashAlgorithm)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Unsupported hash algorithm") from exc

    ok, message = check_algorithm_policy(hash_algorithm, "RSA-PSS")
    if not ok:
        raise HTTPException(status_code=400, detail=message)
    if not _hash_hex_valid(body.documentHash, hash_algorithm):
        raise HTTPException(status_code=400, detail="documentHash does not match hashAlgorithm")
    if body.signingPurpose not in ALLOWED_SIGNING_PURPOSES:
        raise HTTPException(status_code=400, detail=f"Invalid signing purpose: {body.signingPurpose}")

    record = db.get(CertificateRecord, body.certificateSerialNumber)
    if not record:
        raise HTTPException(status_code=404, detail="Certificate not found")
    if record.email.strip().lower() != _actor_email(actor):
        raise HTTPException(status_code=403, detail="Authenticated signer does not own this certificate")
    if record.status != "valid":
        raise HTTPException(status_code=400, detail="Certificate is revoked")
    if _as_utc(record.expires_at) < utc_now():
        raise HTTPException(status_code=400, detail="Certificate has expired")

    fingerprint = _record_fingerprint(record)
    if not record.fingerprint_sha256:
        record.fingerprint_sha256 = fingerprint
    if not record.key_size_bits:
        record.key_size_bits = get_public_key_size(record.public_key_pem)

    warnings: list[str] = []
    if (record.certificate_type or "legacy-demo") == "legacy-demo":
        warnings.append("Certificate is a legacy-demo JSON certificate, not X.509.")
    else:
        warnings.append("X.509 certificate is issued by SecureDoc local demo CA, not a public CA.")
    warnings.append("SecureDoc Demo CA is local demo trust only.")

    now = utc_now()
    request_id = secrets.token_hex(16)
    nonce = secrets.token_hex(16)
    payload = SigningPayloadV2(
        documentName=body.documentName,
        documentHash=body.documentHash.lower(),
        hashAlgorithm=hash_algorithm,
        signatureAlgorithm="RSA-PSS",
        signerName=record.owner_name,
        signerEmail=record.email,
        certificateSerialNumber=record.serial_number,
        certificateFingerprint=fingerprint,
        certificateType=record.certificate_type or "legacy-demo",
        signingPurpose=body.signingPurpose,
        createdAt=isoformat(now),
        nonce=nonce,
        requestId=request_id,
        payloadVersion="1.0",
    )

    canonical = canonicalize_signing_payload(payload.model_dump())
    db.add(
        SigningRequest(
            request_id=request_id,
            document_name=body.documentName,
            document_hash=body.documentHash.lower(),
            hash_algorithm=hash_algorithm,
            signer_name=record.owner_name,
            signer_email=record.email,
            certificate_serial=record.serial_number,
            signing_purpose=body.signingPurpose,
            nonce=nonce,
            status="pending",
            created_at=_db_time(now),
        )
    )
    _log_audit(
        db,
        "signing_request_created",
        record.email,
        "success",
        details=f"requestId={request_id}",
        document_hash=body.documentHash.lower(),
        certificate_serial=record.serial_number,
    )
    db.commit()

    return SigningRequestResponseV2(
        requestId=request_id,
        nonce=nonce,
        signingPayload=payload,
        canonicalPayloadBase64=base64.b64encode(canonical).decode("ascii"),
        warnings=warnings,
    )


@router.post("/api/v2/signing-requests/{request_id}/otp/request", response_model=SigningOtpRequestResponse)
def request_signing_email_otp(
    request_id: str,
    db: Session = Depends(get_db),
    actor: dict[str, str] = Depends(require_roles(SIGNER)),
):
    request = db.get(SigningRequest, request_id)
    if not request:
        raise HTTPException(status_code=404, detail="Signing request not found")
    _require_signing_request_owner(request, actor)
    if request.status != "pending":
        raise HTTPException(status_code=400, detail=f"Signing request is {request.status}")

    try:
        token, otp = create_signing_email_otp(
            db,
            email=request.signer_email,
            signing_request_id=request.request_id,
            document_hash=request.document_hash,
            certificate_serial=request.certificate_serial,
            signing_purpose=request.signing_purpose,
            nonce=request.nonce,
        )
    except ValueError as exc:
        if "cooldown" in str(exc):
            raise HTTPException(status_code=429, detail=str(exc)) from exc
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    delivery = _send_otp_email(token.email, "SIGNING_CONFIRMATION", otp)
    _log_audit(
        db,
        "signing_confirmation_otp_requested",
        request.signer_email,
        "success",
        details=f"requestId={request.request_id}",
        document_hash=request.document_hash,
        certificate_serial=request.certificate_serial,
    )
    db.commit()
    return {
        "otpId": token.id,
        "requestId": request.request_id,
        "email": token.email,
        "expiresAt": token.expires_at.isoformat(),
        "delivery": delivery,
        "warning": "OTP is bound to this signing request and is not returned by this API.",
    }


@router.post("/api/v2/signing-requests/{request_id}/confirm", response_model=SigningConfirmResponse)
def confirm_signing_request(
    request_id: str,
    body: SigningConfirmRequest,
    db: Session = Depends(get_db),
    actor: dict[str, str] = Depends(require_roles(SIGNER)),
):
    request = db.get(SigningRequest, request_id)
    if not request:
        raise HTTPException(status_code=404, detail="Signing request not found")
    _require_signing_request_owner(request, actor)
    if request.status != "pending":
        raise HTTPException(status_code=400, detail=f"Signing request is {request.status}")

    method = body.method.strip().upper()
    if method == "EMAIL_OTP":
        ok, message = verify_signing_email_otp(
            db,
            email=request.signer_email,
            signing_request_id=request.request_id,
            document_hash=request.document_hash,
            certificate_serial=request.certificate_serial,
            signing_purpose=request.signing_purpose,
            nonce=request.nonce,
            otp=body.code,
        )
    elif method == "TOTP":
        ok, message = verify_enabled_totp_for_email(db, request.signer_email, body.code)
    else:
        raise HTTPException(status_code=400, detail="Unsupported confirmation method")

    if not ok:
        _log_audit(
            db,
            "signing_request_confirmed",
            request.signer_email,
            "failed",
            details=f"requestId={request.request_id}; method={method}; reason={message}",
            document_hash=request.document_hash,
            certificate_serial=request.certificate_serial,
        )
        db.commit()
        raise HTTPException(status_code=400, detail=message)

    now = utc_now()
    request.status = "mfa_confirmed"
    request.confirmation_method = method
    request.confirmed_at = _db_time(now)
    _log_audit(
        db,
        "signing_request_confirmed",
        request.signer_email,
        "success",
        details=f"requestId={request.request_id}; method={method}",
        document_hash=request.document_hash,
        certificate_serial=request.certificate_serial,
    )
    db.commit()
    return {
        "confirmed": True,
        "requestId": request.request_id,
        "status": request.status,
        "confirmationMethod": method,
        "confirmedAt": isoformat(now),
    }


@router.post("/api/sign/v2/submit")
def submit_signature(
    body: SignedPackageV2,
    db: Session = Depends(get_db),
    actor: dict[str, str] = Depends(require_roles(SIGNER)),
):
    payload = body.signingPayload
    try:
        cert = _certificate_from_package(body)
    except ValueError as exc:
        _reject_submit(db, str(exc), payload, None)
    warnings: list[str] = []
    steps: list[dict[str, str]] = []

    if body.packageVersion != "2.0":
        _reject_submit(db, "Unsupported packageVersion", payload, cert)
    if body.payloadCanonicalization != CANONICALIZATION_METHOD:
        _reject_submit(db, "Unsupported payload canonicalization", payload, cert)
    if body.signatureAlgorithm != payload.signatureAlgorithm:
        _reject_submit(db, "Package signatureAlgorithm differs from signingPayload", payload, cert)

    try:
        hash_algorithm = normalize_hash_algorithm(payload.hashAlgorithm)
    except ValueError:
        _reject_submit(db, "Unsupported hash algorithm", payload, cert)

    ok, message = check_algorithm_policy(hash_algorithm, body.signatureAlgorithm)
    if not ok:
        _reject_submit(db, message, payload, cert)
    _step(steps, "Algorithm policy", "passed", message)

    if not _hash_hex_valid(payload.documentHash, hash_algorithm):
        _reject_submit(db, "documentHash does not match hashAlgorithm", payload, cert)

    request = db.get(SigningRequest, payload.requestId)
    if not request:
        _reject_submit(db, "Unknown signing request ID", payload, cert)
    if request.status == "pending":
        _reject_submit(db, "Signing request has not been OTP/TOTP confirmed", payload, cert)
    if request.status != "mfa_confirmed":
        _reject_submit(db, f"Signing request already {request.status}", payload, cert)
    _step(steps, "Signing request", "passed", "Request exists and is MFA-confirmed.")

    if db.get(UsedNonce, payload.nonce):
        _reject_submit(db, "Nonce already used", payload, cert)
    _step(steps, "Replay check", "passed", "Nonce has not been used before.")

    if not _request_context_matches_payload(request, payload, hash_algorithm):
        _reject_submit(db, "Signing payload mismatch with confirmed request", payload, cert)
    _step(steps, "Payload-request consistency", "passed", "Payload matches server request.")

    if cert.serialNumber != payload.certificateSerialNumber:
        _reject_submit(db, "Certificate serial does not match payload", payload, cert)
    if cert.certificateType != payload.certificateType:
        _reject_submit(db, "Certificate type does not match payload", payload, cert)
    if cert.ownerName != payload.signerName or cert.email != payload.signerEmail:
        _reject_submit(db, "Certificate signer identity does not match payload", payload, cert)
    try:
        certificate_fingerprint = _certificate_fingerprint(cert)
    except ValueError as exc:
        _reject_submit(db, str(exc), payload, cert)
    if certificate_fingerprint != payload.certificateFingerprint:
        _reject_submit(db, "Certificate fingerprint does not match payload", payload, cert)
    _step(steps, "Payload-certificate consistency", "passed", "Signer and certificate fields match.")

    trust_ok, trust_message = _verify_certificate_trust(cert)
    if not trust_ok:
        _reject_submit(db, trust_message, payload, cert)
    _step(steps, "Certificate trust", "passed", trust_message)

    record = db.get(CertificateRecord, cert.serialNumber)
    if not record:
        _reject_submit(db, "Unknown certificate serial number", payload, cert)
    if not _certificate_matches_record(cert, record):
        _reject_submit(db, "Certificate does not match server record", payload, cert)
    record_fingerprint = _record_fingerprint(record)
    if record_fingerprint != payload.certificateFingerprint:
        _reject_submit(db, "Payload certificate fingerprint does not match server record", payload, cert)
    _step(steps, "Certificate record", "passed", "Certificate matches trusted DB record.")

    if record.status != "valid":
        _reject_submit(db, "Certificate revoked", payload, cert)
    _step(steps, "Revocation status", "passed", "Server DB marks certificate valid.")

    try:
        expires_at = parse_iso_datetime(cert.expiresAt)
    except ValueError:
        _reject_submit(db, "Malformed certificate expiration", payload, cert)
    if expires_at < utc_now() or _as_utc(record.expires_at) < utc_now():
        _reject_submit(db, "Certificate expired", payload, cert)
    _step(steps, "Validity period", "passed", "Certificate is within its validity period.")

    key_size = get_public_key_size(cert.publicKeyPem)
    if key_size < ALGORITHM_POLICY["minimumRsaKeyBits"]:
        _reject_submit(db, "RSA key size is below policy minimum", payload, cert)
    _step(steps, "Key size", "passed", f"RSA key size is {key_size} bits.")

    canonical = canonicalize_signing_payload(payload.model_dump())
    if not verify_canonical_signature(canonical, body.signatureBase64, cert.publicKeyPem, hash_algorithm):
        _reject_submit(db, "Signature verification failed", payload, cert)
    _step(steps, "Signature verification", "passed", "RSA-PSS signature is valid over canonical payload.")

    now = utc_now()
    db.add(UsedNonce(nonce=payload.nonce, request_id=payload.requestId, used_at=_db_time(now)))
    request.status = "completed"
    request.completed_at = _db_time(now)

    certificate_type = _certificate_type(cert, record)
    if certificate_type == "legacy-demo":
        warnings.append("Legacy-demo JSON certificate is not X.509.")
    else:
        warnings.append("X.509 demo chain is local trust only, not public CA trust.")
    warnings.append("No public CA validation, OCSP/CRL, production TSA, HSM, PAdES, XAdES, or CAdES is used.")

    timestamp_token = body.timestampToken
    timestamp_imprint = _signature_message_imprint(body.signatureBase64)
    if timestamp_token:
        timestamp_ok, timestamp_message = verify_timestamp_token(timestamp_token, timestamp_imprint, payload.nonce)
        if not timestamp_ok:
            _reject_submit(db, timestamp_message, payload, cert)
        _step(steps, "Timestamp token", "passed", timestamp_message)
    else:
        timestamp_token = issue_timestamp_token(timestamp_imprint, "SHA-256", payload.nonce)
        _log_audit(
            db,
            "timestamp_issued",
            payload.signerEmail,
            "success",
            details=f"serialNumber={timestamp_token['serialNumber']}",
            document_hash=payload.documentHash.lower(),
            certificate_serial=cert.serialNumber,
        )
        _step(steps, "Timestamp token", "passed", "Demo TSA token issued for signature hash.")

    report = _base_report(steps, warnings, "valid")
    report.update(
        {
            "documentIntegrity": "passed",
            "signingPayloadValid": "passed",
            "signatureValid": "passed",
            "certificateParsed": "passed",
            "certificateTrusted": "passed",
            "certificateType": certificate_type,
            "certificateChainValid": "passed" if certificate_type == X509_CERTIFICATE_TYPE else "not_available",
            "certificateValidityPeriod": "passed",
            "certificateRevocationStatus": "valid",
            "revocationSource": "server-db",
            "keyUsageValid": "passed" if certificate_type == X509_CERTIFICATE_TYPE else "not_available",
            "algorithmPolicyValid": "passed",
            "replayCheck": "passed",
            "timestampStatus": "demo-tsa-valid",
            "cryptoValid": True,
            "documentHashValid": True,
            "trustedChainValid": True,
            "revocationValid": True,
            "timestampValid": True,
            "serverAccepted": True,
            "signingRequestConfirmed": True,
            "confirmationMethod": request.confirmation_method,
            "legalReady": False,
        }
    )

    package_dict = body.model_dump()
    package_dict["userCertificatePem"] = cert.userCertificatePem
    package_dict["intermediateCertificatePem"] = cert.intermediateCertificatePem
    package_dict["rootCertificatePem"] = cert.rootCertificatePem
    package_dict["trustedRootId"] = body.trustedRootId or TRUSTED_DEMO_ROOT_ID
    package_dict["timestampToken"] = timestamp_token
    package_dict["signerCertificate"] = cert.model_dump()
    package_dict["receivedAtServer"] = isoformat(now)
    package_dict["verificationReport"] = report

    db.add(
        SignatureRecord(
            request_id=payload.requestId,
            document_name=payload.documentName,
            document_hash=payload.documentHash.lower(),
            hash_algorithm=hash_algorithm,
            signature_algorithm=body.signatureAlgorithm,
            signature_base64=body.signatureBase64,
            signer_name=payload.signerName,
            signer_email=payload.signerEmail,
            certificate_serial=cert.serialNumber,
            signing_purpose=payload.signingPurpose,
            signed_at_client=body.signedAtClient,
            received_at_server=_db_time(now),
            verification_result="valid",
            signed_package_json=json.dumps(package_dict, ensure_ascii=False),
        )
    )
    _log_audit(
        db,
        "signature_submitted",
        payload.signerEmail,
        "success",
        details=f"requestId={payload.requestId}",
        document_hash=payload.documentHash.lower(),
        certificate_serial=cert.serialNumber,
    )
    db.commit()

    return {
        "accepted": True,
        "requestId": payload.requestId,
        "receivedAtServer": isoformat(now),
        "verificationReport": report,
        "signedPackage": package_dict,
        "warnings": warnings,
    }


@router.post("/api/verify/v2")
def verify_v2(body: dict[str, Any], db: Session = Depends(get_db)):
    steps: list[dict[str, str]] = []
    warnings: list[str] = []
    document_hash = str(body.get("documentHash") or "").lower()
    request_hash_algorithm = str(body.get("hashAlgorithm") or "SHA-256")
    package_data = body.get("signedPackage")

    def fail(
        reason: str,
        field_values: dict[str, str],
        payload: SigningPayloadV2 | None = None,
        cert: Certificate | None = None,
        signed_at: str | None = None,
    ) -> dict[str, Any]:
        report = _base_report(steps, warnings, "invalid")
        report.update(field_values)
        report["errors"].append(reason)
        _log_audit(
            db,
            "signature_verified",
            payload.signerEmail if payload else None,
            "failed",
            details=reason,
            document_hash=payload.documentHash if payload else document_hash,
            certificate_serial=cert.serialNumber if cert else None,
        )
        db.commit()
        return _verification_response(False, reason, report, document_hash, payload, cert, signed_at)

    if not document_hash or not package_data:
        _log_audit(db, "signature_verified", None, "failed", details="documentHash and signedPackage required")
        db.commit()
        raise HTTPException(status_code=400, detail="documentHash and signedPackage required")

    try:
        package = SignedPackageV2.model_validate(package_data)
    except Exception as exc:
        _log_audit(db, "signature_verified", None, "failed", details="Malformed signedPackage")
        db.commit()
        raise HTTPException(status_code=400, detail="Malformed signedPackage") from exc

    payload = package.signingPayload
    try:
        cert = _certificate_from_package(package)
    except ValueError as exc:
        _step(steps, "Certificate parsing", "failed", str(exc))
        report = _base_report(steps, warnings, "invalid")
        report.update({"certificateParsed": "failed"})
        _log_audit(db, "signature_verified", payload.signerEmail, "failed", details=str(exc), document_hash=payload.documentHash)
        db.commit()
        return _verification_response(False, "malformed certificate", report, document_hash, payload, None, package.signedAtClient)
    signed_at = package.signedAtClient

    if package.packageVersion != "2.0":
        _step(steps, "Package version", "failed", "Only v2 packages are accepted.")
        return fail("unsupported packageVersion", {"signingPayloadValid": "failed"}, payload, cert, signed_at)
    if package.payloadCanonicalization != CANONICALIZATION_METHOD:
        _step(steps, "Canonicalization", "failed", "Unsupported canonicalization method.")
        return fail("unsupported canonicalization", {"signingPayloadValid": "failed"}, payload, cert, signed_at)

    try:
        payload_hash_algorithm = normalize_hash_algorithm(payload.hashAlgorithm)
        request_hash_algorithm = normalize_hash_algorithm(request_hash_algorithm)
    except ValueError:
        _step(steps, "Algorithm policy", "failed", "Unsupported hash algorithm.")
        return fail("unsupported hash algorithm", {"algorithmPolicyValid": "failed"}, payload, cert, signed_at)

    if request_hash_algorithm != payload_hash_algorithm:
        _step(steps, "Algorithm policy", "failed", "Request hashAlgorithm differs from payload.")
        return fail("hash algorithm mismatch", {"algorithmPolicyValid": "failed"}, payload, cert, signed_at)

    if package.signatureAlgorithm != payload.signatureAlgorithm:
        _step(steps, "Algorithm policy", "failed", "Package signatureAlgorithm differs from payload.")
        return fail("signature algorithm mismatch", {"algorithmPolicyValid": "failed"}, payload, cert, signed_at)

    ok, message = check_algorithm_policy(payload_hash_algorithm, package.signatureAlgorithm)
    if not ok:
        _step(steps, "Algorithm policy", "failed", message)
        return fail("algorithm policy failed", {"algorithmPolicyValid": "failed"}, payload, cert, signed_at)
    if not _hash_hex_valid(document_hash, payload_hash_algorithm) or not _hash_hex_valid(
        payload.documentHash, payload_hash_algorithm
    ):
        _step(steps, "Algorithm policy", "failed", "documentHash length does not match hashAlgorithm.")
        return fail("documentHash does not match hashAlgorithm", {"algorithmPolicyValid": "failed"}, payload, cert, signed_at)
    _step(steps, "Algorithm policy", "passed", message)

    if document_hash != payload.documentHash.lower():
        _step(steps, "Document integrity", "failed", "Provided document hash differs from signed payload.")
        return fail("document modified", {"documentIntegrity": "failed", "algorithmPolicyValid": "passed"}, payload, cert, signed_at)
    _step(steps, "Document integrity", "passed", "Document hash matches signed payload.")

    if not payload.requestId or not payload.nonce or payload.payloadVersion != "1.0":
        _step(steps, "Signing payload", "failed", "Missing requestId/nonce or unsupported payloadVersion.")
        return fail(
            "invalid signing payload",
            {"documentIntegrity": "passed", "signingPayloadValid": "failed", "algorithmPolicyValid": "passed"},
            payload,
            cert,
            signed_at,
        )

    if cert.serialNumber != payload.certificateSerialNumber:
        _step(steps, "Signing payload", "failed", "Certificate serial differs from payload.")
        return fail(
            "certificate serial mismatch",
            {"documentIntegrity": "passed", "signingPayloadValid": "failed", "algorithmPolicyValid": "passed"},
            payload,
            cert,
            signed_at,
        )
    if cert.ownerName != payload.signerName or cert.email != payload.signerEmail:
        _step(steps, "Signing payload", "failed", "Signer identity differs from certificate.")
        return fail(
            "signer identity mismatch",
            {"documentIntegrity": "passed", "signingPayloadValid": "failed", "algorithmPolicyValid": "passed"},
            payload,
            cert,
            signed_at,
        )
    if cert.certificateType != payload.certificateType:
        _step(steps, "Signing payload", "failed", "Certificate type differs from payload.")
        return fail(
            "certificate type mismatch",
            {"documentIntegrity": "passed", "signingPayloadValid": "failed", "algorithmPolicyValid": "passed"},
            payload,
            cert,
            signed_at,
        )
    try:
        certificate_fingerprint = _certificate_fingerprint(cert)
    except ValueError as exc:
        _step(steps, "Signing payload", "failed", str(exc))
        return fail(
            "certificate fingerprint missing",
            {"documentIntegrity": "passed", "signingPayloadValid": "failed", "algorithmPolicyValid": "passed"},
            payload,
            cert,
            signed_at,
        )
    if certificate_fingerprint != payload.certificateFingerprint:
        _step(steps, "Signing payload", "failed", "Certificate fingerprint differs from payload.")
        return fail(
            "certificate fingerprint mismatch",
            {"documentIntegrity": "passed", "signingPayloadValid": "failed", "algorithmPolicyValid": "passed"},
            payload,
            cert,
            signed_at,
        )
    _step(steps, "Signing payload", "passed", "Payload fields are consistent with certificate.")

    certificate_type = _certificate_type(cert)
    _step(
        steps,
        "Certificate parsing",
        "passed",
        "X.509 certificate PEM parsed." if certificate_type == X509_CERTIFICATE_TYPE else "Legacy certificate JSON parsed.",
    )
    trust_ok, trust_message = _verify_certificate_trust(cert)
    if not trust_ok:
        _step(steps, "Certificate trust", "failed", trust_message)
        return fail(
            "certificate not trusted",
            {
                "documentIntegrity": "passed",
                "signingPayloadValid": "passed",
                "certificateParsed": "passed",
                "certificateTrusted": "failed",
                "certificateType": certificate_type,
                "certificateChainValid": "failed",
                "keyUsageValid": "failed" if "KeyUsage" in trust_message else "not_available",
                "algorithmPolicyValid": "passed",
            },
            payload,
            cert,
            signed_at,
        )
    _step(steps, "Certificate trust", "passed", trust_message)
    warnings.append("SecureDoc Demo CA is local demo trust only.")

    record = db.get(CertificateRecord, cert.serialNumber)
    if not record:
        _step(steps, "Certificate lookup", "failed", "Serial number is not in server DB.")
        return fail(
            "unknown certificate serial number",
            {
                "documentIntegrity": "passed",
                "signingPayloadValid": "passed",
                "certificateParsed": "passed",
                "certificateTrusted": "failed",
                "certificateRevocationStatus": "unknown",
                "revocationSource": "server-db",
                "algorithmPolicyValid": "passed",
            },
            payload,
            cert,
            signed_at,
        )

    certificate_type = _certificate_type(cert, record)
    if certificate_type == "legacy-demo":
        warnings.append("Certificate is a legacy-demo JSON certificate, not X.509.")
    if not _certificate_matches_record(cert, record):
        _step(steps, "Certificate record", "failed", "Certificate does not match trusted server record.")
        return fail(
            "certificate record mismatch",
            {
                "documentIntegrity": "passed",
                "signingPayloadValid": "passed",
                "certificateParsed": "passed",
                "certificateTrusted": "failed",
                "certificateType": certificate_type,
                "algorithmPolicyValid": "passed",
            },
            payload,
            cert,
            signed_at,
        )
    if _record_fingerprint(record) != payload.certificateFingerprint:
        _step(steps, "Certificate record", "failed", "Payload fingerprint differs from server record.")
        return fail(
            "certificate fingerprint mismatch",
            {
                "documentIntegrity": "passed",
                "signingPayloadValid": "failed",
                "certificateParsed": "passed",
                "certificateTrusted": "failed",
                "certificateType": certificate_type,
                "algorithmPolicyValid": "passed",
            },
            payload,
            cert,
            signed_at,
        )
    _step(steps, "Certificate record", "passed", "Certificate matches trusted server DB record.")

    revocation = _latest_revocation(db, cert.serialNumber)
    revocation_status = "valid"
    if record.status != "valid":
        message = "Server DB marks certificate revoked."
        if revocation:
            message = f"{message} reason={revocation.reason}; revokedAt={_db_iso(revocation.revoked_at)}"
        trusted_signing_time, revocation_timestamp_status, revocation_timestamp_message = _trusted_timestamp_time(
            package.timestampToken,
            package.signatureBase64,
            payload.nonce,
        )
        if revocation and trusted_signing_time and _as_utc(revocation.revoked_at) > _as_utc(trusted_signing_time):
            revocation_status = "revoked_after_signing_time"
            _step(
                steps,
                "Revocation status",
                "passed",
                f"{message}; trusted signing time={isoformat(trusted_signing_time)}",
            )
            warnings.append("Certificate is currently revoked, but revocation occurred after the trusted signing time.")
        else:
            if revocation_timestamp_status != "demo-tsa-valid":
                message = f"{message}; {revocation_timestamp_message}"
            elif revocation and trusted_signing_time:
                message = f"{message}; revoked before or at trusted signing time={isoformat(trusted_signing_time)}"
            _step(steps, "Revocation status", "failed", message)
            revocation_status = "revoked"
            return fail(
                "certificate revoked",
                {
                    "documentIntegrity": "passed",
                    "signingPayloadValid": "passed",
                    "certificateParsed": "passed",
                    "certificateTrusted": "passed",
                    "certificateType": certificate_type,
                    "certificateRevocationStatus": revocation_status,
                    "revocationSource": "server-db",
                    "algorithmPolicyValid": "passed",
                    "timestampStatus": revocation_timestamp_status,
                },
                payload,
                cert,
                signed_at,
            )
    else:
        _step(steps, "Revocation status", "passed", "Server DB marks certificate valid.")

    try:
        expires_at = parse_iso_datetime(cert.expiresAt)
    except ValueError:
        _step(steps, "Validity period", "failed", "Certificate expiration is malformed.")
        return fail(
            "malformed certificate validity",
            {
                "documentIntegrity": "passed",
                "signingPayloadValid": "passed",
                "certificateParsed": "passed",
                "certificateTrusted": "passed",
                "certificateType": certificate_type,
                "certificateRevocationStatus": revocation_status,
                "revocationSource": "server-db",
                "certificateValidityPeriod": "failed",
                "algorithmPolicyValid": "passed",
            },
            payload,
            cert,
            signed_at,
        )
    if expires_at < utc_now() or _as_utc(record.expires_at) < utc_now():
        _step(steps, "Validity period", "failed", "Certificate is expired.")
        return fail(
            "certificate expired",
            {
                "documentIntegrity": "passed",
                "signingPayloadValid": "passed",
                "certificateParsed": "passed",
                "certificateTrusted": "passed",
                "certificateType": certificate_type,
                "certificateRevocationStatus": revocation_status,
                "revocationSource": "server-db",
                "certificateValidityPeriod": "failed",
                "algorithmPolicyValid": "passed",
            },
            payload,
            cert,
            signed_at,
        )
    _step(steps, "Validity period", "passed", "Certificate is within its validity period.")

    key_size = get_public_key_size(cert.publicKeyPem)
    if key_size < ALGORITHM_POLICY["minimumRsaKeyBits"]:
        _step(steps, "Key size", "failed", f"RSA key size is {key_size} bits.")
        return fail(
            "key size below policy",
            {
                "documentIntegrity": "passed",
                "signingPayloadValid": "passed",
                "certificateParsed": "passed",
                "certificateTrusted": "passed",
                "certificateType": certificate_type,
                "certificateRevocationStatus": revocation_status,
                "revocationSource": "server-db",
                "certificateValidityPeriod": "passed",
                "keyUsageValid": "failed",
                "algorithmPolicyValid": "passed",
            },
            payload,
            cert,
            signed_at,
        )
    _step(steps, "Key size", "passed", f"RSA key size is {key_size} bits.")

    used_nonce = db.get(UsedNonce, payload.nonce)
    replay_status = "passed" if used_nonce else "not_available"
    if used_nonce:
        _step(steps, "Replay check", "passed", "Nonce was recorded during signature submission.")
    else:
        _step(steps, "Replay check", "warning", "Nonce was not recorded by this server.")
        warnings.append("Replay check is not authoritative for packages submitted elsewhere.")

    request, signing_request_confirmed, confirmation_method, request_context_matches = _confirmation_state(
        db,
        payload,
        payload_hash_algorithm,
    )
    if not request:
        _step(steps, "Signing confirmation", "warning", "Signing request is not present in this server DB.")
        warnings.append("Signing request confirmation could not be checked on this server.")
    elif not request_context_matches:
        _step(steps, "Signing confirmation", "warning", "Signing payload does not match the server signing request.")
        warnings.append("Signing request context does not match this signed package.")
    elif signing_request_confirmed:
        _step(steps, "Signing confirmation", "passed", f"Signing request was confirmed with {confirmation_method}.")
    else:
        _step(steps, "Signing confirmation", "warning", f"Signing request status is {request.status}, not confirmed.")
        warnings.append("Signing request has not been OTP/TOTP confirmed.")

    canonical = canonicalize_signing_payload(payload.model_dump())
    if not verify_canonical_signature(canonical, package.signatureBase64, cert.publicKeyPem, payload_hash_algorithm):
        _step(steps, "Signature verification", "failed", "RSA-PSS verification failed over canonical payload.")
        return fail(
            "invalid signature",
            {
                "documentIntegrity": "passed",
                "signingPayloadValid": "passed",
                "signatureValid": "failed",
                "certificateParsed": "passed",
                "certificateTrusted": "passed",
                "certificateType": certificate_type,
                "certificateChainValid": "passed" if certificate_type == X509_CERTIFICATE_TYPE else "not_available",
                "certificateRevocationStatus": revocation_status,
                "revocationSource": "server-db",
                "certificateValidityPeriod": "passed",
                "keyUsageValid": "passed" if certificate_type == X509_CERTIFICATE_TYPE else "not_available",
                "algorithmPolicyValid": "passed",
                "replayCheck": replay_status,
            },
            payload,
            cert,
            signed_at,
        )
    _step(steps, "Signature verification", "passed", "RSA-PSS signature is valid over canonical payload.")

    timestamp_status = "not_available"
    if package.timestampToken:
        timestamp_ok, timestamp_message = verify_timestamp_token(
            package.timestampToken,
            _signature_message_imprint(package.signatureBase64),
            payload.nonce,
        )
        if timestamp_ok:
            timestamp_status = "demo-tsa-valid"
            _step(steps, "Timestamp token", "passed", timestamp_message)
        else:
            timestamp_status = "failed"
            _step(steps, "Timestamp token", "failed", timestamp_message)
            return fail(
                "invalid timestamp token",
                {
                    "documentIntegrity": "passed",
                    "signingPayloadValid": "passed",
                    "signatureValid": "passed",
                    "certificateParsed": "passed",
                    "certificateTrusted": "passed",
                    "certificateType": certificate_type,
                    "certificateChainValid": "passed" if certificate_type == X509_CERTIFICATE_TYPE else "not_available",
                    "certificateValidityPeriod": "passed",
                    "certificateRevocationStatus": revocation_status,
                    "revocationSource": "server-db",
                    "keyUsageValid": "passed" if certificate_type == X509_CERTIFICATE_TYPE else "not_available",
                    "algorithmPolicyValid": "passed",
                    "replayCheck": replay_status,
                    "timestampStatus": timestamp_status,
                },
                payload,
                cert,
                signed_at,
            )
    elif signed_at:
        try:
            parse_iso_datetime(signed_at)
            timestamp_status = "client-declared-time"
        except ValueError:
            timestamp_status = "malformed-client-time"
            warnings.append("signedAtClient is malformed and is not trusted.")

    server_accepted = used_nonce is not None and signing_request_confirmed
    final_decision = "valid" if server_accepted else "crypto_valid_server_rejected"
    report = _base_report(steps, warnings, final_decision)
    report.update(
        {
            "documentIntegrity": "passed",
            "signingPayloadValid": "passed",
            "signatureValid": "passed",
            "certificateParsed": "passed",
            "certificateTrusted": "passed",
            "certificateType": certificate_type,
            "certificateChainValid": "passed" if certificate_type == X509_CERTIFICATE_TYPE else "not_available",
            "certificateValidityPeriod": "passed",
            "certificateRevocationStatus": revocation_status,
            "revocationSource": "server-db",
            "keyUsageValid": "passed" if certificate_type == X509_CERTIFICATE_TYPE else "not_available",
            "algorithmPolicyValid": "passed",
            "replayCheck": replay_status,
            "timestampStatus": timestamp_status,
            "cryptoValid": True,
            "documentHashValid": True,
            "trustedChainValid": True,
            "revocationValid": True,
            "timestampValid": timestamp_status == "demo-tsa-valid",
            "serverAccepted": server_accepted,
            "signingRequestConfirmed": signing_request_confirmed,
            "confirmationMethod": confirmation_method,
            "legalReady": False,
        }
    )
    _log_audit(
        db,
        "signature_verified",
        payload.signerEmail,
        "success",
        details=f"requestId={payload.requestId}",
        document_hash=payload.documentHash,
        certificate_serial=cert.serialNumber,
    )
    db.commit()

    reason = "signature valid" if server_accepted else "signature valid but not accepted by server"
    return _verification_response(True, reason, report, document_hash, payload, cert, signed_at)


@router.post("/api/certificates/revoke/v2")
def revoke_v2(
    body: RevokeBySerialRequest,
    db: Session = Depends(get_db),
    actor: dict[str, str] = Depends(require_roles(CA_OFFICER)),
):
    record = db.get(CertificateRecord, body.serialNumber)
    if not record:
        raise HTTPException(status_code=404, detail="Certificate not found")
    if record.status == "revoked":
        raise HTTPException(status_code=400, detail="Already revoked")

    now = utc_now()
    record.status = "revoked"
    db.add(
        CertificateRevocation(
            serial_number=body.serialNumber,
            reason=body.reason,
            revoked_at=_db_time(now),
            revoked_by=body.revokedBy,
        )
    )
    _log_audit(
        db,
        "certificate_revoked",
        body.revokedBy,
        "success",
        details=f"reason={body.reason}",
        certificate_serial=body.serialNumber,
    )
    db.commit()
    return {
        "serialNumber": body.serialNumber,
        "status": "revoked",
        "reason": body.reason,
        "revokedAt": isoformat(now),
    }


@router.get("/api/certificates/status/{serial_number}")
def certificate_status(serial_number: str, db: Session = Depends(get_db)):
    record = db.get(CertificateRecord, serial_number)
    if not record:
        raise HTTPException(status_code=404, detail="Certificate not found")
    revocation = _latest_revocation(db, serial_number)
    return {
        "serialNumber": record.serial_number,
        "status": record.status,
        "reason": revocation.reason if revocation else None,
        "revokedAt": _db_iso(revocation.revoked_at) if revocation else None,
        "expiresAt": _db_iso(record.expires_at),
    }


@router.get("/api/certificates/revocation-list")
def revocation_list(
    db: Session = Depends(get_db),
    actor: dict[str, str] = Depends(require_roles(VERIFIER, AUDITOR, CA_OFFICER)),
):
    revoked_records = db.query(CertificateRecord).filter_by(status="revoked").all()
    items = []
    for record in revoked_records:
        revocation = _latest_revocation(db, record.serial_number)
        items.append(
            {
                "serialNumber": record.serial_number,
                "ownerName": record.owner_name,
                "reason": revocation.reason if revocation else "unspecified",
                "revokedAt": _db_iso(revocation.revoked_at) if revocation else None,
            }
        )
    return {
        "issuer": ISSUER,
        "generatedAt": isoformat(utc_now()),
        "revokedCertificates": items,
        "totalRevoked": len(items),
    }


@router.get("/api/certificates/crl")
def certificate_crl(
    db: Session = Depends(get_db),
    actor: dict[str, str] = Depends(require_roles(VERIFIER, AUDITOR, CA_OFFICER)),
):
    revoked_records = db.query(CertificateRecord).filter_by(status="revoked").all()
    revoked_certificates = []
    for record in revoked_records:
        revocation = _latest_revocation(db, record.serial_number)
        revoked_certificates.append(
            {
                "serialNumber": record.serial_number,
                "certificateFingerprint": record.fingerprint_sha256,
                "reason": revocation.reason if revocation else "unspecified",
                "revokedAt": _db_iso(revocation.revoked_at) if revocation else None,
            }
        )
    crl = build_signed_demo_crl(revoked_certificates)
    valid, message = verify_signed_demo_crl(crl)
    _log_audit(
        db,
        "crl_generated",
        None,
        "success" if valid else "failed",
        details=message,
    )
    db.commit()
    return crl


@router.get("/api/audit/verify-chain")
def verify_audit_chain(
    db: Session = Depends(get_db),
    actor: dict[str, str] = Depends(require_roles(AUDITOR)),
):
    events = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
    previous_hash = None
    for index, event in enumerate(events, start=1):
        event_json = build_audit_event_json(
            event.event_id,
            event.event_type,
            event.actor,
            event.result,
            event.details,
            _db_iso(event.created_at),
        )
        expected_hash = compute_audit_hash(event_json, previous_hash)
        if event.previous_log_hash != previous_hash or event.current_log_hash != expected_hash:
            return {
                "valid": False,
                "totalEvents": len(events),
                "brokenAt": {
                    "index": index,
                    "id": event.id,
                    "eventId": event.event_id,
                },
            }
        previous_hash = event.current_log_hash
    return {"valid": True, "totalEvents": len(events), "brokenAt": None}


@router.get("/api/algorithm-policy")
def get_algorithm_policy():
    return ALGORITHM_POLICY


@router.post("/api/timestamp/rfc3161", response_model=Rfc3161TimestampResponse)
def request_rfc3161_timestamp(
    body: Rfc3161TimestampRequest,
    actor: dict[str, str] = Depends(require_roles(SIGNER, VERIFIER, CA_OFFICER)),
):
    if not RFC3161_TSA_URL:
        raise HTTPException(status_code=503, detail="SECUREDOC_RFC3161_TSA_URL is not configured")
    try:
        digest = base64.b64decode(body.messageDigestBase64, validate=True)
        hash_algorithm = normalize_hash_algorithm(body.hashAlgorithm)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail="Invalid timestamp request") from exc
    try:
        from pyhanko.sign import timestamps

        timestamper = timestamps.HTTPTimeStamper(RFC3161_TSA_URL)
        token = asyncio.run(timestamper.async_timestamp(digest, hash_algorithm.lower().replace("-", "")))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"RFC3161 TSA request failed: {exc}") from exc
    return {
        "tokenBase64": base64.b64encode(token.dump()).decode("ascii"),
        "hashAlgorithm": hash_algorithm,
        "provider": RFC3161_TSA_URL,
    }


@router.post("/api/pdf/pades/sign")
async def sign_pdf_pades(
    file: UploadFile = File(...),
    reason: str = Form("SecureDoc document approval"),
    location: str = Form("SecureDoc"),
    db: Session = Depends(get_db),
    actor: dict[str, str] = Depends(require_roles(SIGNER)),
):
    filename, content, mime_type = await _read_document_upload(file)
    if mime_type != "application/pdf":
        raise HTTPException(status_code=400, detail="PAdES signing requires a PDF file")
    try:
        signed_pdf, profile = await run_in_threadpool(
            sign_pdf_pades_bytes,
            content,
            reason=reason,
            location=location,
            signer_name=_actor_email(actor),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"PAdES signing failed: {exc}") from exc

    signed_hash = hash_bytes(signed_pdf, "SHA-256")
    _log_audit(
        db,
        "pades_pdf_signed",
        _actor_email(actor),
        "success",
        details=f"profile={profile}; filename={filename}",
        document_hash=signed_hash,
    )
    db.commit()
    stem = Path(filename).stem or "signed"
    headers = {
        "Content-Disposition": f'attachment; filename="{stem}-pades-signed.pdf"',
        "X-SecureDoc-PAdES-Profile": profile,
        "X-SecureDoc-PAdES-Hash": signed_hash,
    }
    return StreamingResponse(io.BytesIO(signed_pdf), media_type="application/pdf", headers=headers)
