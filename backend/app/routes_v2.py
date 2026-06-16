"""V2 client-side signing protocol endpoints."""

import base64
import json
import secrets
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

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
    SignatureRecord,
    SigningRequest,
    UsedNonce,
)
from .schemas import (
    Certificate,
    RevokeBySerialRequest,
    SignedPackageV2,
    SigningPayloadV2,
    SigningRequestCreateV2,
    SigningRequestResponseV2,
)

router = APIRouter()

CANONICALIZATION_METHOD = "JSON-canonical-sorted-keys"


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
    return {
        "serialNumber": record.serial_number,
        "ownerName": record.owner_name,
        "email": record.email,
        "publicKeyPem": record.public_key_pem,
        "issuer": record.issuer,
        "issuedAt": _db_iso(record.issued_at),
        "expiresAt": _db_iso(record.expires_at),
    }


def _record_fingerprint(record: CertificateRecord) -> str:
    return compute_certificate_fingerprint(_record_certificate_payload(record))


def _certificate_matches_record(cert: Certificate, record: CertificateRecord) -> bool:
    if cert.serialNumber != record.serial_number:
        return False
    if cert.ownerName != record.owner_name or cert.email != record.email:
        return False
    if cert.publicKeyPem != record.public_key_pem or cert.issuer != record.issuer:
        return False
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
        "documentIntegrity": "not_checked",
        "signingPayloadValid": "not_checked",
        "signatureValid": "not_checked",
        "certificateParsed": "not_checked",
        "certificateTrusted": "not_checked",
        "certificateType": "legacy-demo",
        "certificateChainValid": "not_available",
        "certificateValidityPeriod": "not_checked",
        "certificateRevocationStatus": "not_checked",
        "keyUsageValid": "not_available",
        "algorithmPolicyValid": "not_checked",
        "replayCheck": "not_checked",
        "timestampStatus": "not_checked",
        "finalDecision": decision,
        "warnings": warnings,
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


@router.post("/api/sign/v2/prepare", response_model=SigningRequestResponseV2)
def prepare_signing_request(body: SigningRequestCreateV2, db: Session = Depends(get_db)):
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


@router.post("/api/sign/v2/submit")
def submit_signature(body: SignedPackageV2, db: Session = Depends(get_db)):
    payload = body.signingPayload
    cert = body.signerCertificate
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
    if request.status != "pending":
        _reject_submit(db, f"Signing request already {request.status}", payload, cert)
    _step(steps, "Signing request", "passed", "Request exists and is pending.")

    if db.get(UsedNonce, payload.nonce):
        _reject_submit(db, "Nonce already used", payload, cert)
    _step(steps, "Replay check", "passed", "Nonce has not been used before.")

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
    for attr, expected_value in expected.items():
        if getattr(request, attr) != expected_value:
            _reject_submit(db, f"Signing payload mismatch: {attr}", payload, cert)
    _step(steps, "Payload-request consistency", "passed", "Payload matches server request.")

    if cert.serialNumber != payload.certificateSerialNumber:
        _reject_submit(db, "Certificate serial does not match payload", payload, cert)
    if cert.ownerName != payload.signerName or cert.email != payload.signerEmail:
        _reject_submit(db, "Certificate signer identity does not match payload", payload, cert)
    if compute_certificate_fingerprint(cert.model_dump()) != payload.certificateFingerprint:
        _reject_submit(db, "Certificate fingerprint does not match payload", payload, cert)
    _step(steps, "Payload-certificate consistency", "passed", "Signer and certificate fields match.")

    if not verify_certificate_signature(cert.model_dump()):
        _reject_submit(db, "Certificate is not signed by SecureDoc Demo CA", payload, cert)
    _step(steps, "Certificate trust", "passed", "Certificate is signed by SecureDoc Demo CA.")

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

    if (record.certificate_type or "legacy-demo") == "legacy-demo":
        warnings.append("Legacy-demo JSON certificate is not X.509.")
    warnings.append("No real CA chain, OCSP/CRL, TSA, HSM, PAdES, XAdES, or CAdES is used.")

    report = _base_report(steps, warnings, "valid")
    report.update(
        {
            "documentIntegrity": "passed",
            "signingPayloadValid": "passed",
            "signatureValid": "passed",
            "certificateParsed": "passed",
            "certificateTrusted": "passed",
            "certificateType": record.certificate_type or "legacy-demo",
            "certificateValidityPeriod": "passed",
            "certificateRevocationStatus": "valid",
            "keyUsageValid": "not_available",
            "algorithmPolicyValid": "passed",
            "replayCheck": "passed",
            "timestampStatus": "client-declared-time" if body.signedAtClient else "not_available",
        }
    )

    package_dict = body.model_dump()
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
    cert = package.signerCertificate
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
    if compute_certificate_fingerprint(cert.model_dump()) != payload.certificateFingerprint:
        _step(steps, "Signing payload", "failed", "Certificate fingerprint differs from payload.")
        return fail(
            "certificate fingerprint mismatch",
            {"documentIntegrity": "passed", "signingPayloadValid": "failed", "algorithmPolicyValid": "passed"},
            payload,
            cert,
            signed_at,
        )
    _step(steps, "Signing payload", "passed", "Payload fields are consistent with certificate.")

    _step(steps, "Certificate parsing", "passed", "Certificate JSON parsed.")
    if not verify_certificate_signature(cert.model_dump()):
        _step(steps, "Certificate trust", "failed", "Certificate is not signed by SecureDoc Demo CA.")
        return fail(
            "certificate not trusted",
            {
                "documentIntegrity": "passed",
                "signingPayloadValid": "passed",
                "certificateParsed": "passed",
                "certificateTrusted": "failed",
                "algorithmPolicyValid": "passed",
            },
            payload,
            cert,
            signed_at,
        )
    _step(steps, "Certificate trust", "passed", "Certificate is signed by SecureDoc Demo CA.")
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
                "algorithmPolicyValid": "passed",
            },
            payload,
            cert,
            signed_at,
        )

    certificate_type = record.certificate_type or "legacy-demo"
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
    if record.status != "valid":
        message = "Server DB marks certificate revoked."
        if revocation:
            message = f"{message} reason={revocation.reason}; revokedAt={_db_iso(revocation.revoked_at)}"
        _step(steps, "Revocation status", "failed", message)
        return fail(
            "certificate revoked",
            {
                "documentIntegrity": "passed",
                "signingPayloadValid": "passed",
                "certificateParsed": "passed",
                "certificateTrusted": "passed",
                "certificateType": certificate_type,
                "certificateRevocationStatus": "revoked",
                "algorithmPolicyValid": "passed",
            },
            payload,
            cert,
            signed_at,
        )
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
                "certificateRevocationStatus": "valid",
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
                "certificateRevocationStatus": "valid",
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
                "certificateRevocationStatus": "valid",
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
                "certificateRevocationStatus": "valid",
                "certificateValidityPeriod": "passed",
                "keyUsageValid": "not_available",
                "algorithmPolicyValid": "passed",
                "replayCheck": replay_status,
            },
            payload,
            cert,
            signed_at,
        )
    _step(steps, "Signature verification", "passed", "RSA-PSS signature is valid over canonical payload.")

    timestamp_status = "not_available"
    if signed_at:
        try:
            parse_iso_datetime(signed_at)
            timestamp_status = "client-declared-time"
        except ValueError:
            timestamp_status = "malformed-client-time"
            warnings.append("signedAtClient is malformed and is not trusted.")

    report = _base_report(steps, warnings, "valid")
    report.update(
        {
            "documentIntegrity": "passed",
            "signingPayloadValid": "passed",
            "signatureValid": "passed",
            "certificateParsed": "passed",
            "certificateTrusted": "passed",
            "certificateType": certificate_type,
            "certificateValidityPeriod": "passed",
            "certificateRevocationStatus": "valid",
            "keyUsageValid": "not_available",
            "algorithmPolicyValid": "passed",
            "replayCheck": replay_status,
            "timestampStatus": timestamp_status,
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

    return _verification_response(True, "signature valid", report, document_hash, payload, cert, signed_at)


@router.post("/api/certificates/revoke/v2")
def revoke_v2(body: RevokeBySerialRequest, db: Session = Depends(get_db)):
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
def revocation_list(db: Session = Depends(get_db)):
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


@router.get("/api/algorithm-policy")
def get_algorithm_policy():
    return ALGORITHM_POLICY
