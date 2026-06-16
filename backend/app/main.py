import json
import secrets
from datetime import timezone
from typing import Any, Dict

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .crypto_utils import (
    CERTIFICATE_SIGNATURE_ALGORITHM,
    ISSUER,
    build_audit_event_json,
    compute_audit_hash,
    compute_certificate_fingerprint,
    create_demo_certificate,
    ensure_demo_ca_keys,
    generate_key_pair,
    get_demo_ca_public_key,
    get_public_key_size,
    hash_bytes,
    isoformat,
    normalize_hash_algorithm,
    parse_iso_datetime,
    rsa_blind_signature_demo,
    sign_hash,
    supported_hash_algorithm_profiles,
    utc_now,
    verify_certificate_signature,
    verify_signature,
)
from .database import SessionLocal, init_db
from .models import AuditLog, CertificateRecord, CertificateRevocation
from .routes_v2 import router as v2_router
from .schemas import (
    BlindSignatureDemoRequest,
    CaPublicKeyResponse,
    Certificate,
    KeyGenerateRequest,
    KeyGenerateResponse,
    RevokeCertificateRequest,
    SignedPackage,
    VerifyResponse,
)

app = FastAPI(title="SecureDoc API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(v2_router)


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    ensure_demo_ca_keys()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def read_json_form(value: str, field_name: str) -> Dict[str, Any]:
    try:
        parsed = json.loads(value.lstrip("\ufeff"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Malformed {field_name} JSON") from exc
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=400, detail=f"{field_name} must be a JSON object")
    return parsed


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


@app.get("/api/ca/public-key", response_model=CaPublicKeyResponse)
def get_ca_public_key():
    return {
        "issuer": ISSUER,
        "publicKeyPem": get_demo_ca_public_key(),
        "signatureAlgorithm": CERTIFICATE_SIGNATURE_ALGORITHM,
    }


@app.get("/api/crypto/hash-algorithms")
def get_hash_algorithms():
    return {"algorithms": supported_hash_algorithm_profiles(), "default": "SHA-256"}


@app.post(
    "/api/keys/generate",
    response_model=KeyGenerateResponse,
    summary="Generate RSA key pair (demo - returns private key to client)",
)
def generate_keys(payload: KeyGenerateRequest, db: Session = Depends(get_db)):
    private_key_pem, public_key_pem = generate_key_pair()
    certificate = create_demo_certificate(payload.name, payload.email, public_key_pem)
    record = CertificateRecord(
        serial_number=certificate["serialNumber"],
        owner_name=certificate["ownerName"],
        email=certificate["email"],
        public_key_pem=certificate["publicKeyPem"],
        issuer=certificate["issuer"],
        issued_at=parse_iso_datetime(certificate["issuedAt"]).replace(tzinfo=None),
        expires_at=parse_iso_datetime(certificate["expiresAt"]).replace(tzinfo=None),
        status=certificate["status"],
        certificate_type="legacy-demo",
        fingerprint_sha256=compute_certificate_fingerprint(certificate),
        key_size_bits=get_public_key_size(public_key_pem),
    )
    db.add(record)
    log_audit(
        db,
        "certificate_created",
        payload.email,
        "success",
        details="legacy-demo certificate generated",
        certificate_serial=certificate["serialNumber"],
    )
    db.commit()
    return {
        "privateKeyPem": private_key_pem,
        "publicKeyPem": public_key_pem,
        "certificate": certificate,
    }


@app.post("/api/documents/hash")
async def hash_document(file: UploadFile = File(...), hashAlgorithm: str = Form("SHA-256")):
    try:
        normalized_hash_algorithm = normalize_hash_algorithm(hashAlgorithm)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Unsupported hash algorithm") from exc

    content = await file.read()
    return {
        "documentName": file.filename,
        "hashAlgorithm": normalized_hash_algorithm,
        "documentHash": hash_bytes(content, normalized_hash_algorithm),
    }


@app.post(
    "/api/sign",
    response_model=SignedPackage,
    summary="[LEGACY INSECURE DEMO] Sign document - backend receives private key",
    description="This endpoint receives the user's private key. Use /api/sign/v2/* for client-side signing.",
)
async def sign_document(
    file: UploadFile = File(...),
    privateKeyPem: str = Form(...),
    certificate: str = Form(...),
    hashAlgorithm: str = Form("SHA-256"),
    db: Session = Depends(get_db),
):
    try:
        normalized_hash_algorithm = normalize_hash_algorithm(hashAlgorithm)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Unsupported hash algorithm") from exc

    certificate_obj = read_json_form(certificate, "certificate")
    try:
        certificate_model = Certificate.model_validate(certificate_obj)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Malformed certificate") from exc

    if not verify_certificate_signature(certificate_model.model_dump()):
        raise HTTPException(status_code=400, detail="Certificate is not signed by SecureDoc Demo CA")

    record = db.get(CertificateRecord, certificate_model.serialNumber)
    if not record:
        raise HTTPException(status_code=400, detail="Unknown certificate serial number")
    if record.status != "valid":
        raise HTTPException(status_code=400, detail="Certificate is revoked")

    content = await file.read()
    document_hash = hash_bytes(content, normalized_hash_algorithm)
    try:
        signature = sign_hash(document_hash, privateKeyPem, normalized_hash_algorithm)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail="Invalid private key PEM") from exc

    if not verify_signature(document_hash, signature, certificate_model.publicKeyPem, normalized_hash_algorithm):
        raise HTTPException(status_code=400, detail="Private key does not match certificate public key")

    return {
        "documentName": file.filename,
        "documentHash": document_hash,
        "hashAlgorithm": normalized_hash_algorithm,
        "signatureAlgorithm": "RSA-PSS",
        "signatureBase64": signature,
        "signedAt": isoformat(utc_now()),
        "certificate": certificate_model.model_dump(),
    }


@app.post("/api/verify", response_model=VerifyResponse)
async def verify_document(
    file: UploadFile = File(...),
    signedPackage: str = Form(...),
    db: Session = Depends(get_db),
):
    package_obj = read_json_form(signedPackage, "signed package")
    try:
        package = SignedPackage.model_validate(package_obj)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Malformed signed package") from exc

    content = await file.read()
    try:
        normalized_hash_algorithm = normalize_hash_algorithm(package.hashAlgorithm)
    except ValueError:
        details = {
            "hashMatches": False,
            "certificateStatusInPackage": package.certificate.status,
            "certificateStatusFromServer": None,
            "certificateExpiresAt": package.certificate.expiresAt,
            "caSignatureValid": False,
            "revocationSource": "server database",
            "signatureAlgorithm": package.signatureAlgorithm,
            "hashAlgorithm": package.hashAlgorithm,
            "verificationSteps": [
                {
                    "step": "Check declared algorithms",
                    "status": "failed",
                    "message": f"Unsupported hash algorithm: {package.hashAlgorithm}",
                }
            ],
        }
        return _invalid("unsupported algorithm", package, "", details)

    current_hash = hash_bytes(content, normalized_hash_algorithm)
    cert = package.certificate
    cert_obj = cert.model_dump()
    details = {
        "hashMatches": current_hash == package.documentHash,
        "certificateStatusInPackage": cert.status,
        "certificateStatusFromServer": None,
        "certificateExpiresAt": cert.expiresAt,
        "caSignatureValid": False,
        "revocationSource": "server database",
        "signatureAlgorithm": package.signatureAlgorithm,
        "hashAlgorithm": normalized_hash_algorithm,
        "verificationSteps": [],
    }

    if package.signatureAlgorithm != "RSA-PSS":
        _add_step(details, "Check declared algorithms", "failed", "Only RSA-PSS signatures are supported in this demo.")
        return _invalid("unsupported algorithm", package, current_hash, details)
    _add_step(
        details,
        "Check declared algorithms",
        "passed",
        f"Using {normalized_hash_algorithm} for the document digest and RSA-PSS for the signature.",
    )

    if current_hash != package.documentHash:
        _add_step(
            details,
            "Recompute document hash",
            "failed",
            "The uploaded document hash does not match the hash stored in the signed package.",
        )
        return _invalid("document modified", package, current_hash, details)
    _add_step(
        details,
        "Recompute document hash",
        "passed",
        "The uploaded document matches the signed document hash.",
    )

    ca_signature_ok = verify_certificate_signature(cert_obj)
    details["caSignatureValid"] = ca_signature_ok
    if not ca_signature_ok:
        _add_step(
            details,
            "Verify certificate CA signature",
            "failed",
            "The certificate contents are not signed by SecureDoc Demo CA.",
        )
        return _invalid("certificate not issued by demo CA", package, current_hash, details)
    _add_step(
        details,
        "Verify certificate CA signature",
        "passed",
        "The certificate identity and public key are protected by the Demo CA signature.",
    )

    record = db.get(CertificateRecord, cert.serialNumber)
    if not record:
        details["certificateStatusFromServer"] = "unknown"
        _add_step(
            details,
            "Lookup certificate on server",
            "failed",
            "No certificate record exists for this serial number.",
        )
        return _invalid("unknown certificate serial number", package, current_hash, details)

    details["certificateStatusFromServer"] = record.status
    _add_step(
        details,
        "Lookup certificate on server",
        "passed",
        f"Server record found with status '{record.status}'.",
    )
    if (
        record.owner_name != cert.ownerName
        or record.email != cert.email
        or record.public_key_pem != cert.publicKeyPem
        or record.issuer != cert.issuer
    ):
        _add_step(
            details,
            "Compare certificate with server record",
            "failed",
            "Certificate fields do not match the trusted server record.",
        )
        return _invalid("certificate record mismatch", package, current_hash, details)
    _add_step(
        details,
        "Compare certificate with server record",
        "passed",
        "Certificate identity and public key match the trusted server record.",
    )

    try:
        expires_at = parse_iso_datetime(cert.expiresAt)
    except ValueError:
        _add_step(details, "Check certificate validity period", "failed", "Certificate expiration is malformed.")
        return _invalid("malformed certificate", package, current_hash, details)

    if expires_at < utc_now():
        _add_step(details, "Check certificate validity period", "failed", "Certificate has expired.")
        return _invalid("certificate expired", package, current_hash, details)
    _add_step(details, "Check certificate validity period", "passed", "Certificate is still within its validity period.")

    if record.status != "valid":
        _add_step(details, "Check certificate revocation", "failed", "Server database marks this certificate as revoked.")
        return _invalid("certificate revoked", package, current_hash, details)
    _add_step(details, "Check certificate revocation", "passed", "Server database marks this certificate as valid.")

    try:
        signature_ok = verify_signature(
            package.documentHash,
            package.signatureBase64,
            cert.publicKeyPem,
            normalized_hash_algorithm,
        )
    except (ValueError, TypeError):
        signature_ok = False

    details["signatureValid"] = signature_ok
    if not signature_ok:
        _add_step(
            details,
            "Verify document signature",
            "failed",
            "RSA-PSS verification failed with the public key in the certificate.",
        )
        return _invalid("invalid signature or public key mismatch", package, current_hash, details)
    _add_step(
        details,
        "Verify document signature",
        "passed",
        "RSA-PSS verification succeeded with the public key in the certificate.",
    )

    return {
        "valid": True,
        "reason": "signature valid",
        "signer": {"name": cert.ownerName, "email": cert.email, "serialNumber": cert.serialNumber},
        "documentHash": current_hash,
        "signedAt": package.signedAt,
        "details": details,
    }


def _invalid(reason: str, package: SignedPackage, document_hash: str, details: Dict[str, Any]) -> Dict[str, Any]:
    cert = package.certificate
    return {
        "valid": False,
        "reason": reason,
        "signer": {"name": cert.ownerName, "email": cert.email, "serialNumber": cert.serialNumber},
        "documentHash": document_hash,
        "signedAt": package.signedAt,
        "details": details,
    }


def _add_step(details: Dict[str, Any], step: str, status: str, message: str) -> None:
    details["verificationSteps"].append({"step": step, "status": status, "message": message})


@app.post("/api/certificates/revoke")
def revoke_certificate(payload: RevokeCertificateRequest, db: Session = Depends(get_db)):
    certificate = payload.certificate.model_dump()
    if not verify_certificate_signature(certificate):
        raise HTTPException(status_code=400, detail="Certificate is not signed by SecureDoc Demo CA")

    record = db.get(CertificateRecord, certificate["serialNumber"])
    if not record:
        raise HTTPException(status_code=404, detail="Unknown certificate serial number")

    certificate["status"] = "revoked"
    record.status = "revoked"
    now = utc_now()
    db.add(
        CertificateRevocation(
            serial_number=certificate["serialNumber"],
            reason=payload.reason,
            revoked_at=now.replace(tzinfo=None),
            revoked_by=payload.revokedBy,
        )
    )
    log_audit(
        db,
        "certificate_revoked",
        payload.revokedBy or certificate.get("email"),
        "success",
        details=f"reason={payload.reason}",
        certificate_serial=certificate["serialNumber"],
    )
    db.commit()
    return {"certificate": certificate, "reason": payload.reason, "revokedAt": isoformat(now)}


@app.post("/api/blind-signature/demo")
def blind_signature_demo(payload: BlindSignatureDemoRequest):
    if not payload.message.strip():
        raise HTTPException(status_code=400, detail="Message must not be empty")
    return rsa_blind_signature_demo(payload.message)

