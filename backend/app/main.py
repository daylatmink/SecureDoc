import json
from datetime import timezone
from typing import Any, Dict

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .crypto_utils import (
    create_demo_certificate,
    generate_key_pair,
    isoformat,
    parse_iso_datetime,
    sha256_hex,
    sign_hash,
    utc_now,
    verify_signature,
)
from .database import SessionLocal, init_db
from .models import CertificateRecord
from .schemas import (
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


@app.on_event("startup")
def on_startup() -> None:
    init_db()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def read_json_form(value: str, field_name: str) -> Dict[str, Any]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Malformed {field_name} JSON") from exc
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=400, detail=f"{field_name} must be a JSON object")
    return parsed


@app.post("/api/keys/generate", response_model=KeyGenerateResponse)
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
    )
    db.add(record)
    db.commit()
    return {
        "privateKeyPem": private_key_pem,
        "publicKeyPem": public_key_pem,
        "certificate": certificate,
    }


@app.post("/api/documents/hash")
async def hash_document(file: UploadFile = File(...)):
    content = await file.read()
    return {"documentName": file.filename, "hashAlgorithm": "SHA-256", "documentHash": sha256_hex(content)}


@app.post("/api/sign", response_model=SignedPackage)
async def sign_document(
    file: UploadFile = File(...),
    privateKeyPem: str = Form(...),
    certificate: str = Form(...),
):
    certificate_obj = read_json_form(certificate, "certificate")
    content = await file.read()
    document_hash = sha256_hex(content)
    try:
        signature = sign_hash(document_hash, privateKeyPem)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail="Invalid private key PEM") from exc
    return {
        "documentName": file.filename,
        "documentHash": document_hash,
        "hashAlgorithm": "SHA-256",
        "signatureAlgorithm": "RSA-PSS",
        "signatureBase64": signature,
        "signedAt": isoformat(utc_now()),
        "certificate": certificate_obj,
    }


@app.post("/api/verify", response_model=VerifyResponse)
async def verify_document(file: UploadFile = File(...), signedPackage: str = Form(...)):
    package_obj = read_json_form(signedPackage, "signed package")
    try:
        package = SignedPackage.model_validate(package_obj)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Malformed signed package") from exc

    content = await file.read()
    current_hash = sha256_hex(content)
    cert = package.certificate
    details = {
        "hashMatches": current_hash == package.documentHash,
        "certificateStatus": cert.status,
        "certificateExpiresAt": cert.expiresAt,
        "signatureAlgorithm": package.signatureAlgorithm,
        "hashAlgorithm": package.hashAlgorithm,
    }

    if package.hashAlgorithm != "SHA-256" or package.signatureAlgorithm != "RSA-PSS":
        return _invalid("unsupported algorithm", package, current_hash, details)

    if current_hash != package.documentHash:
        return _invalid("document modified", package, current_hash, details)

    try:
        expires_at = parse_iso_datetime(cert.expiresAt)
    except ValueError:
        return _invalid("malformed certificate", package, current_hash, details)

    if expires_at < utc_now():
        return _invalid("certificate expired", package, current_hash, details)

    if cert.status != "valid":
        return _invalid("certificate revoked", package, current_hash, details)

    try:
        signature_ok = verify_signature(package.documentHash, package.signatureBase64, cert.publicKeyPem)
    except (ValueError, TypeError):
        signature_ok = False

    details["signatureValid"] = signature_ok
    if not signature_ok:
        return _invalid("invalid signature or public key mismatch", package, current_hash, details)

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


@app.post("/api/certificates/revoke")
def revoke_certificate(payload: RevokeCertificateRequest, db: Session = Depends(get_db)):
    certificate = payload.certificate.model_dump()
    certificate["status"] = "revoked"
    record = db.get(CertificateRecord, certificate["serialNumber"])
    if record:
        record.status = "revoked"
        db.commit()
    return {"certificate": certificate}

