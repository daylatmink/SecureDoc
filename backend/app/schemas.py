from typing import Any, Dict, Optional

from pydantic import BaseModel, EmailStr


class KeyGenerateRequest(BaseModel):
    name: str
    email: EmailStr


class Certificate(BaseModel):
    serialNumber: str
    ownerName: str
    email: EmailStr
    publicKeyPem: str
    issuer: str
    issuedAt: str
    expiresAt: str
    status: str
    caSignatureAlgorithm: Optional[str] = None
    caSignatureBase64: Optional[str] = None


class KeyGenerateResponse(BaseModel):
    privateKeyPem: str
    publicKeyPem: str
    certificate: Certificate


class RevokeCertificateRequest(BaseModel):
    certificate: Certificate


class SignedPackage(BaseModel):
    documentName: str
    documentHash: str
    hashAlgorithm: str
    signatureAlgorithm: str
    signatureBase64: str
    signedAt: str
    certificate: Certificate


class VerifyResponse(BaseModel):
    valid: bool
    reason: str
    signer: Optional[Dict[str, Any]]
    documentHash: str
    signedAt: Optional[str]
    details: Dict[str, Any]


class CaPublicKeyResponse(BaseModel):
    issuer: str
    publicKeyPem: str
    signatureAlgorithm: str


class BlindSignatureDemoRequest(BaseModel):
    message: str

