"""Pydantic schemas — legacy (unchanged) + v2 client-side signing."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, EmailStr, Field


# ── Legacy schemas (backward-compatible) ──────────────────────────────────

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
    reason: str = "unspecified"
    revokedBy: Optional[str] = None


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


# ── V2 schemas ────────────────────────────────────────────────────────────

class SigningPayloadV2(BaseModel):
    documentName: str
    documentHash: str
    hashAlgorithm: str
    signatureAlgorithm: str = "RSA-PSS"
    signerName: str
    signerEmail: str
    certificateSerialNumber: str
    certificateFingerprint: str
    signingPurpose: str = "approve_document"
    createdAt: str
    nonce: str
    requestId: str
    payloadVersion: str = "1.0"


class SigningRequestCreateV2(BaseModel):
    documentName: str
    documentHash: str
    hashAlgorithm: str = "SHA-256"
    certificateSerialNumber: str
    signingPurpose: str = "approve_document"


class SigningRequestResponseV2(BaseModel):
    requestId: str
    nonce: str
    signingPayload: SigningPayloadV2
    canonicalPayloadBase64: str
    warnings: List[str] = Field(default_factory=list)


class SignedPackageV2(BaseModel):
    packageVersion: str = "2.0"
    signingPayload: SigningPayloadV2
    payloadCanonicalization: str = "JSON-canonical-sorted-keys"
    signatureAlgorithm: str = "RSA-PSS"
    signatureBase64: str
    signerCertificate: Certificate
    signedAtClient: Optional[str] = None


class VerificationReportV2(BaseModel):
    documentIntegrity: str
    signingPayloadValid: str
    signatureValid: str
    certificateParsed: str
    certificateTrusted: str
    certificateType: str
    certificateChainValid: str
    certificateValidityPeriod: str
    certificateRevocationStatus: str
    keyUsageValid: str
    algorithmPolicyValid: str
    replayCheck: str
    timestampStatus: str
    finalDecision: str
    warnings: List[str] = Field(default_factory=list)
    verificationSteps: List[Dict[str, str]] = Field(default_factory=list)


class VerifyResponseV2(BaseModel):
    valid: bool
    reason: str
    signer: Optional[Dict[str, Any]]
    documentHash: str
    signedAt: Optional[str]
    report: VerificationReportV2


class RevokeBySerialRequest(BaseModel):
    serialNumber: str
    reason: str = "unspecified"
    revokedBy: Optional[str] = None


class CertificateStatusResponse(BaseModel):
    serialNumber: str
    status: str
    reason: Optional[str] = None
    revokedAt: Optional[str] = None
    expiresAt: Optional[str] = None
