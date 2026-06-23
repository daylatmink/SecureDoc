"""Pydantic schemas — legacy (unchanged) + v2 client-side signing."""

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field


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
    certificateType: str = "legacy-demo"
    certificateFingerprint: Optional[str] = None
    userCertificatePem: Optional[str] = None
    intermediateCertificatePem: Optional[str] = None
    rootCertificatePem: Optional[str] = None
    caSignatureAlgorithm: Optional[str] = None
    caSignatureBase64: Optional[str] = None


class KeyGenerateResponse(BaseModel):
    privateKeyPem: str
    publicKeyPem: str
    certificate: Certificate
    warning: Optional[str] = None


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
    warning: Optional[str] = None


class VerifyResponse(BaseModel):
    valid: bool
    reason: str
    signer: Optional[Dict[str, Any]]
    documentHash: str
    signedAt: Optional[str]
    details: Dict[str, Any]
    warning: Optional[str] = None


class CaPublicKeyResponse(BaseModel):
    issuer: str
    publicKeyPem: str
    signatureAlgorithm: str
    warning: Optional[str] = None


class BlindSignatureDemoRequest(BaseModel):
    message: str


class X509CertificateIssueRequest(BaseModel):
    name: str
    email: EmailStr
    publicKeyPem: str
    proofChallenge: str
    proofSignatureBase64: str


class X509ProofChallengeRequest(BaseModel):
    name: str
    email: EmailStr
    publicKeyPem: str


class X509ProofChallengeResponse(BaseModel):
    challenge: str
    expiresAt: str
    subjectName: str
    subjectEmail: EmailStr
    publicKeyFingerprint: str
    warning: str


class X509CertificateIssueResponse(BaseModel):
    userCertificatePem: str
    intermediateCertificatePem: str
    rootCertificatePem: str
    certificateSerialNumber: str
    certificateFingerprint: str
    certificateType: str = "x509-demo"
    certificate: Certificate


# ── V2 schemas ────────────────────────────────────────────────────────────

UserRole = Literal["ADMIN", "CA_OFFICER", "SIGNER", "VERIFIER", "AUDITOR"]
UserStatus = Literal["active", "disabled"]


class UserCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    name: str
    role: UserRole
    status: UserStatus = "active"


class UserUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Optional[str] = None
    role: Optional[UserRole] = None
    status: Optional[UserStatus] = None


class UserResponse(BaseModel):
    email: EmailStr
    name: str
    role: UserRole
    status: UserStatus
    createdAt: str
    updatedAt: str


class SigningPayloadV2(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: str = "2.0"
    documentName: str
    documentHash: str
    hashAlgorithm: str
    signatureAlgorithm: str = "RSA-PSS"
    signerName: str
    signerEmail: str
    certificateSerialNumber: str
    certificateFingerprint: str
    certificateType: str = "x509-demo"
    signingPurpose: str = "approve_document"
    signingIntent: str = "I approve and sign this document with SecureDoc."
    createdAt: str
    expiresAt: str
    nonce: str
    requestId: str
    payloadVersion: str = "1.0"
    rsaPssParams: Dict[str, Any] = Field(default_factory=dict)


class SigningRequestCreateV2(BaseModel):
    model_config = ConfigDict(extra="forbid")

    documentName: str
    documentHash: str
    hashAlgorithm: str = "SHA-256"
    certificateSerialNumber: str
    signingPurpose: str = "approve_document"
    signingIntent: str = "I approve and sign this document with SecureDoc."


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
    userCertificatePem: Optional[str] = None
    intermediateCertificatePem: Optional[str] = None
    rootCertificatePem: Optional[str] = None
    trustedRootId: Optional[str] = None
    timestampToken: Optional[Dict[str, Any]] = None
    signerCertificate: Optional[Certificate] = None
    signedAtClient: Optional[str] = None


class VerificationReportV2(BaseModel):
    cryptoValid: bool = False
    documentHashValid: bool = False
    trustedChainValid: bool = False
    revocationValid: bool = False
    timestampValid: bool = False
    serverAccepted: bool = False
    signingRequestConfirmed: bool = False
    confirmationMethod: Optional[str] = None
    legalReady: bool = False
    documentIntegrity: str
    signingPayloadValid: str
    signatureValid: str
    certificateParsed: str
    certificateTrusted: str
    certificateType: str
    certificateChainValid: str
    certificateValidityPeriod: str
    certificateRevocationStatus: str
    revocationSource: str
    keyUsageValid: str
    algorithmPolicyValid: str
    replayCheck: str
    timestampStatus: str
    finalDecision: str
    warnings: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    verificationSteps: List[Dict[str, str]] = Field(default_factory=list)


class VerifyResponseV2(BaseModel):
    valid: bool
    reason: str
    signer: Optional[Dict[str, Any]]
    documentHash: str
    signedAt: Optional[str]
    report: VerificationReportV2


class SigningOtpRequestResponse(BaseModel):
    otpId: int
    requestId: str
    email: EmailStr
    expiresAt: str
    delivery: str
    warning: str


class SigningConfirmRequest(BaseModel):
    method: str
    code: str


class SigningConfirmResponse(BaseModel):
    confirmed: bool
    requestId: str
    status: str
    confirmationMethod: str
    confirmedAt: str


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


class DocumentStoredResponse(BaseModel):
    documentId: str
    ownerEmail: EmailStr
    originalFilename: str
    contentHash: str
    hashAlgorithm: str
    mimeType: str
    sizeBytes: int
    version: int
    previousDocumentId: Optional[str] = None
    immutable: bool = False
    createdAt: str
    updatedAt: str


class DocumentMarkSignedResponse(BaseModel):
    documentId: str
    immutable: bool
    updatedAt: str


class Rfc3161TimestampRequest(BaseModel):
    messageDigestBase64: str
    hashAlgorithm: str = "SHA-256"


class TimestampStatusResponse(BaseModel):
    demoTsaEnabled: bool
    rfc3161Configured: bool
    rfc3161Provider: Optional[str] = None
    legalReady: bool = False
    warning: str


class PadesStatusResponse(BaseModel):
    enabled: bool
    defaultProfile: str
    timestampedProfileAvailable: bool
    rfc3161Configured: bool
    rfc3161Provider: Optional[str] = None
    legalReady: bool = False
    warning: str


class BlindSignatureStatusResponse(BaseModel):
    enabled: bool
    scheme: str
    allowedPurposes: List[str]
    legalReady: bool = False
    warning: str


class SecurityReadinessCheck(BaseModel):
    key: str
    passed: bool
    severity: str
    message: str


class SecurityReadinessResponse(BaseModel):
    environment: str
    productionMode: bool
    corsAllowOrigins: List[str]
    requestSizeLimitBytes: int
    rateLimitRequestsPerMinute: int
    httpsOnly: bool
    checks: List[SecurityReadinessCheck]
    databaseRecommendation: str
    legalReady: bool = False


class Rfc3161TimestampResponse(BaseModel):
    tokenBase64: str
    hashAlgorithm: str
    provider: str
