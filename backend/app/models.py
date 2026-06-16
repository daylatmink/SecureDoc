"""SQLAlchemy models for SecureDoc — legacy + v2 tables."""

from sqlalchemy import Column, DateTime, Integer, String, Text

from .database import Base


class CertificateRecord(Base):
    __tablename__ = "certificates"

    serial_number = Column(String, primary_key=True, index=True)
    owner_name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    public_key_pem = Column(Text, nullable=False)
    issuer = Column(String, nullable=False)
    issued_at = Column(DateTime, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    status = Column(String, nullable=False, default="valid")
    # v2 fields
    certificate_type = Column(String, nullable=False, default="legacy-demo")
    fingerprint_sha256 = Column(String, nullable=True)
    key_size_bits = Column(Integer, nullable=True)


class SigningRequest(Base):
    __tablename__ = "signing_requests"

    request_id = Column(String, primary_key=True, index=True)
    document_name = Column(String, nullable=False)
    document_hash = Column(String, nullable=False)
    hash_algorithm = Column(String, nullable=False)
    signer_name = Column(String, nullable=False)
    signer_email = Column(String, nullable=False)
    certificate_serial = Column(String, nullable=False)
    signing_purpose = Column(String, nullable=False, default="approve_document")
    nonce = Column(String, nullable=False)
    status = Column(String, nullable=False, default="pending")
    created_at = Column(DateTime, nullable=False)
    completed_at = Column(DateTime, nullable=True)


class SignatureRecord(Base):
    __tablename__ = "signatures"

    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(String, nullable=False, index=True)
    document_name = Column(String, nullable=False)
    document_hash = Column(String, nullable=False)
    hash_algorithm = Column(String, nullable=False)
    signature_algorithm = Column(String, nullable=False)
    signature_base64 = Column(Text, nullable=False)
    signer_name = Column(String, nullable=False)
    signer_email = Column(String, nullable=False)
    certificate_serial = Column(String, nullable=False)
    signing_purpose = Column(String, nullable=False)
    signed_at_client = Column(String, nullable=True)
    received_at_server = Column(DateTime, nullable=False)
    verification_result = Column(String, nullable=False)
    signed_package_json = Column(Text, nullable=False)


class CertificateRevocation(Base):
    __tablename__ = "certificate_revocations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    serial_number = Column(String, nullable=False, index=True)
    reason = Column(String, nullable=False, default="unspecified")
    revoked_at = Column(DateTime, nullable=False)
    revoked_by = Column(String, nullable=True)
    details = Column(Text, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String, nullable=False, unique=True, index=True)
    event_type = Column(String, nullable=False, index=True)
    actor = Column(String, nullable=True)
    document_hash = Column(String, nullable=True)
    certificate_serial = Column(String, nullable=True)
    result = Column(String, nullable=False)
    details = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False)
    previous_log_hash = Column(String, nullable=True)
    current_log_hash = Column(String, nullable=False)


class UsedNonce(Base):
    __tablename__ = "used_nonces"

    nonce = Column(String, primary_key=True, index=True)
    request_id = Column(String, nullable=False)
    used_at = Column(DateTime, nullable=False)
