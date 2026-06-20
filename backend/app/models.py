"""SQLAlchemy models for SecureDoc — legacy + v2 tables."""

import json

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
    user_certificate_pem = Column(Text, nullable=True)
    intermediate_certificate_pem = Column(Text, nullable=True)
    root_certificate_pem = Column(Text, nullable=True)


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
    confirmation_method = Column(String, nullable=True)
    confirmed_at = Column(DateTime, nullable=True)
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


class DocumentObject(Base):
    __tablename__ = "documents"

    document_id = Column(String, primary_key=True, index=True)
    owner_email = Column(String, nullable=False, index=True)
    original_filename = Column(String, nullable=False)
    content_hash = Column(String, nullable=False, index=True)
    hash_algorithm = Column(String, nullable=False, default="SHA-256")
    mime_type = Column(String, nullable=False)
    storage_path = Column(Text, nullable=False)
    size_bytes = Column(Integer, nullable=False)
    version = Column(Integer, nullable=False, default=1)
    previous_document_id = Column(String, nullable=True, index=True)
    immutable = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)


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


class BlindSignatureSession(Base):
    __tablename__ = "blind_signature_sessions"

    session_id = Column(String, primary_key=True, index=True)
    token_id = Column(String, nullable=False, unique=True, index=True)
    purpose = Column(String, nullable=False, index=True)
    token_json = Column(Text, nullable=False)
    token_hash = Column(String, nullable=False)
    blinded_message_base64 = Column(Text, nullable=False)
    blind_signature_base64 = Column(Text, nullable=True)
    final_signature_base64 = Column(Text, nullable=True)
    status = Column(String, nullable=False, default="created")
    created_at = Column(DateTime, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    spent_at = Column(DateTime, nullable=True)

    @staticmethod
    def dumps_token(token: dict) -> str:
        return json.dumps(token, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    @property
    def token_json_as_dict(self) -> dict:
        return json.loads(self.token_json)


class EmailOtpToken(Base):
    __tablename__ = "email_otp_tokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String, nullable=False, index=True)
    purpose = Column(String, nullable=False, index=True)
    signing_request_id = Column(String, nullable=True, index=True)
    document_hash = Column(String, nullable=True)
    certificate_serial = Column(String, nullable=True)
    signing_purpose = Column(String, nullable=True)
    nonce = Column(String, nullable=True)
    otp_hash = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)
    attempt_count = Column(Integer, nullable=False, default=0)
    max_attempts = Column(Integer, nullable=False, default=5)
    created_at = Column(DateTime, nullable=False)


class UserMfaSetting(Base):
    __tablename__ = "user_mfa_settings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String, nullable=False, unique=True, index=True)
    type = Column(String, nullable=False, default="TOTP")
    secret_encrypted = Column(Text, nullable=False)
    enabled = Column(Integer, nullable=False, default=0)
    verified_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    last_used_at = Column(DateTime, nullable=True)
