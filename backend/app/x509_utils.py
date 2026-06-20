"""X.509 demo CA helpers for SecureDoc.

The certificates in this module are for local educational use only. They model
Root CA -> Intermediate CA -> user signing certificate, but they are not backed
by a public trust store or production key custody.
"""

import binascii
import base64
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from .config import ensure_demo_plaintext_keys_allowed, ensure_runtime_secrets_dir
from .crypto_utils import ALGORITHM_POLICY, get_public_key_size, isoformat, utc_now

X509_ROOT_COMMON_NAME = "SecureDoc Demo Root CA"
X509_INTERMEDIATE_COMMON_NAME = "SecureDoc Demo Intermediate CA"
X509_CERTIFICATE_TYPE = "x509-demo"
TRUSTED_DEMO_ROOT_ID = "securedoc-demo-root"

X509_ROOT_KEY_PATH = ensure_runtime_secrets_dir() / "securedoc_demo_x509_root_private.pem"
X509_ROOT_CERT_PATH = ensure_runtime_secrets_dir() / "securedoc_demo_x509_root_cert.pem"
X509_INTERMEDIATE_KEY_PATH = ensure_runtime_secrets_dir() / "securedoc_demo_x509_intermediate_private.pem"
X509_INTERMEDIATE_CERT_PATH = ensure_runtime_secrets_dir() / "securedoc_demo_x509_intermediate_cert.pem"
TSA_PRIVATE_KEY_PATH = ensure_runtime_secrets_dir() / "securedoc_demo_tsa_private.pem"

DEMO_SIGNATURE_ALGORITHM = "RSA-PSS-SHA256"
DEMO_TSA_NAME = "SecureDoc Demo TSA"


@dataclass
class X509CertificateDetails:
    serial_number: str
    owner_name: str
    email: str
    public_key_pem: str
    issuer: str
    issued_at: datetime
    expires_at: datetime
    fingerprint_sha256: str


def _name(common_name: str, email: str | None = None) -> x509.Name:
    attributes = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureDoc Demo"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ]
    if email:
        attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
    return x509.Name(attributes)


def _new_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=ALGORITHM_POLICY["defaultRsaKeyBits"],
    )


def _private_key_pem(private_key: rsa.RSAPrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _cert_pem(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def _load_private_key(path: Path) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("Demo CA private key must be RSA")
    return key


def _load_certificate(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def _public_key_pem(public_key: Any) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def _serial_hex(certificate: x509.Certificate) -> str:
    return format(certificate.serial_number, "X")


def _fingerprint_sha256(certificate: x509.Certificate) -> str:
    return binascii.hexlify(certificate.fingerprint(hashes.SHA256())).decode("ascii")


def _canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign_demo_payload(private_key: rsa.RSAPrivateKey, payload: dict[str, Any]) -> str:
    signature = private_key.sign(
        _canonical_json(payload),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("ascii")


def _verify_demo_payload(public_key: Any, payload: dict[str, Any], signature_base64: str) -> None:
    public_key.verify(
        base64.b64decode(signature_base64),
        _canonical_json(payload),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
        hashes.SHA256(),
    )


def _ca_key_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=None,
        decipher_only=None,
    )


def _user_key_usage(
    digital_signature: bool = True,
    content_commitment: bool = True,
) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=digital_signature,
        content_commitment=content_commitment,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=None,
        decipher_only=None,
    )


def _build_root_ca(private_key: rsa.RSAPrivateKey) -> x509.Certificate:
    now = utc_now()
    subject = _name(X509_ROOT_COMMON_NAME)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(_ca_key_usage(), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
    )
    return builder.sign(private_key=private_key, algorithm=hashes.SHA256())


def _build_intermediate_ca(
    intermediate_key: rsa.RSAPrivateKey,
    root_key: rsa.RSAPrivateKey,
    root_cert: x509.Certificate,
) -> x509.Certificate:
    now = utc_now()
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(X509_INTERMEDIATE_COMMON_NAME))
        .issuer_name(root_cert.subject)
        .public_key(intermediate_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_ca_key_usage(), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(intermediate_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
    )
    return builder.sign(private_key=root_key, algorithm=hashes.SHA256())


def ensure_demo_x509_ca() -> tuple[str, str]:
    ensure_demo_plaintext_keys_allowed()
    if X509_ROOT_KEY_PATH.exists() and X509_ROOT_CERT_PATH.exists():
        root_key = _load_private_key(X509_ROOT_KEY_PATH)
        root_cert = _load_certificate(X509_ROOT_CERT_PATH)
    else:
        root_key = _new_private_key()
        root_cert = _build_root_ca(root_key)
        X509_ROOT_KEY_PATH.write_bytes(_private_key_pem(root_key))
        X509_ROOT_CERT_PATH.write_bytes(root_cert.public_bytes(serialization.Encoding.PEM))

    if X509_INTERMEDIATE_KEY_PATH.exists() and X509_INTERMEDIATE_CERT_PATH.exists():
        intermediate_cert = _load_certificate(X509_INTERMEDIATE_CERT_PATH)
    else:
        intermediate_key = _new_private_key()
        intermediate_cert = _build_intermediate_ca(intermediate_key, root_key, root_cert)
        X509_INTERMEDIATE_KEY_PATH.write_bytes(_private_key_pem(intermediate_key))
        X509_INTERMEDIATE_CERT_PATH.write_bytes(intermediate_cert.public_bytes(serialization.Encoding.PEM))

    return _cert_pem(intermediate_cert), _cert_pem(root_cert)


def issue_user_x509_certificate(
    name: str,
    email: str,
    public_key_pem: str,
    *,
    validity_days: int = 365,
    digital_signature_usage: bool = True,
    content_commitment_usage: bool = True,
) -> dict[str, Any]:
    if not name.strip():
        raise ValueError("name is required")

    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Only RSA public keys are supported")
    if get_public_key_size(public_key_pem) < ALGORITHM_POLICY["minimumRsaKeyBits"]:
        raise ValueError("RSA key size is below policy minimum")

    ensure_demo_x509_ca()
    intermediate_key = _load_private_key(X509_INTERMEDIATE_KEY_PATH)
    intermediate_cert = _load_certificate(X509_INTERMEDIATE_CERT_PATH)
    root_cert = _load_certificate(X509_ROOT_CERT_PATH)

    now = utc_now()
    if validity_days <= 0:
        not_before = now - timedelta(days=2)
        not_after = now - timedelta(days=1)
    else:
        not_before = now - timedelta(minutes=5)
        not_after = now + timedelta(days=validity_days)
    user_cert = (
        x509.CertificateBuilder()
        .subject_name(_name(name.strip(), email))
        .issuer_name(intermediate_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_user_key_usage(digital_signature_usage, content_commitment_usage), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(intermediate_key.public_key()),
            critical=False,
        )
        .sign(private_key=intermediate_key, algorithm=hashes.SHA256())
    )

    user_certificate_pem = _cert_pem(user_cert)
    intermediate_certificate_pem = _cert_pem(intermediate_cert)
    root_certificate_pem = _cert_pem(root_cert)
    fingerprint = _fingerprint_sha256(user_cert)
    serial_number = _serial_hex(user_cert)

    return {
        "userCertificatePem": user_certificate_pem,
        "intermediateCertificatePem": intermediate_certificate_pem,
        "rootCertificatePem": root_certificate_pem,
        "certificateSerialNumber": serial_number,
        "certificateFingerprint": fingerprint,
        "certificateType": X509_CERTIFICATE_TYPE,
        "certificate": {
            "serialNumber": serial_number,
            "ownerName": name.strip(),
            "email": email,
            "publicKeyPem": _public_key_pem(public_key),
            "issuer": X509_INTERMEDIATE_COMMON_NAME,
            "issuedAt": isoformat(not_before),
            "expiresAt": isoformat(not_after),
            "status": "valid",
            "certificateType": X509_CERTIFICATE_TYPE,
            "certificateFingerprint": fingerprint,
            "userCertificatePem": user_certificate_pem,
            "intermediateCertificatePem": intermediate_certificate_pem,
            "rootCertificatePem": root_certificate_pem,
        },
    }


def _verify_cert_signature(certificate: x509.Certificate, issuer_public_key: Any) -> None:
    issuer_public_key.verify(
        certificate.signature,
        certificate.tbs_certificate_bytes,
        padding.PKCS1v15(),
        certificate.signature_hash_algorithm,
    )


def _extension(certificate: x509.Certificate, oid: ExtensionOID) -> Any:
    return certificate.extensions.get_extension_for_oid(oid).value


def _common_name(name: x509.Name) -> str:
    attributes = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attributes[0].value if attributes else ""


def _email(name: x509.Name) -> str:
    attributes = name.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
    return attributes[0].value if attributes else ""


def parse_user_x509_details(user_certificate_pem: str) -> X509CertificateDetails:
    certificate = x509.load_pem_x509_certificate(user_certificate_pem.encode("utf-8"))
    return X509CertificateDetails(
        serial_number=_serial_hex(certificate),
        owner_name=_common_name(certificate.subject),
        email=_email(certificate.subject),
        public_key_pem=_public_key_pem(certificate.public_key()),
        issuer=_common_name(certificate.issuer),
        issued_at=certificate.not_valid_before_utc.astimezone(timezone.utc),
        expires_at=certificate.not_valid_after_utc.astimezone(timezone.utc),
        fingerprint_sha256=_fingerprint_sha256(certificate),
    )


def verify_demo_x509_chain(
    user_certificate_pem: str,
    intermediate_certificate_pem: str,
    root_certificate_pem: str,
) -> tuple[bool, str]:
    try:
        user_cert = x509.load_pem_x509_certificate(user_certificate_pem.encode("utf-8"))
        intermediate_cert = x509.load_pem_x509_certificate(intermediate_certificate_pem.encode("utf-8"))
        root_cert = x509.load_pem_x509_certificate(root_certificate_pem.encode("utf-8"))

        ensure_demo_x509_ca()
        trusted_root_cert = _load_certificate(X509_ROOT_CERT_PATH)
        if _fingerprint_sha256(root_cert) != _fingerprint_sha256(trusted_root_cert):
            return False, "Root certificate is not the trusted SecureDoc demo root"
        if _common_name(root_cert.subject) != X509_ROOT_COMMON_NAME or root_cert.issuer != root_cert.subject:
            return False, "Root certificate is not the SecureDoc demo root CA"
        if _common_name(intermediate_cert.subject) != X509_INTERMEDIATE_COMMON_NAME:
            return False, "Intermediate certificate is not the SecureDoc demo intermediate CA"
        if user_cert.issuer != intermediate_cert.subject or intermediate_cert.issuer != root_cert.subject:
            return False, "Certificate issuer chain does not match"

        _verify_cert_signature(root_cert, root_cert.public_key())
        _verify_cert_signature(intermediate_cert, root_cert.public_key())
        _verify_cert_signature(user_cert, intermediate_cert.public_key())

        for ca_cert in (root_cert, intermediate_cert):
            basic_constraints = _extension(ca_cert, ExtensionOID.BASIC_CONSTRAINTS)
            key_usage = _extension(ca_cert, ExtensionOID.KEY_USAGE)
            if not basic_constraints.ca:
                return False, "CA certificate BasicConstraints is not CA=true"
            if not key_usage.key_cert_sign or not key_usage.crl_sign:
                return False, "CA certificate KeyUsage must include keyCertSign and cRLSign"

        user_constraints = _extension(user_cert, ExtensionOID.BASIC_CONSTRAINTS)
        user_key_usage = _extension(user_cert, ExtensionOID.KEY_USAGE)
        _extension(user_cert, ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        _extension(user_cert, ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        if user_constraints.ca:
            return False, "User certificate BasicConstraints must be CA=false"
        if not user_key_usage.digital_signature or not user_key_usage.content_commitment:
            return False, "User certificate KeyUsage must include digitalSignature and contentCommitment"
        if user_key_usage.key_cert_sign or user_key_usage.crl_sign:
            return False, "User signing certificate must not be allowed to sign certificates or CRLs"

        now = utc_now()
        for certificate in (intermediate_cert, root_cert):
            if certificate.not_valid_before_utc > now or certificate.not_valid_after_utc < now:
                return False, "CA certificate chain is outside its validity period"

        return True, "X.509 demo chain is valid"
    except (ValueError, InvalidSignature, x509.ExtensionNotFound, TypeError) as exc:
        return False, f"Invalid X.509 demo chain: {exc}"


def build_signed_demo_crl(revoked_certificates: list[dict[str, Any]]) -> dict[str, Any]:
    ensure_demo_x509_ca()
    intermediate_key = _load_private_key(X509_INTERMEDIATE_KEY_PATH)
    now = utc_now()
    crl_payload = {
        "issuer": X509_INTERMEDIATE_COMMON_NAME,
        "thisUpdate": isoformat(now),
        "nextUpdate": isoformat(now + timedelta(hours=24)),
        "revokedCertificates": revoked_certificates,
        "signatureAlgorithm": DEMO_SIGNATURE_ALGORITHM,
    }
    crl_payload["signatureBase64"] = _sign_demo_payload(intermediate_key, crl_payload)
    return crl_payload


def verify_signed_demo_crl(crl: dict[str, Any]) -> tuple[bool, str]:
    try:
        signature_base64 = str(crl["signatureBase64"])
        payload = {key: crl[key] for key in ("issuer", "thisUpdate", "nextUpdate", "revokedCertificates", "signatureAlgorithm")}
        if payload["issuer"] != X509_INTERMEDIATE_COMMON_NAME:
            return False, "CRL issuer is not the SecureDoc demo intermediate CA"
        if payload["signatureAlgorithm"] != DEMO_SIGNATURE_ALGORITHM:
            return False, "Unsupported CRL signature algorithm"
        parse_time = datetime.fromisoformat(str(payload["thisUpdate"]).replace("Z", "+00:00"))
        next_update = datetime.fromisoformat(str(payload["nextUpdate"]).replace("Z", "+00:00"))
        if parse_time.tzinfo is None:
            parse_time = parse_time.replace(tzinfo=timezone.utc)
        if next_update.tzinfo is None:
            next_update = next_update.replace(tzinfo=timezone.utc)
        if next_update.astimezone(timezone.utc) < utc_now():
            return False, "CRL is expired"

        ensure_demo_x509_ca()
        intermediate_cert = _load_certificate(X509_INTERMEDIATE_CERT_PATH)
        _verify_demo_payload(intermediate_cert.public_key(), payload, signature_base64)
        return True, "Signed demo CRL is valid"
    except (KeyError, ValueError, TypeError, InvalidSignature, binascii.Error) as exc:
        return False, f"Invalid signed demo CRL: {exc}"


def ensure_demo_tsa_key() -> rsa.RSAPrivateKey:
    ensure_demo_plaintext_keys_allowed()
    if TSA_PRIVATE_KEY_PATH.exists():
        return _load_private_key(TSA_PRIVATE_KEY_PATH)
    private_key = _new_private_key()
    TSA_PRIVATE_KEY_PATH.write_bytes(_private_key_pem(private_key))
    return private_key


def issue_timestamp_token(message_imprint: str, hash_algorithm: str = "SHA-256", nonce: str | None = None) -> dict[str, Any]:
    private_key = ensure_demo_tsa_key()
    token = {
        "tokenVersion": "1.0",
        "messageImprint": message_imprint,
        "hashAlgorithm": hash_algorithm,
        "timestamp": isoformat(utc_now()),
        "tsaName": DEMO_TSA_NAME,
        "serialNumber": secrets.token_hex(12).upper(),
        "signatureAlgorithm": DEMO_SIGNATURE_ALGORITHM,
    }
    if nonce:
        token["nonce"] = nonce
    token["signatureBase64"] = _sign_demo_payload(private_key, token)
    return token


def verify_timestamp_token(
    token: dict[str, Any],
    expected_message_imprint: str,
    expected_nonce: str | None = None,
) -> tuple[bool, str]:
    try:
        signature_base64 = str(token["signatureBase64"])
        payload = {
            key: token[key]
            for key in (
                "tokenVersion",
                "messageImprint",
                "hashAlgorithm",
                "timestamp",
                "tsaName",
                "serialNumber",
                "signatureAlgorithm",
            )
        }
        if "nonce" in token:
            payload["nonce"] = token["nonce"]
        if payload["tokenVersion"] != "1.0":
            return False, "Unsupported timestamp token version"
        if payload["messageImprint"] != expected_message_imprint:
            return False, "Timestamp token messageImprint mismatch"
        if expected_nonce is not None and payload.get("nonce") != expected_nonce:
            return False, "Timestamp token nonce mismatch"
        if payload["hashAlgorithm"] != "SHA-256":
            return False, "Unsupported timestamp hash algorithm"
        if payload["tsaName"] != DEMO_TSA_NAME:
            return False, "Unknown demo TSA"
        if payload["signatureAlgorithm"] != DEMO_SIGNATURE_ALGORITHM:
            return False, "Unsupported timestamp signature algorithm"
        datetime.fromisoformat(str(payload["timestamp"]).replace("Z", "+00:00"))

        tsa_key = ensure_demo_tsa_key()
        _verify_demo_payload(tsa_key.public_key(), payload, signature_base64)
        return True, "Demo timestamp token is valid"
    except (KeyError, ValueError, TypeError, InvalidSignature, binascii.Error) as exc:
        return False, f"Invalid timestamp token: {exc}"
