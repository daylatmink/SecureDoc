import base64
import binascii
import hashlib
import json
import math
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ISSUER = "SecureDoc Demo CA"
CA_PRIVATE_KEY_PATH = Path(__file__).resolve().parents[1] / "securedoc_demo_ca_private.pem"
CA_PUBLIC_KEY_PATH = Path(__file__).resolve().parents[1] / "securedoc_demo_ca_public.pem"
CERTIFICATE_SIGNATURE_ALGORITHM = "RSA-PSS-SHA256"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def parse_iso_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generate_key_pair() -> Tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


def ensure_demo_ca_keys() -> Tuple[str, str]:
    if CA_PRIVATE_KEY_PATH.exists():
        private_pem = CA_PRIVATE_KEY_PATH.read_bytes()
        private_key = serialization.load_pem_private_key(private_pem, password=None)
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        CA_PRIVATE_KEY_PATH.write_bytes(private_pem)

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if not CA_PUBLIC_KEY_PATH.exists() or CA_PUBLIC_KEY_PATH.read_bytes() != public_pem:
        CA_PUBLIC_KEY_PATH.write_bytes(public_pem)

    return private_pem.decode("utf-8"), public_pem.decode("utf-8")


def get_demo_ca_public_key() -> str:
    _, public_key_pem = ensure_demo_ca_keys()
    return public_key_pem


def certificate_payload_for_signature(certificate: Dict[str, Any]) -> bytes:
    payload = {
        "serialNumber": certificate["serialNumber"],
        "ownerName": certificate["ownerName"],
        "email": certificate["email"],
        "publicKeyPem": certificate["publicKeyPem"],
        "issuer": certificate["issuer"],
        "issuedAt": certificate["issuedAt"],
        "expiresAt": certificate["expiresAt"],
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_certificate(certificate: Dict[str, Any]) -> str:
    private_key_pem, _ = ensure_demo_ca_keys()
    private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    signature = private_key.sign(
        certificate_payload_for_signature(certificate),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("ascii")


def verify_certificate_signature(certificate: Dict[str, Any]) -> bool:
    if certificate.get("issuer") != ISSUER:
        return False
    if certificate.get("caSignatureAlgorithm") != CERTIFICATE_SIGNATURE_ALGORITHM:
        return False
    signature_base64 = certificate.get("caSignatureBase64")
    if not isinstance(signature_base64, str):
        return False

    _, public_key_pem = ensure_demo_ca_keys()
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    try:
        public_key.verify(
            base64.b64decode(signature_base64),
            certificate_payload_for_signature(certificate),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError, binascii.Error):
        return False


def create_demo_certificate(name: str, email: str, public_key_pem: str) -> Dict[str, Any]:
    issued_at = utc_now()
    expires_at = issued_at + timedelta(days=365)
    certificate = {
        "serialNumber": secrets.token_hex(12).upper(),
        "ownerName": name,
        "email": email,
        "publicKeyPem": public_key_pem,
        "issuer": ISSUER,
        "issuedAt": isoformat(issued_at),
        "expiresAt": isoformat(expires_at),
        "status": "valid",
    }
    certificate["caSignatureAlgorithm"] = CERTIFICATE_SIGNATURE_ALGORITHM
    certificate["caSignatureBase64"] = sign_certificate(certificate)
    return certificate


def sign_hash(document_hash_hex: str, private_key_pem: str) -> str:
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None,
    )
    # The demo signs the SHA-256 digest bytes with RSA-PSS and SHA-256.
    signature = private_key.sign(
        bytes.fromhex(document_hash_hex),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("ascii")


def verify_signature(document_hash_hex: str, signature_base64: str, public_key_pem: str) -> bool:
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    try:
        public_key.verify(
            base64.b64decode(signature_base64),
            bytes.fromhex(document_hash_hex),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError, binascii.Error):
        return False


def _int_to_base64(value: int, length: int) -> str:
    return base64.b64encode(value.to_bytes(length, "big")).decode("ascii")


def rsa_blind_signature_demo(message: str) -> Dict[str, Any]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_numbers = private_key.private_numbers()
    public_numbers = private_numbers.public_numbers
    n = public_numbers.n
    e = public_numbers.e
    d = private_numbers.d
    key_length = (n.bit_length() + 7) // 8

    message_hash = hashlib.sha256(message.encode("utf-8")).digest()
    message_int = int.from_bytes(message_hash, "big")

    while True:
        blinding_factor = secrets.randbelow(n - 3) + 2
        if math.gcd(blinding_factor, n) == 1:
            break

    blinded_message = (message_int * pow(blinding_factor, e, n)) % n
    blind_signature = pow(blinded_message, d, n)
    unblinded_signature = (blind_signature * pow(blinding_factor, -1, n)) % n
    verification_value = pow(unblinded_signature, e, n)

    return {
        "message": message,
        "hashAlgorithm": "SHA-256",
        "messageHash": message_hash.hex(),
        "scheme": "Educational RSA blind signature demo",
        "publicKey": {
            "modulusHex": hex(n),
            "publicExponent": e,
        },
        "blindedMessageBase64": _int_to_base64(blinded_message, key_length),
        "blindSignatureBase64": _int_to_base64(blind_signature, key_length),
        "unblindedSignatureBase64": _int_to_base64(unblinded_signature, key_length),
        "verificationValueHex": hex(verification_value),
        "valid": verification_value == message_int,
    }

