"""Cryptographic utilities for SecureDoc — legacy + v2 functions.

All legacy functions are preserved.  New v2 functions added:
- canonicalize_signing_payload()
- verify_canonical_signature()
- record_audit_log()
- ALGORITHM_POLICY
"""

import base64
import binascii
import hashlib
import json
import math
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

ISSUER = "SecureDoc Demo CA"
CA_PRIVATE_KEY_PATH = Path(__file__).resolve().parents[1] / "securedoc_demo_ca_private.pem"
CA_PUBLIC_KEY_PATH = Path(__file__).resolve().parents[1] / "securedoc_demo_ca_public.pem"
CERTIFICATE_SIGNATURE_ALGORITHM = "RSA-PSS-SHA256"

HASH_ALGORITHM_PROFILES = {
    "SHA-256": {
        "name": "SHA-256",
        "digestBits": 256,
        "securityStrengthBits": 128,
        "family": "SHA-2",
        "description": "Widely used default for modern digital signatures.",
    },
    "SHA-384": {
        "name": "SHA-384",
        "digestBits": 384,
        "securityStrengthBits": 192,
        "family": "SHA-2",
        "description": "Higher-strength SHA-2 profile, often paired with stronger keys.",
    },
    "SHA-512": {
        "name": "SHA-512",
        "digestBits": 512,
        "securityStrengthBits": 256,
        "family": "SHA-2",
        "description": "High-strength SHA-2 profile with a 512-bit digest.",
    },
    "SHA3-256": {
        "name": "SHA3-256",
        "digestBits": 256,
        "securityStrengthBits": 128,
        "family": "SHA-3",
        "description": "NIST SHA-3 profile based on the Keccak sponge construction.",
    },
}

# ── Algorithm policy ──────────────────────────────────────────────────────

ALGORITHM_POLICY = {
    "allowedHashAlgorithms": ["SHA-256", "SHA-384", "SHA-512", "SHA3-256"],
    "rejectedHashAlgorithms": ["MD5", "SHA-1"],
    "allowedSignatureAlgorithms": ["RSA-PSS"],
    "minimumRsaKeyBits": 2048,
    "defaultRsaKeyBits": 3072,
    "defaultHashAlgorithm": "SHA-256",
    "defaultSignatureAlgorithm": "RSA-PSS",
}

ALLOWED_SIGNING_PURPOSES = [
    "approve_document",
    "confirm_reading",
    "sign_contract",
    "certify_copy",
    "acknowledge_receipt",
]


# ── Time helpers ──────────────────────────────────────────────────────────

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def parse_iso_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


# ── Hash helpers ──────────────────────────────────────────────────────────

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_hash_algorithm(hash_algorithm: str) -> str:
    normalized = hash_algorithm.strip().upper().replace("_", "-")
    aliases = {
        "SHA256": "SHA-256",
        "SHA384": "SHA-384",
        "SHA512": "SHA-512",
        "SHA3_256": "SHA3-256",
        "SHA-3-256": "SHA3-256",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized not in HASH_ALGORITHM_PROFILES:
        raise ValueError("Unsupported hash algorithm")
    return normalized


def supported_hash_algorithm_profiles() -> list[Dict[str, Any]]:
    return list(HASH_ALGORITHM_PROFILES.values())


def _hashlib_name(hash_algorithm: str) -> str:
    return {
        "SHA-256": "sha256",
        "SHA-384": "sha384",
        "SHA-512": "sha512",
        "SHA3-256": "sha3_256",
    }[normalize_hash_algorithm(hash_algorithm)]


def _cryptography_hash_algorithm(hash_algorithm: str) -> hashes.HashAlgorithm:
    return {
        "SHA-256": hashes.SHA256,
        "SHA-384": hashes.SHA384,
        "SHA-512": hashes.SHA512,
        "SHA3-256": hashes.SHA3_256,
    }[normalize_hash_algorithm(hash_algorithm)]()


def hash_bytes(data: bytes, hash_algorithm: str = "SHA-256") -> str:
    return hashlib.new(_hashlib_name(hash_algorithm), data).hexdigest()


def check_algorithm_policy(hash_alg: str, sig_alg: str) -> Tuple[bool, str]:
    """Check whether the given algorithms comply with the policy."""
    if hash_alg in ALGORITHM_POLICY["rejectedHashAlgorithms"]:
        return False, f"{hash_alg} is rejected by algorithm policy"
    if hash_alg not in ALGORITHM_POLICY["allowedHashAlgorithms"]:
        return False, f"{hash_alg} is not in the allowed list"
    if sig_alg not in ALGORITHM_POLICY["allowedSignatureAlgorithms"]:
        return False, f"{sig_alg} is not in the allowed list"
    return True, "Algorithm policy satisfied"


# ── Key generation ────────────────────────────────────────────────────────

def generate_key_pair(key_size: int = 3072) -> Tuple[str, str]:
    if key_size < ALGORITHM_POLICY["minimumRsaKeyBits"]:
        raise ValueError(f"Key size must be >= {ALGORITHM_POLICY['minimumRsaKeyBits']} bits")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
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


def get_public_key_size(public_key_pem: str) -> int:
    """Return key size in bits from a PEM public key."""
    try:
        pub = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        return pub.key_size  # type: ignore[union-attr]
    except Exception:
        return 0


def compute_certificate_fingerprint(certificate: Dict[str, Any]) -> str:
    """SHA-256 fingerprint of the canonical certificate payload."""
    payload = certificate_payload_for_signature(certificate)
    return hashlib.sha256(payload).hexdigest()


# ── Demo CA ───────────────────────────────────────────────────────────────

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


# ── Certificate signing (legacy demo CA) ──────────────────────────────────

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


# ── Document signing (legacy) ─────────────────────────────────────────────

def sign_hash(document_hash_hex: str, private_key_pem: str, hash_algorithm: str = "SHA-256") -> str:
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None,
    )
    algorithm = _cryptography_hash_algorithm(hash_algorithm)
    # The demo signs a precomputed document digest with RSA-PSS.
    signature = private_key.sign(
        bytes.fromhex(document_hash_hex),
        padding.PSS(
            mgf=padding.MGF1(algorithm),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        utils.Prehashed(algorithm),
    )
    return base64.b64encode(signature).decode("ascii")


def verify_signature(
    document_hash_hex: str,
    signature_base64: str,
    public_key_pem: str,
    hash_algorithm: str = "SHA-256",
) -> bool:
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    algorithm = _cryptography_hash_algorithm(hash_algorithm)
    try:
        public_key.verify(
            base64.b64decode(signature_base64),
            bytes.fromhex(document_hash_hex),
            padding.PSS(
                mgf=padding.MGF1(algorithm),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            utils.Prehashed(algorithm),
        )
        return True
    except (InvalidSignature, ValueError, binascii.Error):
        return False


# ── V2: Canonical signing payload ─────────────────────────────────────────

def canonicalize_signing_payload(payload_dict: Dict[str, Any]) -> bytes:
    """Deterministic JSON serialization with sorted keys for signing."""
    return json.dumps(
        payload_dict,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def verify_canonical_signature(
    canonical_bytes: bytes,
    signature_base64: str,
    public_key_pem: str,
    hash_algorithm: str = "SHA-256",
) -> bool:
    """Verify RSA-PSS signature over canonical JSON bytes.

    V2 uses saltLength = hash digest size so browser Web Crypto clients can
    interoperate. Legacy document-hash signing keeps its original PSS profile.
    """
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    algorithm = _cryptography_hash_algorithm(hash_algorithm)
    try:
        public_key.verify(
            base64.b64decode(signature_base64),
            canonical_bytes,
            padding.PSS(
                mgf=padding.MGF1(algorithm),
                salt_length=algorithm.digest_size,
            ),
            algorithm,
        )
        return True
    except (InvalidSignature, ValueError, binascii.Error):
        return False


# ── V2: Audit log hash chain ─────────────────────────────────────────────

def compute_audit_hash(event_json: str, previous_hash: Optional[str]) -> str:
    data = event_json.encode("utf-8")
    if previous_hash:
        data += previous_hash.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def build_audit_event_json(
    event_id: str,
    event_type: str,
    actor: Optional[str],
    result: str,
    details: Optional[str],
    created_at: str,
) -> str:
    event = {
        "eventId": event_id,
        "eventType": event_type,
        "actor": actor or "",
        "result": result,
        "details": details or "",
        "createdAt": created_at,
    }
    return json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


# ── Blind signature demo (unchanged) ─────────────────────────────────────

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
