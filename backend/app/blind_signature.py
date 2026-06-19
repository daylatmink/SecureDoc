"""Educational RSA blind signature helpers.

This module is intentionally separate from the document-signing flow. Blind
signatures are for privacy/anonymous-token demonstrations, not legal document
signing.
"""

import base64
import binascii
import hashlib
import json
import math
import secrets
from datetime import timedelta
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .config import ensure_demo_plaintext_keys_allowed, ensure_runtime_secrets_dir
from .crypto_utils import isoformat, utc_now

ALLOWED_BLIND_PURPOSES = {"anonymous_access_token", "e_voting_demo", "e_cash_demo"}
BLIND_TOKEN_VERSION = "1.0"
BLIND_SIGNATURE_SCHEME = "RSA blind signature educational demo"
BLIND_SIGNER_PRIVATE_KEY_PATH = ensure_runtime_secrets_dir() / "securedoc_blind_signer_private.pem"


def ensure_blind_signer_key() -> rsa.RSAPrivateKey:
    ensure_demo_plaintext_keys_allowed()
    if BLIND_SIGNER_PRIVATE_KEY_PATH.exists():
        key = serialization.load_pem_private_key(BLIND_SIGNER_PRIVATE_KEY_PATH.read_bytes(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("Blind signer private key must be RSA")
        return key

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    BLIND_SIGNER_PRIVATE_KEY_PATH.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return private_key


def canonical_token_bytes(token: dict[str, Any]) -> bytes:
    return json.dumps(token, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def token_hash_hex(token: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_token_bytes(token)).hexdigest()


def create_token(purpose: str, ttl_seconds: int = 600) -> dict[str, str]:
    if purpose not in ALLOWED_BLIND_PURPOSES:
        raise ValueError("Invalid blind signature purpose")
    now = utc_now()
    return {
        "tokenId": secrets.token_hex(16),
        "purpose": purpose,
        "createdAt": isoformat(now),
        "expiresAt": isoformat(now + timedelta(seconds=ttl_seconds)),
        "nonce": secrets.token_hex(16),
        "tokenVersion": BLIND_TOKEN_VERSION,
    }


def public_key_numbers() -> dict[str, int]:
    public_numbers = ensure_blind_signer_key().public_key().public_numbers()
    return {"n": public_numbers.n, "e": public_numbers.e}


def int_to_base64(value: int, length: int | None = None) -> str:
    if length is None:
        length = max(1, (value.bit_length() + 7) // 8)
    return base64.b64encode(value.to_bytes(length, "big")).decode("ascii")


def base64_to_int(value: str) -> int:
    return int.from_bytes(base64.b64decode(value), "big")


def key_length_bytes() -> int:
    return (public_key_numbers()["n"].bit_length() + 7) // 8


def token_message_int(token: dict[str, Any]) -> int:
    return int.from_bytes(hashlib.sha256(canonical_token_bytes(token)).digest(), "big")


def blind_token(token: dict[str, Any]) -> dict[str, str]:
    numbers = public_key_numbers()
    n = numbers["n"]
    e = numbers["e"]
    message_int = token_message_int(token)

    while True:
        blinding_factor = secrets.randbelow(n - 3) + 2
        if math.gcd(blinding_factor, n) == 1:
            break

    blinded_message = (message_int * pow(blinding_factor, e, n)) % n
    length = key_length_bytes()
    return {
        "blindedMessageBase64": int_to_base64(blinded_message, length),
        "blindingFactorBase64": int_to_base64(blinding_factor, length),
        "tokenHash": token_hash_hex(token),
    }


def sign_blinded_message(blinded_message_base64: str) -> str:
    private_numbers = ensure_blind_signer_key().private_numbers()
    n = private_numbers.public_numbers.n
    d = private_numbers.d
    blinded_message = base64_to_int(blinded_message_base64)
    if blinded_message <= 0 or blinded_message >= n:
        raise ValueError("Invalid blinded message")
    blind_signature = pow(blinded_message, d, n)
    return int_to_base64(blind_signature, key_length_bytes())


def unblind_signature(blind_signature_base64: str, blinding_factor_base64: str) -> str:
    n = public_key_numbers()["n"]
    blind_signature = base64_to_int(blind_signature_base64)
    blinding_factor = base64_to_int(blinding_factor_base64)
    if math.gcd(blinding_factor, n) != 1:
        raise ValueError("Invalid blinding factor")
    final_signature = (blind_signature * pow(blinding_factor, -1, n)) % n
    return int_to_base64(final_signature, key_length_bytes())


def verify_final_signature(token: dict[str, Any], final_signature_base64: str) -> bool:
    try:
        numbers = public_key_numbers()
        verification_value = pow(base64_to_int(final_signature_base64), numbers["e"], numbers["n"])
        return verification_value == token_message_int(token)
    except (ValueError, TypeError, binascii.Error):
        return False


def public_key_response() -> dict[str, Any]:
    numbers = public_key_numbers()
    return {
        "modulusBase64": int_to_base64(numbers["n"], key_length_bytes()),
        "publicExponent": numbers["e"],
    }
