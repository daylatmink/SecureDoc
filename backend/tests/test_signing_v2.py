import base64
import copy
import sys
import os
from pathlib import Path

os.environ["SECUREDOC_DATABASE_URL"] = "sqlite:///:memory:"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi.testclient import TestClient

from app.crypto_utils import canonicalize_signing_payload, hash_bytes
from app.main import app


DOCUMENT = b"SecureDoc v2 test document"


def test_canonical_signing_payload_is_deterministic():
    first = {"documentHash": "abc", "documentName": "demo.txt", "payloadVersion": "1.0"}
    second = {"payloadVersion": "1.0", "documentName": "demo.txt", "documentHash": "abc"}

    assert canonicalize_signing_payload(first) == canonicalize_signing_payload(second)
    assert canonicalize_signing_payload(first) == b'{"documentHash":"abc","documentName":"demo.txt","payloadVersion":"1.0"}'


def test_v2_verify_success():
    with TestClient(app) as client:
        signed_package, document_hash = _create_submitted_package(client)

        response = client.post(
            "/api/verify/v2",
            json={"documentHash": document_hash, "hashAlgorithm": "SHA-256", "signedPackage": signed_package},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is True
    assert data["report"]["documentIntegrity"] == "passed"
    assert data["report"]["signatureValid"] == "passed"
    assert data["report"]["certificateRevocationStatus"] == "valid"
    assert data["report"]["finalDecision"] == "valid"


def test_v2_verify_rejects_modified_document_hash():
    with TestClient(app) as client:
        signed_package, _ = _create_submitted_package(client)
        tampered_hash = hash_bytes(b"tampered document", "SHA-256")

        response = client.post(
            "/api/verify/v2",
            json={"documentHash": tampered_hash, "hashAlgorithm": "SHA-256", "signedPackage": signed_package},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is False
    assert data["reason"] == "document modified"
    assert data["report"]["documentIntegrity"] == "failed"


def test_v2_verify_rejects_tampered_signature():
    with TestClient(app) as client:
        signed_package, document_hash = _create_submitted_package(client)
        tampered_package = copy.deepcopy(signed_package)
        tampered_package["signatureBase64"] = _mutate_base64(tampered_package["signatureBase64"])

        response = client.post(
            "/api/verify/v2",
            json={"documentHash": document_hash, "hashAlgorithm": "SHA-256", "signedPackage": tampered_package},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is False
    assert data["reason"] == "invalid signature"
    assert data["report"]["signatureValid"] == "failed"


def test_v2_verify_rejects_revoked_certificate():
    with TestClient(app) as client:
        signed_package, document_hash = _create_submitted_package(client)
        serial = signed_package["signerCertificate"]["serialNumber"]
        revoke = client.post(
            "/api/certificates/revoke/v2",
            json={"serialNumber": serial, "reason": "key_compromise", "revokedBy": "pytest"},
        )
        assert revoke.status_code == 200

        response = client.post(
            "/api/verify/v2",
            json={"documentHash": document_hash, "hashAlgorithm": "SHA-256", "signedPackage": signed_package},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is False
    assert data["reason"] == "certificate revoked"
    assert data["report"]["certificateRevocationStatus"] == "revoked"


def _create_submitted_package(client: TestClient):
    keys = client.post("/api/keys/generate", json={"name": "Test Signer", "email": "signer@example.com"})
    assert keys.status_code == 200
    key_data = keys.json()
    certificate = key_data["certificate"]
    private_key_pem = key_data["privateKeyPem"]
    document_hash = hash_bytes(DOCUMENT, "SHA-256")

    prepare = client.post(
        "/api/sign/v2/prepare",
        json={
            "documentName": "document.txt",
            "documentHash": document_hash,
            "hashAlgorithm": "SHA-256",
            "certificateSerialNumber": certificate["serialNumber"],
            "signingPurpose": "approve_document",
        },
    )
    assert prepare.status_code == 200
    payload = prepare.json()["signingPayload"]
    signature = _sign_payload(payload, private_key_pem)
    package = {
        "packageVersion": "2.0",
        "signingPayload": payload,
        "payloadCanonicalization": "JSON-canonical-sorted-keys",
        "signatureAlgorithm": "RSA-PSS",
        "signatureBase64": signature,
        "signerCertificate": certificate,
        "signedAtClient": "2026-06-16T00:00:00+00:00",
    }

    submit = client.post("/api/sign/v2/submit", json=package)
    assert submit.status_code == 200, submit.text
    return submit.json()["signedPackage"], document_hash


def _sign_payload(payload: dict, private_key_pem: str) -> str:
    private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    algorithm = hashes.SHA256()
    signature = private_key.sign(
        canonicalize_signing_payload(payload),
        padding.PSS(mgf=padding.MGF1(algorithm), salt_length=algorithm.digest_size),
        algorithm,
    )
    return base64.b64encode(signature).decode("ascii")


def _mutate_base64(value: str) -> str:
    replacement = "A" if value[0] != "A" else "B"
    return replacement + value[1:]
