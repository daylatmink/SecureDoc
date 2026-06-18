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

from app.crypto_utils import canonicalize_signing_payload, generate_key_pair, get_public_key_size, hash_bytes, parse_iso_datetime
from app.database import SessionLocal
from app.main import app
from app.models import AuditLog, CertificateRecord
from app.x509_utils import issue_user_x509_certificate, verify_signed_demo_crl


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
    assert data["report"]["certificateType"] == "x509-demo"
    assert data["report"]["certificateChainValid"] == "passed"
    assert data["report"]["keyUsageValid"] == "passed"
    assert data["report"]["certificateRevocationStatus"] == "valid"
    assert data["report"]["revocationSource"] == "server-db"
    assert data["report"]["timestampStatus"] == "demo-tsa-valid"
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
    assert data["report"]["revocationSource"] == "server-db"


def test_v2_verify_rejects_expired_certificate():
    with TestClient(app) as client:
        signed_package, document_hash = _create_unsigned_verify_package(
            "Expired Signer",
            "expired@example.com",
            validity_days=0,
        )

        response = client.post(
            "/api/verify/v2",
            json={"documentHash": document_hash, "hashAlgorithm": "SHA-256", "signedPackage": signed_package},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is False
    assert data["reason"] == "certificate expired"
    assert data["report"]["certificateValidityPeriod"] == "failed"


def test_v2_verify_rejects_bad_key_usage():
    with TestClient(app) as client:
        signed_package, document_hash = _create_unsigned_verify_package(
            "Bad Usage Signer",
            "bad-usage@example.com",
            content_commitment_usage=False,
        )

        response = client.post(
            "/api/verify/v2",
            json={"documentHash": document_hash, "hashAlgorithm": "SHA-256", "signedPackage": signed_package},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is False
    assert data["reason"] == "certificate not trusted"
    assert data["report"]["keyUsageValid"] == "failed"


def test_x509_chain_success_and_failure_when_chain_is_tampered():
    with TestClient(app) as client:
        signed_package, document_hash = _create_submitted_package(client)

        ok_response = client.post(
            "/api/verify/v2",
            json={"documentHash": document_hash, "hashAlgorithm": "SHA-256", "signedPackage": signed_package},
        )
        tampered_package = copy.deepcopy(signed_package)
        tampered_package["intermediateCertificatePem"] = tampered_package["rootCertificatePem"]
        tampered_package["signerCertificate"]["intermediateCertificatePem"] = tampered_package["rootCertificatePem"]
        fail_response = client.post(
            "/api/verify/v2",
            json={"documentHash": document_hash, "hashAlgorithm": "SHA-256", "signedPackage": tampered_package},
        )

    assert ok_response.status_code == 200
    assert ok_response.json()["report"]["certificateChainValid"] == "passed"
    assert fail_response.status_code == 200
    fail_data = fail_response.json()
    assert fail_data["valid"] is False
    assert fail_data["reason"] == "certificate not trusted"


def test_demo_crl_is_signed_and_lists_revoked_certificate():
    with TestClient(app) as client:
        signed_package, _ = _create_submitted_package(client)
        serial = signed_package["signerCertificate"]["serialNumber"]
        revoke = client.post(
            "/api/certificates/revoke/v2",
            json={"serialNumber": serial, "reason": "cessation_of_operation", "revokedBy": "pytest"},
        )
        assert revoke.status_code == 200

        response = client.get("/api/certificates/crl")

    assert response.status_code == 200
    crl = response.json()
    assert crl["signatureAlgorithm"] == "RSA-PSS-SHA256"
    assert any(item["serialNumber"] == serial for item in crl["revokedCertificates"])
    valid, message = verify_signed_demo_crl(crl)
    assert valid, message


def test_timestamp_token_is_verified():
    with TestClient(app) as client:
        signed_package, document_hash = _create_submitted_package(client)

        response = client.post(
            "/api/verify/v2",
            json={"documentHash": document_hash, "hashAlgorithm": "SHA-256", "signedPackage": signed_package},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is True
    assert signed_package["timestampToken"]["messageImprint"]
    assert data["report"]["timestampStatus"] == "demo-tsa-valid"


def test_audit_chain_valid():
    with TestClient(app) as client:
        _create_submitted_package(client)
        response = client.get("/api/audit/verify-chain")

    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is True
    assert data["totalEvents"] > 0
    assert data["brokenAt"] is None


def test_audit_chain_detects_tampered_log():
    with TestClient(app) as client:
        _create_submitted_package(client)
        with SessionLocal() as db:
            event = db.query(AuditLog).order_by(AuditLog.id.asc()).first()
            assert event is not None
            event.details = "tampered audit log"
            db.commit()

        response = client.get("/api/audit/verify-chain")

    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is False
    assert data["brokenAt"] is not None


def _create_submitted_package(client: TestClient):
    private_key_pem, public_key_pem = generate_key_pair()
    issued = client.post(
        "/api/certificates/x509/issue",
        json={"name": "Test Signer", "email": "signer@example.com", "publicKeyPem": public_key_pem},
    )
    assert issued.status_code == 200, issued.text
    key_data = issued.json()
    assert key_data["certificateType"] == "x509-demo"
    assert key_data["userCertificatePem"].startswith("-----BEGIN CERTIFICATE-----")
    certificate = key_data["certificate"]
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
        "userCertificatePem": certificate["userCertificatePem"],
        "intermediateCertificatePem": certificate["intermediateCertificatePem"],
        "rootCertificatePem": certificate["rootCertificatePem"],
        "trustedRootId": "securedoc-demo-root",
        "signerCertificate": certificate,
        "signedAtClient": "2026-06-16T00:00:00+00:00",
    }

    submit = client.post("/api/sign/v2/submit", json=package)
    assert submit.status_code == 200, submit.text
    return submit.json()["signedPackage"], document_hash


def _create_unsigned_verify_package(
    name: str,
    email: str,
    *,
    validity_days: int = 365,
    content_commitment_usage: bool = True,
):
    private_key_pem, public_key_pem = generate_key_pair()
    issued = issue_user_x509_certificate(
        name,
        email,
        public_key_pem,
        validity_days=validity_days,
        content_commitment_usage=content_commitment_usage,
    )
    certificate = issued["certificate"]
    _insert_certificate_record(certificate)
    document_hash = hash_bytes(DOCUMENT, "SHA-256")
    payload = {
        "documentName": "document.txt",
        "documentHash": document_hash,
        "hashAlgorithm": "SHA-256",
        "signatureAlgorithm": "RSA-PSS",
        "signerName": certificate["ownerName"],
        "signerEmail": certificate["email"],
        "certificateSerialNumber": certificate["serialNumber"],
        "certificateFingerprint": certificate["certificateFingerprint"],
        "certificateType": "x509-demo",
        "signingPurpose": "approve_document",
        "createdAt": "2026-06-16T00:00:00+00:00",
        "requestId": "verify-only-request",
        "nonce": "verify-only-nonce",
        "payloadVersion": "1.0",
    }
    return {
        "packageVersion": "2.0",
        "signingPayload": payload,
        "payloadCanonicalization": "JSON-canonical-sorted-keys",
        "signatureAlgorithm": "RSA-PSS",
        "signatureBase64": _sign_payload(payload, private_key_pem),
        "userCertificatePem": certificate["userCertificatePem"],
        "intermediateCertificatePem": certificate["intermediateCertificatePem"],
        "rootCertificatePem": certificate["rootCertificatePem"],
        "trustedRootId": "securedoc-demo-root",
        "signerCertificate": certificate,
        "signedAtClient": "2026-06-16T00:00:00+00:00",
    }, document_hash


def _insert_certificate_record(certificate: dict) -> None:
    with SessionLocal() as db:
        db.add(
            CertificateRecord(
                serial_number=certificate["serialNumber"],
                owner_name=certificate["ownerName"],
                email=certificate["email"],
                public_key_pem=certificate["publicKeyPem"],
                issuer=certificate["issuer"],
                issued_at=parse_iso_datetime(certificate["issuedAt"]).replace(tzinfo=None),
                expires_at=parse_iso_datetime(certificate["expiresAt"]).replace(tzinfo=None),
                status=certificate["status"],
                certificate_type="x509-demo",
                fingerprint_sha256=certificate["certificateFingerprint"],
                key_size_bits=get_public_key_size(certificate["publicKeyPem"]),
                user_certificate_pem=certificate["userCertificatePem"],
                intermediate_certificate_pem=certificate["intermediateCertificatePem"],
                root_certificate_pem=certificate["rootCertificatePem"],
            )
        )
        db.commit()


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
