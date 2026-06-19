import base64
import copy
import hashlib
import hmac
import sys
import os
import time
from datetime import timedelta
from pathlib import Path

os.environ["SECUREDOC_DATABASE_URL"] = "sqlite:///:memory:"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi.testclient import TestClient

from app.crypto_utils import canonicalize_signing_payload, generate_key_pair, get_public_key_size, hash_bytes, parse_iso_datetime
from app.auth_utils import (
    create_email_otp,
    create_signing_email_otp,
    create_totp_setting,
    current_totp_code,
    verify_email_otp,
    verify_totp_setup,
)
from app.database import SessionLocal
from app.main import _rate_limit_buckets, app
from app.models import AuditLog, CertificateRecord, EmailOtpToken, SigningRequest, UserMfaSetting
from app.x509_utils import issue_user_x509_certificate, verify_signed_demo_crl


DOCUMENT = b"SecureDoc v2 test document"
CA_HEADERS = {"X-SecureDoc-User": "pytest-ca", "X-SecureDoc-Role": "CA_OFFICER"}
SIGNER_HEADERS = {"X-SecureDoc-User": "signer@example.com", "X-SecureDoc-Role": "SIGNER"}
OTHER_SIGNER_HEADERS = {"X-SecureDoc-User": "other-signer@example.com", "X-SecureDoc-Role": "SIGNER"}
AUDITOR_HEADERS = {"X-SecureDoc-User": "pytest-auditor", "X-SecureDoc-Role": "AUDITOR"}
VERIFIER_HEADERS = {"X-SecureDoc-User": "pytest-verifier", "X-SecureDoc-Role": "VERIFIER"}


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
    assert data["report"]["cryptoValid"] is True
    assert data["report"]["documentHashValid"] is True
    assert data["report"]["trustedChainValid"] is True
    assert data["report"]["revocationValid"] is True
    assert data["report"]["timestampValid"] is True
    assert data["report"]["serverAccepted"] is True
    assert data["report"]["signingRequestConfirmed"] is True
    assert data["report"]["confirmationMethod"] == "EMAIL_OTP"
    assert data["report"]["legalReady"] is False


def test_offline_valid_package_is_not_server_accepted():
    with TestClient(app) as client:
        signed_package, document_hash = _create_unsigned_verify_package(
            "Offline Signer",
            "offline@example.com",
        )

        response = client.post(
            "/api/verify/v2",
            json={"documentHash": document_hash, "hashAlgorithm": "SHA-256", "signedPackage": signed_package},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is True
    assert data["report"]["cryptoValid"] is True
    assert data["report"]["serverAccepted"] is False
    assert data["report"]["legalReady"] is False
    assert data["report"]["signingRequestConfirmed"] is False
    assert data["report"]["confirmationMethod"] is None
    assert data["report"]["finalDecision"] == "crypto_valid_server_rejected"
    assert any("Replay check is not authoritative" in warning for warning in data["report"]["warnings"])


def test_legacy_private_key_routes_disabled_by_default():
    with TestClient(app) as client:
        generate = client.post(
            "/api/keys/generate",
            json={"name": "Legacy User", "email": "legacy@example.com"},
        )
        sign = client.post(
            "/api/sign",
            files={"file": ("document.txt", DOCUMENT, "text/plain")},
            data={"privateKeyPem": "secret", "certificate": "{}"},
        )
        openapi = client.get("/openapi.json")

    assert generate.status_code == 404
    assert generate.json()["detail"] == "Legacy demo API is disabled"
    assert sign.status_code == 404
    assert sign.json()["detail"] == "Legacy demo API is disabled"
    paths = openapi.json()["paths"]
    assert "/api/keys/generate" not in paths
    assert "/api/sign" not in paths


def test_hash_document_respects_requested_hash_algorithm():
    with TestClient(app) as client:
        response = client.post(
            "/api/documents/hash",
            files={"file": ("document.txt", DOCUMENT, "text/plain")},
            data={"hashAlgorithm": "SHA-512"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["hashAlgorithm"] == "SHA-512"
    assert data["documentHash"] == hash_bytes(DOCUMENT, "SHA-512")


def test_unauthenticated_cannot_issue_cert():
    _, public_key_pem = generate_key_pair()
    with TestClient(app) as client:
        response = client.post(
            "/api/certificates/x509/issue",
            json={"name": "No Auth", "email": "noauth@example.com", "publicKeyPem": public_key_pem},
        )

    assert response.status_code == 401


def test_signer_cannot_revoke_cert():
    with TestClient(app) as client:
        response = client.post(
            "/api/certificates/revoke/v2",
            headers=SIGNER_HEADERS,
            json={"serialNumber": "ABC", "reason": "pytest", "revokedBy": "pytest"},
        )

    assert response.status_code == 403


def test_ca_officer_can_issue_cert():
    _, public_key_pem = generate_key_pair()
    with TestClient(app) as client:
        response = client.post(
            "/api/certificates/x509/issue",
            headers=CA_HEADERS,
            json={"name": "CA Issued", "email": "ca-issued@example.com", "publicKeyPem": public_key_pem},
        )

    assert response.status_code == 200
    assert response.json()["certificateType"] == "x509-demo"


def test_user_cannot_prepare_signing_request_for_certificate_they_do_not_own():
    _, public_key_pem = generate_key_pair()
    with TestClient(app) as client:
        issued = client.post(
            "/api/certificates/x509/issue",
            headers=CA_HEADERS,
            json={"name": "Other Owner", "email": "other-owner@example.com", "publicKeyPem": public_key_pem},
        )
        assert issued.status_code == 200
        certificate = issued.json()["certificate"]
        response = client.post(
            "/api/sign/v2/prepare",
            headers=SIGNER_HEADERS,
            json={
                "documentName": "document.txt",
                "documentHash": hash_bytes(DOCUMENT, "SHA-256"),
                "hashAlgorithm": "SHA-256",
                "certificateSerialNumber": certificate["serialNumber"],
                "signingPurpose": "approve_document",
            },
        )

    assert response.status_code == 403
    assert response.json()["detail"] == "Authenticated signer does not own this certificate"


def test_email_otp_is_hashed_expires_and_cannot_be_reused():
    with SessionLocal() as db:
        token, otp = create_email_otp(db, "otp@example.com", "SENSITIVE_ACTION")
        db.commit()
        assert token.otp_hash != otp
        assert token.used_at is None

        ok, message = verify_email_otp(db, "otp@example.com", "SENSITIVE_ACTION", otp)
        db.commit()
        assert ok, message

        reused, reused_message = verify_email_otp(db, "otp@example.com", "SENSITIVE_ACTION", otp)
        assert reused is False
        assert reused_message == "OTP already used"


def test_otp_hash_uses_hmac_pepper_and_is_not_plain_bruteforce(monkeypatch):
    monkeypatch.delenv("SECUREDOC_OTP_PEPPER", raising=False)
    with SessionLocal() as db:
        token, otp = create_email_otp(db, "pepper@example.com", "SENSITIVE_ACTION")
        stored_hash = token.otp_hash
        db.commit()

    legacy_plain = hashlib.sha256(f"pepper@example.com:SENSITIVE_ACTION:{otp}".encode("utf-8")).hexdigest()
    context = "pepper@example.com:SENSITIVE_ACTION::::::" + otp
    wrong_pepper = hmac.new(b"wrong-pepper", context.encode("utf-8"), hashlib.sha256).hexdigest()
    assert stored_hash != legacy_plain
    assert stored_hash != wrong_pepper


def test_email_otp_api_does_not_return_plain_otp():
    with TestClient(app) as client:
        response = client.post(
            "/api/auth/email-otp/request",
            headers={"X-SecureDoc-User": "api-otp@example.com", "X-SecureDoc-Role": "SIGNER"},
            json={"email": "api-otp@example.com", "purpose": "SENSITIVE_ACTION"},
        )

    assert response.status_code == 200
    data = response.json()
    assert "otp" not in {key.lower() for key in data}
    assert data["delivery"] == "not_configured_demo_no_otp_in_response"

    with SessionLocal() as db:
        token = db.query(EmailOtpToken).filter_by(email="api-otp@example.com").first()
        assert token is not None
        assert len(token.otp_hash) == 64


def test_generic_email_otp_cannot_be_used_for_signing_confirmation():
    with TestClient(app) as client:
        response = client.post(
            "/api/auth/email-otp/request",
            headers=SIGNER_HEADERS,
            json={"email": "signer@example.com", "purpose": "SIGNING_CONFIRMATION"},
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "Use signing request confirmation OTP endpoint"


def test_email_otp_attempt_limit_and_expiry():
    with SessionLocal() as db:
        token, _otp = create_email_otp(db, "limit@example.com", "LOGIN_MFA")
        token.max_attempts = 2
        db.commit()

        first, _ = verify_email_otp(db, "limit@example.com", "LOGIN_MFA", "000000")
        second, _ = verify_email_otp(db, "limit@example.com", "LOGIN_MFA", "111111")
        third, message = verify_email_otp(db, "limit@example.com", "LOGIN_MFA", "222222")
        db.commit()
        assert first is False
        assert second is False
        assert third is False
        assert message == "OTP attempt limit exceeded"

        expired_token, expired_otp = create_email_otp(db, "expired-otp@example.com", "LOGIN_MFA")
        expired_token.expires_at = expired_token.created_at
        db.commit()
        expired, expired_message = verify_email_otp(db, "expired-otp@example.com", "LOGIN_MFA", expired_otp)
        assert expired is False
        assert expired_message == "OTP expired"


def test_totp_setup_requires_valid_code_and_does_not_store_plain_secret():
    headers = {"X-SecureDoc-User": "mfa@example.com", "X-SecureDoc-Role": "SIGNER"}
    with TestClient(app) as client:
        setup = client.post("/api/auth/totp/setup", headers=headers)
        assert setup.status_code == 200, setup.text
        data = setup.json()
        assert data["email"] == "mfa@example.com"
        assert data["otpauthUri"].startswith("otpauth://totp/")
        secret = data["secret"]

        invalid_code = "000000" if current_totp_code(secret) != "000000" else "000001"
        bad = client.post("/api/auth/totp/verify-setup", headers=headers, json={"code": invalid_code})
        assert bad.status_code == 200
        assert bad.json()["verified"] is False

        good = client.post("/api/auth/totp/verify-setup", headers=headers, json={"code": current_totp_code(secret)})
        assert good.status_code == 200
        assert good.json()["verified"] is True

    with SessionLocal() as db:
        stored = db.query(UserMfaSetting).filter_by(email="mfa@example.com").first()
        assert stored is not None
        assert stored.enabled == 1
        assert stored.secret_encrypted != secret
        assert not stored.secret_encrypted.startswith("demo-b64:")
        assert base64.b32encode(base64.b32decode(secret + ("=" * ((8 - len(secret) % 8) % 8)), casefold=True)).decode("ascii").rstrip("=") == secret
        assert base64.b64encode(secret.encode("utf-8")).decode("ascii") not in stored.secret_encrypted


def test_unauthenticated_totp_setup_is_rejected():
    with TestClient(app) as client:
        response = client.post("/api/auth/totp/setup")

    assert response.status_code == 401


def test_totp_verify_setup_does_not_accept_secret():
    headers = {"X-SecureDoc-User": "totp-contract@example.com", "X-SecureDoc-Role": "SIGNER"}
    with TestClient(app) as client:
        setup = client.post("/api/auth/totp/setup", headers=headers)
        assert setup.status_code == 200
        secret = setup.json()["secret"]
        response = client.post(
            "/api/auth/totp/verify-setup",
            headers=headers,
            json={"code": current_totp_code(secret), "secret": secret},
        )

    assert response.status_code == 422


def test_enabled_mfa_is_not_reset_by_regular_totp_setup():
    headers = {"X-SecureDoc-User": "enabled-mfa@example.com", "X-SecureDoc-Role": "SIGNER"}
    with TestClient(app) as client:
        setup = client.post("/api/auth/totp/setup", headers=headers)
        assert setup.status_code == 200
        secret = setup.json()["secret"]
        verify = client.post("/api/auth/totp/verify-setup", headers=headers, json={"code": current_totp_code(secret)})
        assert verify.status_code == 200
        assert verify.json()["verified"] is True
        with SessionLocal() as db:
            stored_before = db.query(UserMfaSetting).filter_by(email="enabled-mfa@example.com").first()
            assert stored_before is not None
            encrypted_before = stored_before.secret_encrypted

        reset = client.post("/api/auth/totp/setup", headers=headers)

    assert reset.status_code == 403
    assert reset.json()["detail"] == "TOTP already enabled; re-authentication is required to reset it"
    with SessionLocal() as db:
        stored_after = db.query(UserMfaSetting).filter_by(email="enabled-mfa@example.com").first()
        assert stored_after is not None
        assert stored_after.enabled == 1
        assert stored_after.secret_encrypted == encrypted_before


def test_request_size_limit_rejects_large_body():
    with TestClient(app) as client:
        response = client.post(
            "/api/verify/v2",
            content=b"x" * (2 * 1024 * 1024 + 1),
            headers={"Content-Type": "application/json"},
        )

    assert response.status_code == 413


def test_rate_limit_returns_429_when_bucket_is_full():
    _rate_limit_buckets[("testclient", "/api/algorithm-policy")] = [time.time()] * 120
    with TestClient(app) as client:
        response = client.get("/api/algorithm-policy")
    _rate_limit_buckets.clear()

    assert response.status_code == 429


def test_cors_allowlist_does_not_reflect_untrusted_origin():
    with TestClient(app) as client:
        response = client.options(
            "/api/algorithm-policy",
            headers={
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "GET",
            },
        )

    assert response.headers.get("access-control-allow-origin") != "https://evil.example"


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
            headers=CA_HEADERS,
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
            headers=CA_HEADERS,
            json={"serialNumber": serial, "reason": "cessation_of_operation", "revokedBy": "pytest"},
        )
        assert revoke.status_code == 200

        response = client.get("/api/certificates/crl", headers=VERIFIER_HEADERS)

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


def test_submit_signed_package_without_otp_or_totp_confirmation_is_rejected():
    with TestClient(app) as client:
        package, _document_hash, _certificate = _create_prepared_signed_package(client)

        response = client.post("/api/sign/v2/submit", headers=SIGNER_HEADERS, json=package)

    assert response.status_code == 400
    assert response.json()["detail"] == "Signing request has not been OTP/TOTP confirmed"


def test_signing_otp_resend_cooldown_is_enforced():
    with TestClient(app) as client:
        package, _document_hash, _certificate = _create_prepared_signed_package(client)
        request_id = package["signingPayload"]["requestId"]
        first = client.post(f"/api/v2/signing-requests/{request_id}/otp/request", headers=SIGNER_HEADERS)
        second = client.post(f"/api/v2/signing-requests/{request_id}/otp/request", headers=SIGNER_HEADERS)

    assert first.status_code == 200, first.text
    assert second.status_code == 429
    assert "cooldown" in second.json()["detail"]


def test_old_signing_otp_is_revoked_when_new_one_is_created_after_cooldown():
    with TestClient(app) as client:
        package, _document_hash, _certificate = _create_prepared_signed_package(client)
        request_id = package["signingPayload"]["requestId"]
        old_otp = _create_bound_email_otp(request_id)
        with SessionLocal() as db:
            old_token = (
                db.query(EmailOtpToken)
                .filter_by(signing_request_id=request_id, purpose="SIGNING_CONFIRMATION")
                .order_by(EmailOtpToken.id.desc())
                .first()
            )
            assert old_token is not None
            old_token.created_at = old_token.created_at - timedelta(seconds=61)
            db.commit()
        new_otp = _create_bound_email_otp(request_id)

        old_confirm = client.post(
            f"/api/v2/signing-requests/{request_id}/confirm",
            headers=SIGNER_HEADERS,
            json={"method": "EMAIL_OTP", "code": old_otp},
        )
        new_confirm = client.post(
            f"/api/v2/signing-requests/{request_id}/confirm",
            headers=SIGNER_HEADERS,
            json={"method": "EMAIL_OTP", "code": new_otp},
        )

    assert old_confirm.status_code == 400
    assert new_confirm.status_code == 200, new_confirm.text


def test_email_otp_bound_to_different_request_id_is_rejected():
    with TestClient(app) as client:
        package_a, _document_hash_a, _certificate_a = _create_prepared_signed_package(client, document_name="request-a.txt")
        package_b, _document_hash_b, _certificate = _create_prepared_signed_package(
            client,
            document_name="request-b.txt",
            document=b"second document",
        )
        otp = _create_bound_email_otp(package_a["signingPayload"]["requestId"])

        response = client.post(
            f"/api/v2/signing-requests/{package_b['signingPayload']['requestId']}/confirm",
            headers=SIGNER_HEADERS,
            json={"method": "EMAIL_OTP", "code": otp},
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "OTP not found for this signing request"


def test_email_otp_bound_to_different_document_hash_is_rejected():
    with TestClient(app) as client:
        package, _document_hash, _certificate = _create_prepared_signed_package(client)
        request_id = package["signingPayload"]["requestId"]
        with SessionLocal() as db:
            request = db.get(SigningRequest, request_id)
            assert request is not None
            _token, otp = create_signing_email_otp(
                db,
                email=request.signer_email,
                signing_request_id=request.request_id,
                document_hash=hash_bytes(b"different document", "SHA-256"),
                certificate_serial=request.certificate_serial,
                signing_purpose=request.signing_purpose,
                nonce=request.nonce,
            )
            db.commit()

        response = client.post(
            f"/api/v2/signing-requests/{request_id}/confirm",
            headers=SIGNER_HEADERS,
            json={"method": "EMAIL_OTP", "code": otp},
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "OTP not found for this signing request"


def test_totp_confirmation_rejects_authenticated_user_who_does_not_own_request():
    with TestClient(app) as client:
        package, _document_hash, _certificate = _create_prepared_signed_package(client)
        request_id = package["signingPayload"]["requestId"]
        with SessionLocal() as db:
            setting, secret, _uri = create_totp_setting(db, "signer@example.com")
            db.commit()
            ok, message = verify_totp_setup(db, "signer@example.com", current_totp_code(secret))
            db.commit()
            assert ok, message
        code = current_totp_code(secret)

        response = client.post(
            f"/api/v2/signing-requests/{request_id}/confirm",
            headers=OTHER_SIGNER_HEADERS,
            json={"method": "TOTP", "code": code},
        )

    assert response.status_code == 403
    assert response.json()["detail"] == "Authenticated signer does not own this signing request"


def test_crypto_valid_package_for_unconfirmed_request_is_not_server_accepted():
    with TestClient(app) as client:
        package, document_hash, _certificate = _create_prepared_signed_package(client)

        response = client.post(
            "/api/verify/v2",
            json={"documentHash": document_hash, "hashAlgorithm": "SHA-256", "signedPackage": package},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["report"]["cryptoValid"] is True
    assert data["report"]["serverAccepted"] is False
    assert data["report"]["signingRequestConfirmed"] is False
    assert data["report"]["confirmationMethod"] is None


def test_audit_chain_valid():
    with TestClient(app) as client:
        _create_submitted_package(client)
        response = client.get("/api/audit/verify-chain", headers=AUDITOR_HEADERS)

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

        response = client.get("/api/audit/verify-chain", headers=AUDITOR_HEADERS)

    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is False
    assert data["brokenAt"] is not None


def _create_submitted_package(client: TestClient):
    package, document_hash, _certificate = _create_prepared_signed_package(client)
    _confirm_request_with_email_otp(client, package["signingPayload"]["requestId"])
    submit = client.post("/api/sign/v2/submit", headers=SIGNER_HEADERS, json=package)
    assert submit.status_code == 200, submit.text
    return submit.json()["signedPackage"], document_hash


def _create_prepared_signed_package(
    client: TestClient,
    *,
    document: bytes = DOCUMENT,
    document_name: str = "document.txt",
):
    private_key_pem, public_key_pem = generate_key_pair()
    issued = client.post(
        "/api/certificates/x509/issue",
        headers=CA_HEADERS,
        json={"name": "Test Signer", "email": "signer@example.com", "publicKeyPem": public_key_pem},
    )
    assert issued.status_code == 200, issued.text
    key_data = issued.json()
    assert key_data["certificateType"] == "x509-demo"
    assert key_data["userCertificatePem"].startswith("-----BEGIN CERTIFICATE-----")
    certificate = key_data["certificate"]

    document_hash = hash_bytes(document, "SHA-256")
    prepare = client.post(
        "/api/sign/v2/prepare",
        headers=SIGNER_HEADERS,
        json={
            "documentName": document_name,
            "documentHash": document_hash,
            "hashAlgorithm": "SHA-256",
            "certificateSerialNumber": certificate["serialNumber"],
            "signingPurpose": "approve_document",
        },
    )
    assert prepare.status_code == 200, prepare.text
    payload = prepare.json()["signingPayload"]
    package = {
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
    }
    return package, document_hash, certificate


def _confirm_request_with_email_otp(client: TestClient, request_id: str) -> None:
    otp = _create_bound_email_otp(request_id)
    confirm = client.post(
        f"/api/v2/signing-requests/{request_id}/confirm",
        headers=SIGNER_HEADERS,
        json={"method": "EMAIL_OTP", "code": otp},
    )
    assert confirm.status_code == 200, confirm.text


def _create_bound_email_otp(request_id: str) -> str:
    with SessionLocal() as db:
        request = db.get(SigningRequest, request_id)
        assert request is not None
        _token, otp = create_signing_email_otp(
            db,
            email=request.signer_email,
            signing_request_id=request.request_id,
            document_hash=request.document_hash,
            certificate_serial=request.certificate_serial,
            signing_purpose=request.signing_purpose,
            nonce=request.nonce,
        )
        db.commit()
        return otp


def client_like_verify_totp_setup(db, email: str, code: str) -> bool:
    ok, _message = verify_totp_setup(db, email, code)
    return ok


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
