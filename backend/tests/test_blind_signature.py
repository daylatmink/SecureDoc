import os
import sys
from pathlib import Path

os.environ["SECUREDOC_DATABASE_URL"] = "sqlite:///:memory:"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient

from app.blind_signature import blind_token, create_token, sign_blinded_message, unblind_signature, verify_final_signature
from app.main import app


def test_blind_signature_demo_routes_disabled_by_default():
    with TestClient(app) as client:
        response = client.post(
            "/api/blind-signature/sessions",
            json={"purpose": "anonymous_access_token", "ttlSeconds": 600},
        )

    assert response.status_code == 404


def test_blind_signature_helper_success_flow():
    token = create_token("anonymous_access_token")
    blinded = blind_token(token)
    blind_signature = sign_blinded_message(blinded["blindedMessageBase64"])
    final_signature = unblind_signature(blind_signature, blinded["blindingFactorBase64"])

    assert verify_final_signature(token, final_signature) is True


def test_blind_signature_helper_tampered_token_fails():
    token = create_token("anonymous_access_token")
    blinded = blind_token(token)
    blind_signature = sign_blinded_message(blinded["blindedMessageBase64"])
    final_signature = unblind_signature(blind_signature, blinded["blindingFactorBase64"])
    tampered_token = dict(token)
    tampered_token["nonce"] = "tampered"

    assert verify_final_signature(tampered_token, final_signature) is False


def test_blind_signature_invalid_purpose_fails():
    try:
        create_token("sign_document")
    except ValueError as exc:
        assert str(exc) == "Invalid blind signature purpose"
    else:
        raise AssertionError("Invalid blind signature purpose should fail")
