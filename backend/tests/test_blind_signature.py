import sys
import os
from pathlib import Path

os.environ["SECUREDOC_DATABASE_URL"] = "sqlite:///:memory:"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient

from app.blind_signature import unblind_signature
from app.main import app


def test_blind_signature_success_flow():
    with TestClient(app) as client:
        session = _create_session(client)
        signed = _sign_blinded(client, session)
        final_signature = unblind_signature(signed["blindSignatureBase64"], session["blindingFactorBase64"])

        verify = client.post(
            "/api/blind-signature/verify",
            json={
                "sessionId": session["sessionId"],
                "token": session["token"],
                "finalSignatureBase64": final_signature,
            },
        )
        redeem = client.post(
            "/api/blind-signature/redeem",
            json={
                "sessionId": session["sessionId"],
                "token": session["token"],
                "finalSignatureBase64": final_signature,
            },
        )

    assert verify.status_code == 200
    assert verify.json()["valid"] is True
    assert redeem.status_code == 200
    assert redeem.json()["redeemed"] is True


def test_blind_signature_tampered_token_fails():
    with TestClient(app) as client:
        session = _create_session(client)
        signed = _sign_blinded(client, session)
        final_signature = unblind_signature(signed["blindSignatureBase64"], session["blindingFactorBase64"])
        tampered_token = dict(session["token"])
        tampered_token["nonce"] = "tampered"

        response = client.post(
            "/api/blind-signature/verify",
            json={
                "sessionId": session["sessionId"],
                "token": tampered_token,
                "finalSignatureBase64": final_signature,
            },
        )

    assert response.status_code == 200
    assert response.json()["valid"] is False
    assert response.json()["reason"] == "token does not match session"


def test_blind_signature_double_redeem_fails():
    with TestClient(app) as client:
        session = _create_session(client)
        signed = _sign_blinded(client, session)
        final_signature = unblind_signature(signed["blindSignatureBase64"], session["blindingFactorBase64"])
        body = {
            "sessionId": session["sessionId"],
            "token": session["token"],
            "finalSignatureBase64": final_signature,
        }

        first = client.post("/api/blind-signature/redeem", json=body)
        second = client.post("/api/blind-signature/redeem", json=body)

    assert first.status_code == 200
    assert first.json()["redeemed"] is True
    assert second.status_code == 200
    assert second.json()["redeemed"] is False
    assert second.json()["reason"] == "token already spent"


def test_blind_signature_expired_token_fails():
    with TestClient(app) as client:
        session = _create_session(client, ttl_seconds=-1)

        response = client.post(
            "/api/blind-signature/sign",
            json={
                "sessionId": session["sessionId"],
                "blindedMessageBase64": session["blindedMessageBase64"],
            },
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "Blind signature session expired"


def test_blind_signature_invalid_purpose_fails():
    with TestClient(app) as client:
        response = client.post(
            "/api/blind-signature/sessions",
            json={"purpose": "sign_document", "ttlSeconds": 600},
        )

    assert response.status_code in {400, 422}


def _create_session(client: TestClient, ttl_seconds: int = 600):
    response = client.post(
        "/api/blind-signature/sessions",
        json={"purpose": "anonymous_access_token", "ttlSeconds": ttl_seconds},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["token"]["tokenVersion"] == "1.0"
    assert data["token"]["purpose"] == "anonymous_access_token"
    assert data["blindedMessageBase64"]
    assert data["blindingFactorBase64"]
    return data


def _sign_blinded(client: TestClient, session: dict):
    response = client.post(
        "/api/blind-signature/sign",
        json={
            "sessionId": session["sessionId"],
            "blindedMessageBase64": session["blindedMessageBase64"],
        },
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["blindSignatureBase64"]
    return data
