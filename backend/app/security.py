"""Minimal Phase 1 auth and request hardening helpers.

This is a demo JWT/RBAC guard, not a production identity provider. Production
must replace it with real login/session/JWT, MFA enforcement, and audited user
IDs.
"""

import base64
import hashlib
import hmac
import json
import time
from collections.abc import Iterable
from typing import Any

from fastapi import Header, HTTPException, status

from .config import ENABLE_DEMO_HEADER_AUTH, JWT_SECRET, JWT_TTL_SECONDS

Role = str

ADMIN = "ADMIN"
CA_OFFICER = "CA_OFFICER"
SIGNER = "SIGNER"
VERIFIER = "VERIFIER"
AUDITOR = "AUDITOR"

VALID_ROLES = {ADMIN, CA_OFFICER, SIGNER, VERIFIER, AUDITOR}
JWT_TYP = "securedoc-demo-access"


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid token encoding") from exc


def _json_b64url(value: dict[str, Any]) -> str:
    return _b64url_encode(json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _sign(message: str) -> str:
    signature = hmac.new(JWT_SECRET.encode("utf-8"), message.encode("ascii"), hashlib.sha256).digest()
    return _b64url_encode(signature)


def create_demo_access_token(user: str, role: Role) -> str:
    normalized_role = role.strip().upper()
    if normalized_role not in VALID_ROLES:
        raise ValueError("Invalid role")
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user.strip().lower(),
        "role": normalized_role,
        "iat": now,
        "exp": now + JWT_TTL_SECONDS,
        "typ": JWT_TYP,
    }
    signing_input = f"{_json_b64url(header)}.{_json_b64url(payload)}"
    return f"{signing_input}.{_sign(signing_input)}"


def _decode_demo_access_token(token: str) -> dict[str, str]:
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bearer token")

    signing_input = f"{parts[0]}.{parts[1]}"
    expected_signature = _sign(signing_input)
    if not hmac.compare_digest(expected_signature, parts[2]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bearer token")

    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bearer token") from exc

    if header.get("alg") != "HS256":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bearer token")
    if payload.get("typ") != JWT_TYP:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bearer token")

    subject = payload.get("sub")
    role = payload.get("role")
    issued_at = payload.get("iat")
    expires_at = payload.get("exp")
    if not isinstance(subject, str) or not subject.strip():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bearer token")
    if not isinstance(role, str):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bearer token")
    if not isinstance(issued_at, int) or not isinstance(expires_at, int):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bearer token")
    if expires_at <= int(time.time()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer token expired")

    normalized_role = role.strip().upper()
    if normalized_role not in VALID_ROLES:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid role")
    return {"user": subject.strip().lower(), "role": normalized_role}


def _actor_from_demo_header(user: str | None, role: str | None) -> dict[str, str] | None:
    if not ENABLE_DEMO_HEADER_AUTH:
        return None
    if not user or not role:
        return None
    normalized_role = role.strip().upper()
    if normalized_role not in VALID_ROLES:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid role")
    return {"user": user.strip().lower(), "role": normalized_role}


def require_roles(*allowed_roles: Role):
    allowed = set(allowed_roles)

    def dependency(
        authorization: str | None = Header(default=None, alias="Authorization"),
        x_securedoc_role: str | None = Header(default=None, alias="X-SecureDoc-Role"),
        x_securedoc_user: str | None = Header(default=None, alias="X-SecureDoc-User"),
    ) -> dict[str, str]:
        actor: dict[str, str] | None = None
        if authorization:
            scheme, _, token = authorization.partition(" ")
            if scheme.lower() != "bearer" or not token.strip():
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authorization header",
                )
            actor = _decode_demo_access_token(token.strip())
        else:
            actor = _actor_from_demo_header(x_securedoc_user, x_securedoc_role)

        if actor is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
            )

        role = actor["role"]
        if role not in VALID_ROLES:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid role",
            )
        if role not in allowed and role != ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role",
            )
        return actor

    return dependency


def auth_headers(user: str, role: Role) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_demo_access_token(user, role)}"}


def role_headers(user: str, role: Role) -> dict[str, str]:
    return auth_headers(user, role)


def any_role(roles: Iterable[Role]) -> tuple[Role, ...]:
    return tuple(roles)
