"""Minimal Phase 1 auth and request hardening helpers.

This is a demo RBAC guard, not a production identity provider. Production must
replace it with real login/session/JWT, MFA enforcement, and audited user IDs.
"""

from collections.abc import Iterable

from fastapi import Header, HTTPException, status

Role = str

ADMIN = "ADMIN"
CA_OFFICER = "CA_OFFICER"
SIGNER = "SIGNER"
VERIFIER = "VERIFIER"
AUDITOR = "AUDITOR"

VALID_ROLES = {ADMIN, CA_OFFICER, SIGNER, VERIFIER, AUDITOR}


def require_roles(*allowed_roles: Role):
    allowed = set(allowed_roles)

    def dependency(
        x_securedoc_role: str | None = Header(default=None, alias="X-SecureDoc-Role"),
        x_securedoc_user: str | None = Header(default=None, alias="X-SecureDoc-User"),
    ) -> dict[str, str]:
        if not x_securedoc_role or not x_securedoc_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
            )
        role = x_securedoc_role.strip().upper()
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
        return {"user": x_securedoc_user, "role": role}

    return dependency


def role_headers(user: str, role: Role) -> dict[str, str]:
    return {"X-SecureDoc-User": user, "X-SecureDoc-Role": role}


def any_role(roles: Iterable[Role]) -> tuple[Role, ...]:
    return tuple(roles)
