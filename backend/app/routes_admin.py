"""Admin user management routes for the Phase 4 user service."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .audit_service import log_audit
from .crypto_utils import isoformat, utc_now
from .database import SessionLocal
from .models import User
from .schemas import UserCreateRequest, UserResponse, UserUpdateRequest
from .security import ADMIN, require_roles

router = APIRouter(prefix="/api/admin", tags=["admin"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _actor_email(actor: dict[str, str]) -> str:
    return actor["user"].strip().lower()


def _user_to_response(user: User) -> UserResponse:
    return UserResponse(
        email=user.email,
        name=user.name,
        role=user.role,
        status=user.status,
        createdAt=_db_iso(user.created_at),
        updatedAt=_db_iso(user.updated_at),
    )


def _db_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return isoformat(value)


def _clean_name(name: str) -> str:
    cleaned = name.strip()
    if not cleaned:
        raise HTTPException(status_code=400, detail="User name is required")
    return cleaned


@router.get("/users")
def list_users(
    db: Session = Depends(get_db),
    actor: dict[str, str] = Depends(require_roles(ADMIN)),
):
    users = db.query(User).order_by(User.email.asc()).all()
    return {"users": [_user_to_response(user) for user in users]}


@router.post("/users", response_model=UserResponse, status_code=201)
def create_user(
    body: UserCreateRequest,
    db: Session = Depends(get_db),
    actor: dict[str, str] = Depends(require_roles(ADMIN)),
):
    email = body.email.strip().lower()
    if db.get(User, email):
        raise HTTPException(status_code=409, detail="User already exists")

    now = utc_now().replace(tzinfo=None)
    user = User(
        email=email,
        name=_clean_name(body.name),
        role=body.role,
        status=body.status,
        created_at=now,
        updated_at=now,
    )
    db.add(user)
    log_audit(
        db,
        "user_created",
        _actor_email(actor),
        "success",
        details=f"target={email}; role={user.role}; status={user.status}",
    )
    db.commit()
    db.refresh(user)
    return _user_to_response(user)


@router.get("/users/{email}", response_model=UserResponse)
def get_user(
    email: str,
    db: Session = Depends(get_db),
    actor: dict[str, str] = Depends(require_roles(ADMIN)),
):
    user = db.get(User, email.strip().lower())
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return _user_to_response(user)


@router.patch("/users/{email}", response_model=UserResponse)
def update_user(
    email: str,
    body: UserUpdateRequest,
    db: Session = Depends(get_db),
    actor: dict[str, str] = Depends(require_roles(ADMIN)),
):
    normalized_email = email.strip().lower()
    user = db.get(User, normalized_email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    changes: list[str] = []
    if body.name is not None:
        new_name = _clean_name(body.name)
        if user.name != new_name:
            user.name = new_name
            changes.append("name")
    if body.role is not None and user.role != body.role:
        user.role = body.role
        changes.append(f"role={body.role}")
    if body.status is not None and user.status != body.status:
        user.status = body.status
        changes.append(f"status={body.status}")
    if not changes:
        raise HTTPException(status_code=400, detail="No user changes provided")

    user.updated_at = utc_now().replace(tzinfo=None)
    log_audit(
        db,
        "user_updated",
        _actor_email(actor),
        "success",
        details=f"target={normalized_email}; changes={','.join(changes)}",
    )
    db.commit()
    db.refresh(user)
    return _user_to_response(user)


@router.post("/users/{email}/disable", response_model=UserResponse)
def disable_user(
    email: str,
    db: Session = Depends(get_db),
    actor: dict[str, str] = Depends(require_roles(ADMIN)),
):
    return _set_user_status(email, "disabled", "user_disabled", db, actor)


@router.post("/users/{email}/enable", response_model=UserResponse)
def enable_user(
    email: str,
    db: Session = Depends(get_db),
    actor: dict[str, str] = Depends(require_roles(ADMIN)),
):
    return _set_user_status(email, "active", "user_enabled", db, actor)


def _set_user_status(
    email: str,
    status: str,
    event_type: str,
    db: Session,
    actor: dict[str, str],
) -> UserResponse:
    normalized_email = email.strip().lower()
    user = db.get(User, normalized_email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.status == status:
        raise HTTPException(status_code=400, detail=f"User is already {status}")

    user.status = status
    user.updated_at = utc_now().replace(tzinfo=None)
    log_audit(
        db,
        event_type,
        _actor_email(actor),
        "success",
        details=f"target={normalized_email}",
    )
    db.commit()
    db.refresh(user)
    return _user_to_response(user)
