import os

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

from .config import SYNC_SEEDED_USERS

DATABASE_URL = os.getenv("SECUREDOC_DATABASE_URL", "sqlite:///./securedoc.db")

engine_options = {"connect_args": {"check_same_thread": False}}
if DATABASE_URL == "sqlite:///:memory:":
    engine_options["poolclass"] = StaticPool

engine = create_engine(DATABASE_URL, **engine_options)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    _ensure_sqlite_columns()
    _seed_default_users()


def _seed_default_users() -> None:
    from .crypto_utils import utc_now
    from .models import User

    defaults = [
        ("tai.dv230062@sis.hust.edu.vn", "Default Signer", "CA_OFFICER"),
        ("vutuanminhvtm2k5@gmail.com", "Tester", "CA_OFFICER" ),
        ("signer@example.com", "Test Signer", "SIGNER"),
        ("other-signer@example.com", "Other Signer", "SIGNER"),
        ("nguyenhathanhdz2k5@gmail.com", "Pytest CA Officer", "CA_OFFICER"),
        ("pytest-ca@example.com", "Pytest CA Officer", "CA_OFFICER"),
        ("pytest-auditor@example.com", "Pytest Auditor", "AUDITOR"),
        ("pytest-verifier@example.com", "Pytest Verifier", "VERIFIER"),
        ("api-otp@example.com", "API OTP Signer", "SIGNER"),
        ("mfa@example.com", "MFA Signer", "SIGNER"),
        ("totp-contract@example.com", "TOTP Contract Signer", "SIGNER"),
        ("enabled-mfa@example.com", "Enabled MFA Signer", "SIGNER"),
        ("demo-admin@example.com", "Demo Admin", "ADMIN"),
        ("demo-ca-officer@example.com", "Demo CA Officer", "CA_OFFICER"),
        ("demo-auditor@example.com", "Demo Auditor", "AUDITOR"),
        ("demo-verifier@example.com", "Demo Verifier", "VERIFIER"),
    ]
    now = utc_now().replace(tzinfo=None)
    with SessionLocal() as db:
        for email, name, role in defaults:
            user = db.get(User, email)
            if not user:
                db.add(User(email=email, name=name, role=role, status="active", created_at=now, updated_at=now))
            elif SYNC_SEEDED_USERS:
                user.name = name
                user.role = role
                user.status = "active"
                user.updated_at = now
        db.commit()


def _ensure_sqlite_columns() -> None:
    if not DATABASE_URL.startswith("sqlite"):
        return

    inspector = inspect(engine)
    table_names = inspector.get_table_names()
    certificate_existing = {column["name"] for column in inspector.get_columns("certificates")} if "certificates" in table_names else set()
    certificate_additions = {
        "certificate_type": "VARCHAR DEFAULT 'legacy-demo' NOT NULL",
        "fingerprint_sha256": "VARCHAR",
        "key_size_bits": "INTEGER",
        "user_certificate_pem": "TEXT",
        "intermediate_certificate_pem": "TEXT",
        "root_certificate_pem": "TEXT",
    }
    with engine.begin() as connection:
        if "users" in table_names:
            user_existing = {column["name"] for column in inspector.get_columns("users")}
            user_additions = {
                "name": "VARCHAR DEFAULT '' NOT NULL",
                "role": "VARCHAR DEFAULT 'SIGNER' NOT NULL",
                "status": "VARCHAR DEFAULT 'active' NOT NULL",
                "created_at": "DATETIME",
                "updated_at": "DATETIME",
            }
            for column_name, column_type in user_additions.items():
                if column_name not in user_existing:
                    connection.execute(text(f"ALTER TABLE users ADD COLUMN {column_name} {column_type}"))

        for column_name, column_type in certificate_additions.items():
            if "certificates" in table_names and column_name not in certificate_existing:
                connection.execute(text(f"ALTER TABLE certificates ADD COLUMN {column_name} {column_type}"))

        if "signing_requests" in table_names:
            signing_request_existing = {column["name"] for column in inspector.get_columns("signing_requests")}
            signing_request_additions = {
                "confirmation_method": "VARCHAR",
                "confirmed_at": "DATETIME",
                "signing_intent": "TEXT",
                "expires_at": "DATETIME",
            }
            for column_name, column_type in signing_request_additions.items():
                if column_name not in signing_request_existing:
                    connection.execute(text(f"ALTER TABLE signing_requests ADD COLUMN {column_name} {column_type}"))

        if "email_otp_tokens" in table_names:
            otp_existing = {column["name"] for column in inspector.get_columns("email_otp_tokens")}
            otp_additions = {
                "signing_request_id": "VARCHAR",
                "document_hash": "VARCHAR",
                "certificate_serial": "VARCHAR",
                "signing_purpose": "VARCHAR",
                "nonce": "VARCHAR",
            }
            for column_name, column_type in otp_additions.items():
                if column_name not in otp_existing:
                    connection.execute(text(f"ALTER TABLE email_otp_tokens ADD COLUMN {column_name} {column_type}"))

        if "documents" in table_names:
            document_existing = {column["name"] for column in inspector.get_columns("documents")}
            document_additions = {
                "previous_document_id": "VARCHAR",
                "immutable": "INTEGER DEFAULT 0 NOT NULL",
            }
            for column_name, column_type in document_additions.items():
                if column_name not in document_existing:
                    connection.execute(text(f"ALTER TABLE documents ADD COLUMN {column_name} {column_type}"))
