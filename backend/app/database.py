import os

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

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


def _ensure_sqlite_columns() -> None:
    if not DATABASE_URL.startswith("sqlite"):
        return

    inspector = inspect(engine)
    if "certificates" not in inspector.get_table_names():
        return

    existing = {column["name"] for column in inspector.get_columns("certificates")}
    additions = {
        "certificate_type": "VARCHAR DEFAULT 'legacy-demo' NOT NULL",
        "fingerprint_sha256": "VARCHAR",
        "key_size_bits": "INTEGER",
        "user_certificate_pem": "TEXT",
        "intermediate_certificate_pem": "TEXT",
        "root_certificate_pem": "TEXT",
    }
    with engine.begin() as connection:
        for column_name, column_type in additions.items():
            if column_name not in existing:
                connection.execute(text(f"ALTER TABLE certificates ADD COLUMN {column_name} {column_type}"))

