"""Runtime security configuration for SecureDoc."""

import os
from pathlib import Path


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


SECUREDOC_ENV = os.getenv("SECUREDOC_ENV", "development").strip().lower()
IS_PRODUCTION = SECUREDOC_ENV in {"prod", "production"}

ENABLE_LEGACY_DEMO = _bool_env("ENABLE_LEGACY_DEMO", False) and not IS_PRODUCTION
ENABLE_BLIND_SIGNATURE_DEMO = _bool_env("ENABLE_BLIND_SIGNATURE_DEMO", False) and not IS_PRODUCTION
REQUEST_SIZE_LIMIT_BYTES = int(os.getenv("SECUREDOC_REQUEST_SIZE_LIMIT_BYTES", str(2 * 1024 * 1024)))
RATE_LIMIT_REQUESTS_PER_MINUTE = int(os.getenv("SECUREDOC_RATE_LIMIT_REQUESTS_PER_MINUTE", "120"))
SMTP_HOST = os.getenv("SECUREDOC_SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SECUREDOC_SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SECUREDOC_SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.getenv("SECUREDOC_SMTP_PASSWORD", "")
SMTP_FROM_EMAIL = os.getenv("SECUREDOC_SMTP_FROM_EMAIL", SMTP_USERNAME or "no-reply@securedoc.local").strip()
SMTP_USE_TLS = _bool_env("SECUREDOC_SMTP_USE_TLS", True)
CORS_ALLOW_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "SECUREDOC_CORS_ALLOW_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
]

if IS_PRODUCTION and "*" in CORS_ALLOW_ORIGINS:
    raise RuntimeError("Wildcard CORS origins are not allowed in production")

RUNTIME_SECRETS_DIR = Path(
    os.getenv(
        "SECUREDOC_RUNTIME_SECRETS_DIR",
        str(Path(__file__).resolve().parents[2] / ".securedoc-runtime"),
    )
)


def ensure_runtime_secrets_dir() -> Path:
    RUNTIME_SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    return RUNTIME_SECRETS_DIR


def ensure_demo_plaintext_keys_allowed() -> None:
    """Block plaintext demo key custody in production-like mode."""
    if IS_PRODUCTION:
        raise RuntimeError(
            "SecureDoc demo plaintext CA/TSA keys are disabled in production. "
            "Use HSM/KMS/remote signing or run with SECUREDOC_ENV=development."
        )
