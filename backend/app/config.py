"""Runtime security configuration for SecureDoc."""

import os
from pathlib import Path


def _load_dotenv_file(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


for _env_path in (
    Path(__file__).resolve().parents[2] / ".env",
    Path(__file__).resolve().parents[1] / ".env",
):
    _load_dotenv_file(_env_path)


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


SECUREDOC_ENV = os.getenv("SECUREDOC_ENV", "development").strip().lower()
IS_PRODUCTION = SECUREDOC_ENV in {"prod", "production"}

ENABLE_LEGACY_DEMO = _bool_env("ENABLE_LEGACY_DEMO", False) and not IS_PRODUCTION
ENABLE_BLIND_SIGNATURE_DEMO = _bool_env("ENABLE_BLIND_SIGNATURE_DEMO", False) and not IS_PRODUCTION
ENABLE_DEMO_HEADER_AUTH = _bool_env("ENABLE_DEMO_HEADER_AUTH", False) and not IS_PRODUCTION
JWT_SECRET = os.getenv("SECUREDOC_JWT_SECRET", "development-only-change-me-jwt-secret").strip()
JWT_TTL_SECONDS = int(os.getenv("SECUREDOC_JWT_TTL_SECONDS", "3600"))
REQUEST_SIZE_LIMIT_BYTES = int(os.getenv("SECUREDOC_REQUEST_SIZE_LIMIT_BYTES", str(2 * 1024 * 1024)))
RATE_LIMIT_REQUESTS_PER_MINUTE = int(os.getenv("SECUREDOC_RATE_LIMIT_REQUESTS_PER_MINUTE", "120"))
HTTPS_ONLY = _bool_env("SECUREDOC_HTTPS_ONLY", IS_PRODUCTION)
RFC3161_TSA_URL = os.getenv("SECUREDOC_RFC3161_TSA_URL", "").strip()
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

if IS_PRODUCTION and JWT_SECRET == "development-only-change-me-jwt-secret":
    raise RuntimeError("SECUREDOC_JWT_SECRET must be set to a strong random value in production")

RUNTIME_SECRETS_DIR = Path(
    os.getenv(
        "SECUREDOC_RUNTIME_SECRETS_DIR",
        str(Path(__file__).resolve().parents[2] / ".securedoc-runtime"),
    )
)


def ensure_runtime_secrets_dir() -> Path:
    RUNTIME_SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    return RUNTIME_SECRETS_DIR


DOCUMENT_STORAGE_DIR = Path(
    os.getenv(
        "SECUREDOC_DOCUMENT_STORAGE_DIR",
        str(RUNTIME_SECRETS_DIR / "documents"),
    )
)


def ensure_document_storage_dir() -> Path:
    DOCUMENT_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    return DOCUMENT_STORAGE_DIR


def ensure_demo_plaintext_keys_allowed() -> None:
    """Block plaintext demo key custody in production-like mode."""
    if IS_PRODUCTION:
        raise RuntimeError(
            "SecureDoc demo plaintext CA/TSA keys are disabled in production. "
            "Use HSM/KMS/remote signing or run with SECUREDOC_ENV=development."
        )
