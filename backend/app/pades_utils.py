"""PAdES PDF signing helpers backed by pyHanko.

This module creates a standards-shaped PDF signature (ByteRange + CMS/CAdES
detached signature) for product demos. The default signer key is still a local
demo key; production deployments should replace it with HSM/KMS/remote signing.
"""

from __future__ import annotations

import io
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers, timestamps

from .config import RFC3161_TSA_URL, ensure_demo_plaintext_keys_allowed, ensure_runtime_secrets_dir
from .x509_utils import issue_user_x509_certificate

PADES_SIGNER_KEY_PATH = ensure_runtime_secrets_dir() / "securedoc_pades_demo_signer_private.pem"
PADES_SIGNER_CERT_PATH = ensure_runtime_secrets_dir() / "securedoc_pades_demo_signer_cert.pem"
PADES_SIGNER_INTERMEDIATE_PATH = ensure_runtime_secrets_dir() / "securedoc_pades_demo_intermediate_ca.pem"
PADES_SIGNER_ROOT_PATH = ensure_runtime_secrets_dir() / "securedoc_pades_demo_root_ca.pem"


def _private_key_pem(private_key: rsa.RSAPrivateKey) -> bytes:
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _public_key_pem(private_key: rsa.RSAPrivateKey) -> str:
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def ensure_demo_pades_signer() -> dict[str, Path]:
    ensure_demo_plaintext_keys_allowed()
    if PADES_SIGNER_KEY_PATH.exists() and PADES_SIGNER_CERT_PATH.exists():
        return {
            "key": PADES_SIGNER_KEY_PATH,
            "cert": PADES_SIGNER_CERT_PATH,
            "intermediate": PADES_SIGNER_INTERMEDIATE_PATH,
            "root": PADES_SIGNER_ROOT_PATH,
        }

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    issued = issue_user_x509_certificate(
        "SecureDoc PAdES Demo Signer",
        "pades-signer@securedoc.local",
        _public_key_pem(private_key),
    )
    PADES_SIGNER_KEY_PATH.write_bytes(_private_key_pem(private_key))
    PADES_SIGNER_CERT_PATH.write_text(issued["userCertificatePem"], encoding="utf-8")
    PADES_SIGNER_INTERMEDIATE_PATH.write_text(issued["intermediateCertificatePem"], encoding="utf-8")
    PADES_SIGNER_ROOT_PATH.write_text(issued["rootCertificatePem"], encoding="utf-8")
    return {
        "key": PADES_SIGNER_KEY_PATH,
        "cert": PADES_SIGNER_CERT_PATH,
        "intermediate": PADES_SIGNER_INTERMEDIATE_PATH,
        "root": PADES_SIGNER_ROOT_PATH,
    }


def sign_pdf_pades(
    pdf_bytes: bytes,
    *,
    reason: str = "SecureDoc document approval",
    location: str = "SecureDoc",
    signer_name: str = "SecureDoc PAdES Demo Signer",
) -> tuple[bytes, str]:
    if not pdf_bytes.startswith(b"%PDF-"):
        raise ValueError("Input is not a PDF file")

    paths = ensure_demo_pades_signer()
    signer = signers.SimpleSigner.load(
        key_file=str(paths["key"]),
        cert_file=str(paths["cert"]),
        ca_chain_files=[str(paths["intermediate"]), str(paths["root"])],
        prefer_pss=True,
    )
    timestamper = timestamps.HTTPTimeStamper(RFC3161_TSA_URL) if RFC3161_TSA_URL else None
    profile = "PAdES-B-T" if timestamper else "PAdES-B-B"
    metadata = signers.PdfSignatureMetadata(
        field_name="SecureDocSignature",
        md_algorithm="sha256",
        reason=reason,
        location=location,
        name=signer_name,
        subfilter=fields.SigSeedSubFilter.PADES,
    )
    pdf_signer = signers.PdfSigner(
        metadata,
        signer=signer,
        timestamper=timestamper,
        new_field_spec=fields.SigFieldSpec(sig_field_name="SecureDocSignature"),
    )
    input_stream = io.BytesIO(pdf_bytes)
    output = io.BytesIO()
    writer = IncrementalPdfFileWriter(input_stream)
    pdf_signer.sign_pdf(writer, output=output)
    return output.getvalue(), profile
