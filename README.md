# SecureDoc

SecureDoc is a local educational web app for digital signatures. The main flow is now v2 client-side signing:

- The browser generates the RSA signing key pair with Web Crypto.
- The backend receives only `publicKeyPem` and issues an `x509-demo` signing certificate.
- The browser signs canonical JSON of `signingPayload`.
- The backend receives only a `signedPackage`, verifies it, issues a demo timestamp token, stores it, and returns a detailed verification report.
- The legacy `/api/keys/generate` and `/api/sign` endpoints are disabled by default because they move private keys through the backend.
- Blind signatures are separated into their own token flow for privacy demos and are disabled by default.

## Architecture

```text
SecureDoc/
  backend/    FastAPI, cryptography, SQLite, SQLAlchemy
  frontend/   React + Vite + TypeScript
  docs/       API and demo notes
```

## Run Backend

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Backend: `http://127.0.0.1:8000`

Swagger: `http://127.0.0.1:8000/docs`

Useful security/demo flags:

```powershell
$env:SECUREDOC_ENV="development"
$env:ENABLE_LEGACY_DEMO="false"
$env:ENABLE_BLIND_SIGNATURE_DEMO="false"
$env:SECUREDOC_RUNTIME_SECRETS_DIR="D:\projects\SecureDoc\.securedoc-runtime"
```

`ENABLE_LEGACY_DEMO` and `ENABLE_BLIND_SIGNATURE_DEMO` default to `false`. Set them to `true` only for explicit classroom compatibility demos. Demo CA/TSA/blind-signature keys are written under `.securedoc-runtime/` by default and are ignored by git.

Phase 1 stabilization also adds:

- Demo RBAC headers for sensitive endpoints: `X-SecureDoc-User` and `X-SecureDoc-Role`.
- Roles: `ADMIN`, `CA_OFFICER`, `SIGNER`, `VERIFIER`, `AUDITOR`.
- Email OTP storage with hash, purpose, expiry, used time, and attempt count. The API does not return OTP values.
- TOTP Authenticator setup primitives for MFA design. This is still not a full production login system.
- Request size limit, in-memory rate limit, and CORS allowlist configuration.

## Run Frontend

```powershell
cd frontend
npm install
npm run dev
```

Frontend: `http://127.0.0.1:5173`

## Test

```powershell
python -m pytest backend/tests
npm --prefix frontend run build
```

GitHub Actions workflow is available at `.github/workflows/ci.yml` and runs
backend pytest plus frontend production build on push and pull request.

## Main V2 Flow

Use the `Documents` tab for the classroom demo:

1. Generate key in browser.
2. Request X.509 demo certificate.
3. Upload or select document.
4. Create signing request.
5. Review `signingPayload`.
6. Review the signing payload and confirm the signing intent.
7. Sign in browser.
8. Submit `signedPackage`.
9. Inspect verification report.
10. Revoke certificate and verify again.

The older `Sign v2`, `Verify v2`, and `Revoke` tabs are still available as focused tools. Legacy private-key API tabs are hidden in the default UI.

## Demo Guide

See [docs/demo-guide.md](docs/demo-guide.md) for:

- Case 1: sign original file and verify successfully.
- Case 2: modify file and verify fails.
- Case 3: revoke certificate and verify fails.
- Case 4: inspect verification report.
- Case 5: check audit chain.

## What Improved

- The main signing flow no longer sends private keys to the backend.
- The main certificate is now a PEM X.509 demo certificate issued as `Demo Root CA -> Demo Intermediate CA -> User Signing Certificate`.
- User certificates include subject, issuer, serial, validity, SubjectPublicKeyInfo, BasicConstraints CA=false, KeyUsage digitalSignature/contentCommitment, SubjectKeyIdentifier, and AuthorityKeyIdentifier.
- Demo CA certificates include BasicConstraints CA=true and KeyUsage keyCertSign/cRLSign.
- Signatures cover canonical JSON `signingPayload`, not only a detached document hash.
- The backend verifies algorithm policy, certificate trust, certificate DB record, validity period, revocation status, replay state, and signature validity.
- The verification report separates cryptographic validity from trust, revocation, timestamp, server acceptance, and legal readiness fields.
- Revocation uses server DB `serialNumber`, not the package `status` field.
- `GET /api/certificates/crl` returns a signed demo CRL generated from revoked server records.
- `GET /api/audit/verify-chain` verifies the audit log hash chain.
- The UI includes a PDF visual stamp preview for presentation only.
- Basic audit logs are recorded for certificate issuance, signing requests, timestamp issuance, signature submission, signature verification, CRL generation, and certificate revocation.
- Blind signature code is separated from document signing and disabled by default. When enabled for demo, the signer signs only `blindedMessageBase64`, and redeem prevents double spending.

## Blind Signature Flow

Blind signatures are different from the document signature flow:

- Digital document signatures identify who signed a document and bind that signer to the content.
- Blind signatures are useful when the signer should authorize a token without seeing the original token, such as privacy-preserving access, classroom e-voting demos, or e-cash demos.

Main blind token flow:

1. Create token with `tokenId`, `purpose`, `createdAt`, `expiresAt`, `nonce`, and `tokenVersion`.
2. Blind token hash in the requester/browser.
3. Signer signs only `blindedMessageBase64`.
4. Requester unblinds the blind signature.
5. Verify final signature on the original token.
6. Redeem token.
7. Redeem again fails because the token is spent.

## Remaining Demo Limits

- The X.509 CA chain is demo/local only, not a public CA and not legally valid.
- The CRL and TSA are demo JSON tokens, not standards-complete OCSP/CRL or RFC 3161 timestamping.
- There is no HSM, smart card, USB token, public CA trust, PAdES, XAdES, or CAdES.
- `legalReady` is always `false` until trusted CA, RFC 3161 timestamping, PAdES/CAdES/XAdES policy, revocation evidence, identity proofing, and production key custody are implemented.
- `signedAtClient` remains client-declared time; only `timestampToken` is signed by the demo TSA.
- The visual stamp preview is not PAdES and does not make a PDF legally signed.
- Blind signatures are educational only, not production e-voting/e-cash and not a replacement for document signing.
- Replay checks are local to the server DB.
- Phase 1 includes demo RBAC, CORS allowlist, request size limit, and in-memory rate limit. It is not production authentication or full HTTPS/session hardening.

## Phase 9 Hardening Notes

- `GET /api/system/security-readiness` gives `ADMIN`/`AUDITOR` users a non-secret readiness report for CORS, request size limit, rate limit, security headers, HTTPS/HSTS mode, JWT secret configuration, SMTP delivery, database recommendation, and legal readiness.
- `SECUREDOC_ENV=production` disables demo-only auth/OTP/blind-signature flags and rejects wildcard CORS or the default JWT secret.
- SQLite is still the local/demo database. Production should use PostgreSQL with migrations.
- Final limitations remain explicit: no public CA, no HSM/KMS, no production RFC 3161 TSA, no full PAdES-LTV, no legal-grade signature claim, Gmail SMTP only as demo/dev sender.
