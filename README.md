# SecureDoc

SecureDoc is a local educational web app for digital signatures. The main flow is now v2 client-side signing:

- The browser generates the RSA signing key pair with Web Crypto.
- The backend receives only `publicKeyPem` and issues an `x509-demo` signing certificate.
- The browser signs canonical JSON of `signingPayload`.
- The backend receives only a `signedPackage`, verifies it, issues a demo timestamp token, stores it, and returns a detailed verification report.
- The legacy `/api/keys/generate` endpoint is kept only as a debug demo because it creates private keys in the backend.
- The legacy `/api/sign` endpoint is kept only as an insecure compatibility demo because it receives `privateKeyPem`.
- Blind signatures are separated into their own token flow for privacy demos: blind -> sign blinded token -> unblind -> verify -> redeem.

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

## Main V2 Flow

Use the `Documents` tab for the classroom demo:

1. Generate key in browser.
2. Request X.509 demo certificate.
3. Upload or select document.
4. Create signing request.
5. Review `signingPayload`.
6. Enter demo PIN `123456`.
7. Sign in browser.
8. Submit `signedPackage`.
9. Inspect verification report.
10. Revoke certificate and verify again.

The older `Sign v2`, `Verify v2`, and `Revoke` tabs are still available as focused tools. The legacy sign tab is not part of the main flow.

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
- Revocation uses server DB `serialNumber`, not the package `status` field.
- `GET /api/certificates/crl` returns a signed demo CRL generated from revoked server records.
- `GET /api/audit/verify-chain` verifies the audit log hash chain.
- The UI includes a PDF visual stamp preview for presentation only.
- Basic audit logs are recorded for certificate issuance, signing requests, timestamp issuance, signature submission, signature verification, CRL generation, and certificate revocation.
- Blind signature code is separated from document signing. The signer signs only `blindedMessageBase64`, and redeem prevents double spending.

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
- `signedAtClient` remains client-declared time; only `timestampToken` is signed by the demo TSA.
- The visual stamp preview is not PAdES and does not make a PDF legally signed.
- Blind signatures are educational only, not production e-voting/e-cash and not a replacement for document signing.
- Replay checks are local to the server DB.
- No production authentication, authorization, rate limiting, HTTPS hardening, or key custody controls are implemented.
