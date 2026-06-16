# SecureDoc

SecureDoc is a local educational web app for digital signatures. The main flow is now v2 client-side signing:

- The backend creates or verifies document hashes and signing requests.
- The browser signs canonical JSON of `signingPayload`.
- The backend receives only a `signedPackage`, verifies it, stores it, and returns a detailed verification report.
- The legacy `/api/sign` endpoint is kept only as an insecure compatibility demo because it receives `privateKeyPem`.

Blind signature demo code is left unchanged in this update.

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

1. Generate a demo key pair and legacy-demo certificate.
2. Choose a document, hash algorithm, certificate, private key, and signing purpose in `Sign v2`.
3. Review file name, hash, signer, certificate serial, purpose, `requestId`, and `nonce`.
4. Sign the canonical `signingPayload` in the browser with RSA-PSS.
5. Submit the v2 signed package to the backend.
6. Verify the package in `Verify v2` and inspect the detailed report.

## What Improved

- The main signing flow no longer sends private keys to the backend.
- Signatures cover canonical JSON `signingPayload`, not only a detached document hash.
- The backend verifies algorithm policy, certificate trust, certificate DB record, validity period, revocation status, replay state, and signature validity.
- Revocation uses server DB `serialNumber`, not the package `status` field.
- Basic audit logs are recorded for certificate creation, signing request creation, signature submission, signature verification, and certificate revocation.

## Remaining Demo Limits

- Certificates are still custom legacy-demo JSON certificates, not X.509.
- SecureDoc Demo CA is local demo trust only.
- There is no real CA chain, HSM, TSA, OCSP/CRL, PAdES, XAdES, or CAdES.
- `signedAtClient` is client-declared time, not trusted timestamping.
- Replay checks are local to the server DB.
- No production authentication, authorization, rate limiting, HTTPS hardening, or key custody controls are implemented.
