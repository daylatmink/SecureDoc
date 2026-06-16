# SecureDoc API

Base URL local: `http://127.0.0.1:8000`.

## Tong quan v2

Luon ky chinh hien nay la v2 client-side signing:

1. Client/backend tinh `documentHash` cho file.
2. Client goi `/api/sign/v2/prepare` voi `documentName`, `documentHash`, `hashAlgorithm`, `certificateSerialNumber`, `signingPurpose`.
3. Backend tao `signingPayload` chuan hoa gom:
   `documentName`, `documentHash`, `hashAlgorithm`, `signatureAlgorithm`, signer info,
   `certificateSerialNumber`, `certificateFingerprint`, `signingPurpose`, `requestId`, `nonce`,
   `createdAt`, `payloadVersion`.
4. Client hien man hinh review va ky canonical JSON cua `signingPayload` tai client bang private key.
5. Client gui `signedPackage` toi `/api/sign/v2/submit`.
6. Backend chi verify/luu package; backend khong nhan private key trong luong v2.

Canonicalization method: `JSON-canonical-sorted-keys`.

Signature mac dinh: `RSA-PSS` + `SHA-256`, salt length bang digest size de tuong thich Web Crypto. Backend policy chap nhan `SHA-256`, `SHA-384`, `SHA-512`, `SHA3-256`; khong chap nhan `MD5` hoac `SHA-1`.

Luu y: browser Web Crypto khong ho tro RSA-PSS voi SHA3-256. SHA3-256 co the verify tren backend neu package duoc tao boi client/tool ben ngoai co ho tro SHA3.

## GET /api/algorithm-policy

Tra ve policy thuat toan duoc phep.

```json
{
  "allowedHashAlgorithms": ["SHA-256", "SHA-384", "SHA-512", "SHA3-256"],
  "rejectedHashAlgorithms": ["MD5", "SHA-1"],
  "allowedSignatureAlgorithms": ["RSA-PSS"],
  "minimumRsaKeyBits": 2048,
  "defaultRsaKeyBits": 3072
}
```

## POST /api/keys/generate

Tao RSA key pair va legacy-demo certificate JSON duoc SecureDoc Demo CA ky.

Request:

```json
{
  "name": "Nguyen Van A",
  "email": "student@example.com"
}
```

Response gom `privateKeyPem`, `publicKeyPem`, `certificate`.

Canh bao: endpoint nay tra private key ve client de phuc vu demo local. Production can dung key store, smart card, USB token, HSM hoac signing service bao ve khoa.

Audit event: `certificate_created`. Audit khong ghi private key.

## POST /api/documents/hash

Request `multipart/form-data`:

- `file`: document.
- `hashAlgorithm`: `SHA-256`, `SHA-384`, `SHA-512`, `SHA3-256`. Mac dinh `SHA-256`.

Response:

```json
{
  "documentName": "demo.txt",
  "hashAlgorithm": "SHA-256",
  "documentHash": "b94d27b9934d3e08..."
}
```

## POST /api/sign/v2/prepare

Tao signing request va canonical signing payload. Backend tra signer info tu certificate record trong DB.

Request:

```json
{
  "documentName": "demo.txt",
  "documentHash": "b94d27b9934d3e08...",
  "hashAlgorithm": "SHA-256",
  "certificateSerialNumber": "A1B2C3",
  "signingPurpose": "approve_document"
}
```

Response:

```json
{
  "requestId": "0f9a...",
  "nonce": "d3c1...",
  "signingPayload": {
    "documentName": "demo.txt",
    "documentHash": "b94d27b9934d3e08...",
    "hashAlgorithm": "SHA-256",
    "signatureAlgorithm": "RSA-PSS",
    "signerName": "Nguyen Van A",
    "signerEmail": "student@example.com",
    "certificateSerialNumber": "A1B2C3",
    "certificateFingerprint": "7b8c...",
    "signingPurpose": "approve_document",
    "createdAt": "2026-06-16T00:00:00+00:00",
    "nonce": "d3c1...",
    "requestId": "0f9a...",
    "payloadVersion": "1.0"
  },
  "canonicalPayloadBase64": "eyJjZXJ0...",
  "warnings": [
    "Certificate is a legacy-demo JSON certificate, not X.509.",
    "SecureDoc Demo CA is local demo trust only."
  ]
}
```

Audit event: `signing_request_created`.

## POST /api/sign/v2/submit

Nhan signed package da duoc client ky. Backend verify package va luu signature record.

Request:

```json
{
  "packageVersion": "2.0",
  "signingPayload": {},
  "payloadCanonicalization": "JSON-canonical-sorted-keys",
  "signatureAlgorithm": "RSA-PSS",
  "signatureBase64": "nXk...",
  "signerCertificate": {},
  "signedAtClient": "2026-06-16T00:01:00+00:00"
}
```

Response:

```json
{
  "accepted": true,
  "requestId": "0f9a...",
  "receivedAtServer": "2026-06-16T00:01:05+00:00",
  "verificationReport": {
    "documentIntegrity": "passed",
    "signingPayloadValid": "passed",
    "signatureValid": "passed",
    "certificateTrusted": "passed",
    "certificateValidityPeriod": "passed",
    "certificateRevocationStatus": "valid",
    "algorithmPolicyValid": "passed",
    "replayCheck": "passed",
    "finalDecision": "valid",
    "warnings": [],
    "verificationSteps": []
  },
  "signedPackage": {
    "packageVersion": "2.0",
    "signingPayload": {},
    "payloadCanonicalization": "JSON-canonical-sorted-keys",
    "signatureAlgorithm": "RSA-PSS",
    "signatureBase64": "nXk...",
    "signerCertificate": {},
    "signedAtClient": "2026-06-16T00:01:00+00:00",
    "receivedAtServer": "2026-06-16T00:01:05+00:00"
  },
  "warnings": []
}
```

Backend kiem tra:

- requestId ton tai va dang pending.
- nonce chua dung.
- payload khop signing request.
- algorithm policy.
- certificate do Demo CA ky.
- certificate khop DB record theo serial.
- revocation status tu DB.
- thoi han certificate.
- RSA key size theo policy.
- RSA-PSS signature tren canonical JSON cua `signingPayload`.

Audit event: `signature_submitted` voi `success` hoac `failed`.

## POST /api/verify/v2

Verify document hash va signed package, tra report chi tiet.

Request:

```json
{
  "documentHash": "b94d27b9934d3e08...",
  "hashAlgorithm": "SHA-256",
  "signedPackage": {}
}
```

Response:

```json
{
  "valid": true,
  "reason": "signature valid",
  "signer": {
    "name": "Nguyen Van A",
    "email": "student@example.com",
    "serialNumber": "A1B2C3"
  },
  "documentHash": "b94d27b9934d3e08...",
  "signedAt": "2026-06-16T00:01:00+00:00",
  "report": {
    "documentIntegrity": "passed",
    "signingPayloadValid": "passed",
    "signatureValid": "passed",
    "certificateParsed": "passed",
    "certificateTrusted": "passed",
    "certificateType": "legacy-demo",
    "certificateChainValid": "not_available",
    "certificateValidityPeriod": "passed",
    "certificateRevocationStatus": "valid",
    "keyUsageValid": "not_available",
    "algorithmPolicyValid": "passed",
    "replayCheck": "passed",
    "timestampStatus": "client-declared-time",
    "finalDecision": "valid",
    "warnings": [
      "Certificate is a legacy-demo JSON certificate, not X.509."
    ],
    "verificationSteps": [
      {
        "step": "Document integrity",
        "status": "passed",
        "message": "Document hash matches signed payload."
      }
    ]
  }
}
```

Neu that bai, endpoint van tra HTTP 200 voi `valid=false` va report neu signedPackage parse duoc. Malformed request/package co the tra HTTP 400.

Audit event: `signature_verified` voi `success` hoac `failed`.

## POST /api/certificates/revoke/v2

Thu hoi certificate theo serialNumber tu DB.

Request:

```json
{
  "serialNumber": "A1B2C3",
  "reason": "key_compromise",
  "revokedBy": "admin@example.com"
}
```

Response:

```json
{
  "serialNumber": "A1B2C3",
  "status": "revoked",
  "reason": "key_compromise",
  "revokedAt": "2026-06-16T00:02:00+00:00"
}
```

Audit event: `certificate_revoked`.

## GET /api/certificates/status/{serial_number}

Tra status, reason, revokedAt va expiresAt tu DB.

## GET /api/certificates/revocation-list

Tra danh sach certificate dang bi revoke trong DB.

## Legacy endpoints

### POST /api/sign

Legacy insecure demo. Endpoint nay nhan `privateKeyPem` tu frontend va backend ky document hash.

Khong dung endpoint nay cho UI chinh. No chi duoc giu de tuong thich va minh hoa rui ro: private key roi khoi client va di vao backend.

### POST /api/verify

Legacy verify cho `signed_package.json` cu. Luong nay verify chu ky tren document hash rieng le, khong ky full canonical `signingPayload`.

### POST /api/certificates/revoke

Legacy revoke nhan full certificate JSON. V2 nen dung `/api/certificates/revoke/v2` theo serialNumber.

## Gioi han con lai

- Certificate van la legacy-demo JSON certificate, chua phai X.509.
- SecureDoc Demo CA la CA local, khong co chain of trust that.
- Chua co HSM, smart card, USB token, key isolation production, TSA, OCSP/CRL that.
- Chua co PAdES, XAdES, CAdES.
- `signedAtClient` chi la thoi gian client khai bao, khong phai trusted timestamp.
- Replay check chi co y nghia trong server DB local da nhan submit.
- Chua co authentication, authorization, rate limit, HTTPS bat buoc hay hardening production.
- Phan chu ky mu giu nguyen demo giao duc, khong nam trong pham vi cai tien lan nay.
