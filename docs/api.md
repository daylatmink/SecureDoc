# SecureDoc API

Base URL local: `http://127.0.0.1:8000`.

## Tong quan v2

Luong ky chinh hien nay la v2 client-side signing voi X.509 demo certificate:

1. Browser tao RSA key pair bang Web Crypto.
2. Browser gui `publicKeyPem` toi `/api/certificates/x509/issue`.
3. Backend demo CA cap PEM X.509 certificate theo chain:
   `Demo Root CA -> Demo Intermediate CA -> User Signing Certificate`.
4. Client/backend tinh `documentHash` cho file.
5. Client goi `/api/sign/v2/prepare` voi `documentName`, `documentHash`, `hashAlgorithm`, `certificateSerialNumber`, `signingPurpose`.
6. Backend tao `signingPayload` chuan hoa gom:
   `documentName`, `documentHash`, `hashAlgorithm`, `signatureAlgorithm`, signer info,
   `certificateSerialNumber`, `certificateFingerprint`, `certificateType`, `signingPurpose`, `requestId`, `nonce`,
   `createdAt`, `payloadVersion`.
7. Client hien man hinh review va ky canonical JSON cua `signingPayload` tai client bang private key.
8. Client gui `signedPackage` toi `/api/sign/v2/submit`.
9. Backend chi verify/luu package; backend khong nhan private key trong luong v2.

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

## POST /api/certificates/x509/issue

Cap `x509-demo` certificate tu public key. Backend khong nhan private key.

Request:

```json
{
  "name": "Nguyen Van A",
  "email": "student@example.com",
  "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
}
```

Response:

```json
{
  "userCertificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "intermediateCertificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "rootCertificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "certificateSerialNumber": "4A8D...",
  "certificateFingerprint": "7b8c...",
  "certificateType": "x509-demo",
  "certificate": {
    "serialNumber": "4A8D...",
    "ownerName": "Nguyen Van A",
    "email": "student@example.com",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    "issuer": "SecureDoc Demo Intermediate CA",
    "issuedAt": "2026-06-18T00:00:00+00:00",
    "expiresAt": "2027-06-18T00:00:00+00:00",
    "status": "valid",
    "certificateType": "x509-demo",
    "certificateFingerprint": "7b8c...",
    "userCertificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
    "intermediateCertificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
    "rootCertificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
  }
}
```

User certificate gom subject, issuer, serial number, validity, SubjectPublicKeyInfo, BasicConstraints CA=false, KeyUsage digitalSignature/contentCommitment, SubjectKeyIdentifier va AuthorityKeyIdentifier.

CA certificates gom BasicConstraints CA=true va KeyUsage keyCertSign/cRLSign.

Audit event: `certificate_issued`.

## POST /api/keys/generate

Legacy/debug only. Tao RSA key pair trong backend va legacy-demo certificate JSON duoc SecureDoc Demo CA ky.

Request:

```json
{
  "name": "Nguyen Van A",
  "email": "student@example.com"
}
```

Response gom `privateKeyPem`, `publicKeyPem`, `certificate`.

Canh bao: endpoint nay tao private key o backend roi tra ve client, nen khong thuoc flow chinh. Flow chinh dung browser Web Crypto de tao key pair va chi gui public key len `/api/certificates/x509/issue`.

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
    "certificateType": "x509-demo",
    "signingPurpose": "approve_document",
    "createdAt": "2026-06-16T00:00:00+00:00",
    "nonce": "d3c1...",
    "requestId": "0f9a...",
    "payloadVersion": "1.0"
  },
  "canonicalPayloadBase64": "eyJjZXJ0...",
  "warnings": [
    "X.509 certificate is issued by SecureDoc local demo CA, not a public CA.",
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
  "userCertificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "intermediateCertificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "rootCertificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "trustedRootId": "securedoc-demo-root",
  "signerCertificate": {
    "certificateType": "x509-demo"
  },
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
    "certificateType": "x509-demo",
    "certificateChainValid": "passed",
    "certificateValidityPeriod": "passed",
    "certificateRevocationStatus": "valid",
    "revocationSource": "server-db",
    "keyUsageValid": "passed",
    "algorithmPolicyValid": "passed",
    "replayCheck": "passed",
    "timestampStatus": "demo-tsa-valid",
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
    "userCertificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
    "intermediateCertificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
    "rootCertificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
    "trustedRootId": "securedoc-demo-root",
    "timestampToken": {
      "tokenVersion": "1.0",
      "messageImprint": "e3b0...",
      "hashAlgorithm": "SHA-256",
      "timestamp": "2026-06-16T00:01:05+00:00",
      "tsaName": "SecureDoc Demo TSA",
      "serialNumber": "9A12...",
      "signatureAlgorithm": "RSA-PSS-SHA256",
      "signatureBase64": "MEU..."
    },
    "signerCertificate": {
      "certificateType": "x509-demo"
    },
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
- certificate do Demo CA ky; voi `x509-demo` thi verify PEM chain va key usage.
- certificate khop DB record theo serial.
- revocation status tu DB.
- thoi han certificate.
- RSA key size theo policy.
- RSA-PSS signature tren canonical JSON cua `signingPayload`.
- timestampToken demo neu co; neu client khong gui thi backend tao token Demo TSA cho hash cua signature.

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
    "certificateType": "x509-demo",
    "certificateChainValid": "passed",
    "certificateValidityPeriod": "passed",
    "certificateRevocationStatus": "valid",
    "revocationSource": "server-db",
    "keyUsageValid": "passed",
    "algorithmPolicyValid": "passed",
    "replayCheck": "passed",
    "timestampStatus": "demo-tsa-valid",
    "finalDecision": "valid",
    "warnings": [
      "SecureDoc Demo CA is local demo trust only."
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

## GET /api/certificates/crl

Tra signed demo CRL dang JSON. Day khong phai binary CRL/OCSP chuan, nhung payload duoc ky bang Demo Intermediate CA.

Response:

```json
{
  "issuer": "SecureDoc Demo Intermediate CA",
  "thisUpdate": "2026-06-18T00:00:00+00:00",
  "nextUpdate": "2026-06-19T00:00:00+00:00",
  "revokedCertificates": [
    {
      "serialNumber": "4A8D...",
      "certificateFingerprint": "7b8c...",
      "reason": "key_compromise",
      "revokedAt": "2026-06-18T00:00:00+00:00"
    }
  ],
  "signatureAlgorithm": "RSA-PSS-SHA256",
  "signatureBase64": "nXk..."
}
```

Audit event: `crl_generated`.

## GET /api/audit/verify-chain

Verify audit log hash chain.

Response:

```json
{
  "valid": true,
  "totalEvents": 12,
  "brokenAt": null
}
```

## Blind signature APIs

Blind signature flow is separate from document signing. Document signatures identify a signer for a document. Blind signatures are for privacy/anonymous-token problems where the signer authorizes a blinded token without seeing the original token.

Allowed token purposes:

- `anonymous_access_token`
- `e_voting_demo`
- `e_cash_demo`

Token structure:

```json
{
  "tokenId": "9f3a...",
  "purpose": "anonymous_access_token",
  "createdAt": "2026-06-18T00:00:00+00:00",
  "expiresAt": "2026-06-18T00:10:00+00:00",
  "nonce": "2dd1...",
  "tokenVersion": "1.0"
}
```

### POST /api/blind-signature/sessions

Creates a demo token and blinded message. The response includes `blindingFactorBase64` only for the educational browser demo. Do not expose or log blinding factors in production-like systems.

Request:

```json
{
  "purpose": "anonymous_access_token",
  "ttlSeconds": 600
}
```

### POST /api/blind-signature/sign

Signer signs only `blindedMessageBase64`. It does not receive or sign the raw token.

Request:

```json
{
  "sessionId": "9f3a...",
  "blindedMessageBase64": "AAE..."
}
```

### POST /api/blind-signature/verify

Verifies the final unblinded signature on the original token.

Request:

```json
{
  "sessionId": "9f3a...",
  "token": {},
  "finalSignatureBase64": "AAE..."
}
```

### POST /api/blind-signature/redeem

Redeems a verified token and prevents reuse. First redeem succeeds; second redeem returns `redeemed=false` with reason `token already spent`.

### GET /api/blind-signature/sessions/{sessionId}

Returns session state without returning the demo blinding factor.

### POST /api/blind-signature/demo

Compatibility educational endpoint. The UI uses the step-by-step endpoints above.

## Legacy endpoints

### POST /api/sign

Legacy insecure demo. Endpoint nay nhan `privateKeyPem` tu frontend va backend ky document hash.

Khong dung endpoint nay cho UI chinh. No chi duoc giu de tuong thich va minh hoa rui ro: private key roi khoi client va di vao backend.

### POST /api/verify

Legacy verify cho `signed_package.json` cu. Luong nay verify chu ky tren document hash rieng le, khong ky full canonical `signingPayload`.

### POST /api/certificates/revoke

Legacy revoke nhan full certificate JSON. V2 nen dung `/api/certificates/revoke/v2` theo serialNumber.

## Gioi han con lai

- Flow chinh dung `x509-demo` certificate, nhung Demo CA chi la local trust, khong phai public CA.
- Certificate khong co gia tri phap ly va khong duoc neo vao trust store cong khai.
- CRL/TSA la demo JSON co chu ky, khong phai OCSP/CRL binary hay RFC 3161 TSA production.
- Chua co HSM, smart card, USB token, key isolation production.
- Chua co PAdES, XAdES, CAdES.
- `signedAtClient` chi la thoi gian client khai bao; `timestampToken` la demo TSA token, khong phai trusted timestamp phap ly.
- Replay check chi co y nghia trong server DB local da nhan submit.
- Chua co authentication, authorization, rate limit, HTTPS bat buoc hay hardening production.
- Phan chu ky mu giu nguyen demo giao duc, khong nam trong pham vi cai tien lan nay.
