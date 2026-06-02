# API

Base URL local: `http://127.0.0.1:8000`.

## POST /api/keys/generate

Tao RSA key pair va certificate gia lap.

Request JSON:

```json
{
  "name": "Nguyen Van A",
  "email": "student@example.com"
}
```

Response:

```json
{
  "privateKeyPem": "-----BEGIN PRIVATE KEY-----...",
  "publicKeyPem": "-----BEGIN PUBLIC KEY-----...",
  "certificate": {
    "serialNumber": "A1B2C3",
    "ownerName": "Nguyen Van A",
    "email": "student@example.com",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----...",
    "issuer": "SecureDoc Demo CA",
    "issuedAt": "2026-06-02T10:00:00+00:00",
    "expiresAt": "2027-06-02T10:00:00+00:00",
    "status": "valid"
  }
}
```

## POST /api/documents/hash

Tinh SHA-256 cua file upload.

Request: `multipart/form-data`

- `file`: document can bam.

Response:

```json
{
  "documentName": "demo.txt",
  "hashAlgorithm": "SHA-256",
  "documentHash": "b94d27b9934d3e08..."
}
```

## POST /api/sign

Ky document bang private key.

Request: `multipart/form-data`

- `file`: document can ky.
- `privateKeyPem`: private key PEM.
- `certificate`: certificate JSON string.

Response:

```json
{
  "documentName": "demo.txt",
  "documentHash": "b94d27b9934d3e08...",
  "hashAlgorithm": "SHA-256",
  "signatureAlgorithm": "RSA-PSS",
  "signatureBase64": "nXk...",
  "signedAt": "2026-06-02T10:05:00+00:00",
  "certificate": {
    "serialNumber": "A1B2C3",
    "ownerName": "Nguyen Van A",
    "email": "student@example.com",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----...",
    "issuer": "SecureDoc Demo CA",
    "issuedAt": "2026-06-02T10:00:00+00:00",
    "expiresAt": "2027-06-02T10:00:00+00:00",
    "status": "valid"
  }
}
```

## POST /api/verify

Xac minh document va signed package.

Request: `multipart/form-data`

- `file`: document can verify.
- `signedPackage`: signed package JSON string.

Response valid:

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
  "signedAt": "2026-06-02T10:05:00+00:00",
  "details": {
    "hashMatches": true,
    "certificateStatus": "valid",
    "signatureValid": true
  }
}
```

Response invalid:

```json
{
  "valid": false,
  "reason": "document modified",
  "signer": {
    "name": "Nguyen Van A",
    "email": "student@example.com",
    "serialNumber": "A1B2C3"
  },
  "documentHash": "new-file-hash",
  "signedAt": "2026-06-02T10:05:00+00:00",
  "details": {
    "hashMatches": false,
    "certificateStatus": "valid"
  }
}
```

Possible reasons:

- `document modified`
- `certificate expired`
- `certificate revoked`
- `invalid signature or public key mismatch`
- `malformed certificate`
- `unsupported algorithm`
- `Malformed signed package`

## POST /api/certificates/revoke

Danh dau certificate la revoked trong demo.

Request JSON:

```json
{
  "certificate": {
    "serialNumber": "A1B2C3",
    "ownerName": "Nguyen Van A",
    "email": "student@example.com",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----...",
    "issuer": "SecureDoc Demo CA",
    "issuedAt": "2026-06-02T10:00:00+00:00",
    "expiresAt": "2027-06-02T10:00:00+00:00",
    "status": "valid"
  }
}
```

Response:

```json
{
  "certificate": {
    "serialNumber": "A1B2C3",
    "ownerName": "Nguyen Van A",
    "email": "student@example.com",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----...",
    "issuer": "SecureDoc Demo CA",
    "issuedAt": "2026-06-02T10:00:00+00:00",
    "expiresAt": "2027-06-02T10:00:00+00:00",
    "status": "revoked"
  }
}
```

