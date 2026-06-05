# API

Base URL local: `http://127.0.0.1:8000`.

## GET /api/ca/public-key

Trả về public key của Demo CA để minh họa trust anchor.

Response:

```json
{
  "issuer": "SecureDoc Demo CA",
  "publicKeyPem": "-----BEGIN PUBLIC KEY-----...",
  "signatureAlgorithm": "RSA-PSS-SHA256"
}
```

## POST /api/keys/generate

Tạo RSA key pair và certificate được Demo CA ký.

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
    "issuedAt": "2026-06-05T10:00:00+00:00",
    "expiresAt": "2027-06-05T10:00:00+00:00",
    "status": "valid",
    "caSignatureAlgorithm": "RSA-PSS-SHA256",
    "caSignatureBase64": "nXk..."
  }
}
```

## POST /api/documents/hash

Tính SHA-256 của file upload.

Request: `multipart/form-data`

- `file`: document cần băm.

Response:

```json
{
  "documentName": "demo.txt",
  "hashAlgorithm": "SHA-256",
  "documentHash": "b94d27b9934d3e08..."
}
```

## POST /api/sign

Ký document bằng private key. Backend yêu cầu certificate phải có chữ ký hợp lệ của Demo CA, tồn tại trong DB và chưa bị thu hồi.

Request: `multipart/form-data`

- `file`: document cần ký.
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
  "signedAt": "2026-06-05T10:05:00+00:00",
  "certificate": {
    "serialNumber": "A1B2C3",
    "ownerName": "Nguyen Van A",
    "email": "student@example.com",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----...",
    "issuer": "SecureDoc Demo CA",
    "issuedAt": "2026-06-05T10:00:00+00:00",
    "expiresAt": "2027-06-05T10:00:00+00:00",
    "status": "valid",
    "caSignatureAlgorithm": "RSA-PSS-SHA256",
    "caSignatureBase64": "nXk..."
  }
}
```

## POST /api/verify

Xác minh document và signed package.

Request: `multipart/form-data`

- `file`: document cần verify.
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
  "signedAt": "2026-06-05T10:05:00+00:00",
  "details": {
    "hashMatches": true,
    "certificateStatusInPackage": "valid",
    "certificateStatusFromServer": "valid",
    "caSignatureValid": true,
    "revocationSource": "server database",
    "signatureValid": true
  }
}
```

Response invalid:

```json
{
  "valid": false,
  "reason": "certificate revoked",
  "signer": {
    "name": "Nguyen Van A",
    "email": "student@example.com",
    "serialNumber": "A1B2C3"
  },
  "documentHash": "b94d27b9934d3e08...",
  "signedAt": "2026-06-05T10:05:00+00:00",
  "details": {
    "hashMatches": true,
    "certificateStatusInPackage": "valid",
    "certificateStatusFromServer": "revoked",
    "caSignatureValid": true
  }
}
```

Possible reasons:

- `document modified`
- `certificate not issued by demo CA`
- `unknown certificate serial number`
- `certificate record mismatch`
- `certificate expired`
- `certificate revoked`
- `invalid signature or public key mismatch`
- `malformed certificate`
- `unsupported algorithm`
- `Malformed signed package`

## POST /api/certificates/revoke

Đánh dấu certificate là revoked trong server DB. Verify sẽ tra trạng thái từ DB theo `serialNumber`, không tin riêng trường `status` trong signed package.

Request JSON:

```json
{
  "certificate": {
    "serialNumber": "A1B2C3",
    "ownerName": "Nguyen Van A",
    "email": "student@example.com",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----...",
    "issuer": "SecureDoc Demo CA",
    "issuedAt": "2026-06-05T10:00:00+00:00",
    "expiresAt": "2027-06-05T10:00:00+00:00",
    "status": "valid",
    "caSignatureAlgorithm": "RSA-PSS-SHA256",
    "caSignatureBase64": "nXk..."
  }
}
```

Response:

```json
{
  "certificate": {
    "serialNumber": "A1B2C3",
    "status": "revoked"
  }
}
```

## POST /api/blind-signature/demo

Mô phỏng chữ ký mù RSA cho mục tiêu học thuật.

Request JSON:

```json
{
  "message": "Phieu binh chon an danh so 01"
}
```

Response:

```json
{
  "message": "Phieu binh chon an danh so 01",
  "hashAlgorithm": "SHA-256",
  "messageHash": "ead43965...",
  "scheme": "Educational RSA blind signature demo",
  "blindedMessageBase64": "Q9JS...",
  "blindSignatureBase64": "FXu...",
  "unblindedSignatureBase64": "kpT...",
  "valid": true
}
```
