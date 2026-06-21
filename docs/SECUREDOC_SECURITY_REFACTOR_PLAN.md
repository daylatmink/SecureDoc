# SecureDoc Digital Signature Full Roadmap

## 0. Mục tiêu tổng thể

SecureDoc được định hướng thành một hệ thống ký số tài liệu có phân quyền, có xác thực người dùng, có quản lý chứng thư số, có quy trình ký/xác minh rõ ràng, và có các module mở rộng như timestamp, PAdES, audit log, LTV và chữ ký mù.

Hệ thống không còn đi theo hướng demo classroom/full pipeline gom tất cả role vào một màn hình. Thay vào đó, hệ thống được thiết kế theo mô hình sản phẩm:

* `SIGNER`: người ký tài liệu.
* `CA_OFFICER`: cán bộ cấp/thu hồi chứng thư số.
* `VERIFIER`: người xác minh chữ ký.
* `AUDITOR`: người kiểm tra audit log.
* `ADMIN`: người quản trị user/role/hệ thống.

Các thành phần chữ ký số cần bao phủ:

1. Cơ chế tạo chữ ký số.
2. Giao thức chữ ký số.
3. Dịch vụ chữ ký số.
4. Quản lý khóa và chứng thư.
5. Xác thực người ký.
6. Timestamp và xác minh thời điểm ký.
7. Ký PDF/PAdES.
8. Thu hồi chứng thư và xác minh trạng thái.
9. Audit log và khả năng truy vết.
10. Chữ ký mù cho privacy-preserving token service.

---

## Nguyên tắc triển khai

* Không copy thuật toán ký thành nhiều bản.
* Backend signing pipeline là nguồn sự thật duy nhất.
* Frontend chỉ tách theo role/UI, không tách logic mật mã.
* Không để frontend tự khai role.
* Không dùng `X-SecureDoc-User` / `X-SecureDoc-Role` mặc định.
* Không để user mode tự dùng token `CA_OFFICER` hoặc `AUDITOR` ngầm.
* Không hardcode secret, app password, private key.
* Không commit `.env`.
* Không claim production-ready nếu chưa có HSM/KMS, public CA, RFC3161 thật, PAdES-LTV đầy đủ.

---

# PHASE 0 — Product Cleanup & Architecture Baseline

## Mục tiêu

Dọn kiến trúc hiện tại để SecureDoc không còn là demo pipeline lẫn lộn nhiều role. Chuẩn bị nền cho hệ thống phân quyền thật hơn.

## Việc cần làm

### 0.1. Frontend cleanup

Bỏ `DocumentsWorkflow` khỏi main navigation.

Không còn một màn hình gom toàn bộ:

* generate key
* issue cert
* prepare
* OTP
* sign
* submit
* verify
* revoke
* audit

vào cùng một user-facing flow.

Thay bằng các màn hình theo role:

```text
/sign        → SIGNER
/ca          → CA_OFFICER
/verify      → VERIFIER
/audit       → AUDITOR
/admin       → ADMIN
/security    → MFA/TOTP settings
```

Nếu frontend chưa dùng router thì vẫn có thể dùng tab state, nhưng tab phải phản ánh đúng role.

### 0.2. Xóa demo auth khỏi user flow

Loại bỏ khỏi user-facing frontend:

```typescript
demoAuthHeaders
roleAuthHeaders("CA_OFFICER")
roleAuthHeaders("AUDITOR")
X-SecureDoc-User
X-SecureDoc-Role
```

User flow chỉ dùng:

```http
Authorization: Bearer <access_token>
```

### 0.3. Giữ một signing pipeline duy nhất

Backend vẫn giữ một pipeline chuẩn:

```text
prepare signing request
→ request OTP/TOTP
→ confirm signing intent
→ client-side sign
→ submit signed package
→ verify
```

Không tạo pipeline riêng cho demo và pipeline riêng cho user.

## Deliverable

* Không còn `DocumentsWorkflow` là flow chính.
* Frontend chia theo role.
* Không còn role-switch ngầm trong user UI.
* Backend signing API vẫn hoạt động.

## Test

```bash
python -m pytest backend/tests -q
npm --prefix frontend run build
```

---

# PHASE 1 — Auth, User, Role, OTP, TOTP, RBAC

## Mục tiêu

Xây nền xác thực và phân quyền cho hệ thống. Đây là phase bắt buộc trước khi nâng chuẩn X.509/PAdES.

## 1.1. SMTP sender

Tài khoản gửi OTP của hệ thống:

```text
lucdoka1245@gmail.com
```

`.env.example`:

```env
SECUREDOC_SMTP_HOST=smtp.gmail.com
SECUREDOC_SMTP_PORT=587
SECUREDOC_SMTP_USERNAME=lucdoka1245@gmail.com
SECUREDOC_SMTP_PASSWORD=change-me-google-app-password
SECUREDOC_SMTP_FROM_EMAIL=lucdoka1245@gmail.com
SECUREDOC_SMTP_USE_TLS=true
```

Quy tắc:

* Không hardcode app password.
* Không commit `.env`.
* Nếu SMTP chưa cấu hình, không gửi email thật.
* Không trả OTP plaintext trong response.
* OTP được gửi từ `lucdoka1245@gmail.com`.
* OTP được gửi đến email user hoặc `signing_request.signer_email`.

## 1.2. User model

Thêm bảng `users`:

```text
id
email unique
name
role
status
created_at
updated_at
```

Role hợp lệ:

```text
ADMIN
CA_OFFICER
SIGNER
VERIFIER
AUDITOR
```

Status:

```text
active
disabled
```

## 1.3. Login bằng email OTP

Thay login demo bằng login OTP.

### Request login OTP

```http
POST /api/auth/login/request-otp
```

Body:

```json
{
  "email": "student1@example.com"
}
```

Backend:

* kiểm tra user tồn tại trong DB
* kiểm tra user active
* tạo OTP purpose `LOGIN`
* hash OTP bằng HMAC-SHA256 + `SECUREDOC_OTP_PEPPER`
* gửi OTP đến `user.email`
* không trả OTP plaintext

### Verify login OTP

```http
POST /api/auth/login/verify-otp
```

Body:

```json
{
  "email": "student1@example.com",
  "otp": "123456"
}
```

Backend:

* verify OTP
* kiểm tra expiry
* kiểm tra attempt_count
* kiểm tra used_at
* nếu hợp lệ thì cấp JWT

Response:

```json
{
  "accessToken": "...",
  "tokenType": "Bearer",
  "expiresIn": 3600,
  "user": {
    "email": "student1@example.com",
    "name": "Student 1",
    "role": "SIGNER"
  }
}
```

Role lấy từ DB, không lấy từ request body.

## 1.4. JWT/RBAC

JWT payload:

```json
{
  "sub": "student1@example.com",
  "role": "SIGNER",
  "iat": 1234567890,
  "exp": 1234571490,
  "typ": "securedoc-access"
}
```

`require_roles()` phải:

* đọc `Authorization: Bearer <JWT>`
* verify signature bằng `SECUREDOC_JWT_SECRET`
* check `exp`
* lấy user/role từ token
* check role ở backend
* reject fake token
* reject expired token
* reject raw header auth nếu `ENABLE_DEMO_HEADER_AUTH=false`

`.env.example`:

```env
SECUREDOC_JWT_SECRET=change-me-long-random-jwt-secret
SECUREDOC_JWT_TTL_SECONDS=3600
ENABLE_DEMO_HEADER_AUTH=false
```

## 1.5. Role rules

### SIGNER

Được:

* xem certificate của mình
* xem signing request của mình
* setup TOTP của mình
* request signing OTP của mình
* confirm signing request của mình
* ký tài liệu của mình
* submit signed package của mình

Không được:

* issue certificate
* revoke certificate
* xem audit log
* ký bằng certificate của email khác

### CA_OFFICER

Được:

* issue certificate cho user
* revoke certificate
* xem danh sách certificate

Không được:

* ký thay signer
* confirm signing request thay signer

### VERIFIER

Được:

* verify tài liệu/signed package
* xem verification report

Không được:

* thay đổi certificate
* ký tài liệu
* xem audit nội bộ nếu không có quyền

### AUDITOR

Được:

* xem audit log
* verify audit chain
* export audit report

Không được:

* ký tài liệu
* cấp certificate
* thu hồi certificate

### ADMIN

Được:

* quản lý user
* phân role
* disable user
* cấu hình hệ thống

## 1.6. TOTP/MFA

Endpoint:

```http
POST /api/auth/totp/setup
POST /api/auth/totp/verify-setup
```

Quy tắc:

* chỉ authenticated `SIGNER` được setup
* setup cho chính actor email
* verify setup chỉ nhận `{ "code": "123456" }`
* không nhận secret từ client
* không lưu secret plaintext/base64 nếu claim encrypted
* response setup có `Cache-Control: no-store`
* nếu MFA đã enabled thì không reset bằng setup thường nếu không có re-auth

## 1.7. Signing OTP

Signing OTP dùng cho xác nhận ý chí ký.

OTP phải bind với:

```text
requestId
documentHash
certificateSerial
signingPurpose
nonce
```

Quy tắc:

* gửi đến `signing_request.signer_email`
* không trả OTP plaintext
* có resend cooldown
* tạo OTP mới thì revoke/expire OTP cũ
* submit khi chưa confirm OTP/TOTP phải fail
* confirm xong mới submit được

## 1.8. API cần có

```text
POST /api/auth/login/request-otp
POST /api/auth/login/verify-otp
GET  /api/me

GET  /api/my/certificates
GET  /api/my/signing-requests
GET  /api/my/signing-requests/{id}

POST /api/sign/v2/prepare
POST /api/v2/signing-requests/{id}/otp/request
POST /api/v2/signing-requests/{id}/confirm
POST /api/sign/v2/submit

POST /api/certificates/x509/issue
POST /api/certificates/revoke/v2

POST /api/verify/v2

GET /api/audit/logs
GET /api/audit/verify-chain
```

## 1.9. Tests

* login OTP request với user tồn tại thành công
* login OTP request với user không tồn tại fail
* OTP đúng trả JWT đúng role
* OTP sai fail
* fake JWT fail 401
* expired JWT fail 401
* raw `X-SecureDoc-*` header fail
* SIGNER không gọi được CA endpoint
* CA_OFFICER issue cert được
* SIGNER không dùng cert người khác
* SIGNER chỉ xem signing request của mình
* signing OTP gửi đúng `signing_request.signer_email`
* SMTP trống không trả OTP plaintext
* submit chưa confirm fail
* confirm rồi submit pass
* OTP cooldown hoạt động
* OTP cũ bị revoke
* TOTP setup cần auth
* TOTP verify setup không nhận `secret`

---

# PHASE 2 — Certificate Authority, X.509, Chain of Trust

## Mục tiêu

Chuẩn hóa phần chứng thư số. Thay mô hình certificate tự thiết kế bằng mô hình gần chuẩn X.509 hơn.

## 2.1. CA hierarchy

Tách:

```text
Root CA
Intermediate CA
End-user signing certificate
TSA certificate
```

Root CA nên offline về mặt thiết kế.

Intermediate CA dùng để issue certificate cho signer.

TSA certificate dùng riêng cho timestamp.

## 2.2. Certificate profiles

### Root CA

Extensions:

```text
BasicConstraints: CA=true
KeyUsage: keyCertSign, cRLSign
SubjectKeyIdentifier
```

### Intermediate CA

Extensions:

```text
BasicConstraints: CA=true, pathLen phù hợp
KeyUsage: keyCertSign, cRLSign
SubjectKeyIdentifier
AuthorityKeyIdentifier
CRLDistributionPoints nếu có
AuthorityInfoAccess nếu có
```

### Signer certificate

Extensions:

```text
BasicConstraints: CA=false
KeyUsage: digitalSignature
ExtendedKeyUsage nếu cần
Subject email/name
SubjectKeyIdentifier
AuthorityKeyIdentifier
CertificatePolicies nếu có
```

### TSA certificate

Extensions:

```text
BasicConstraints: CA=false
KeyUsage: digitalSignature
ExtendedKeyUsage: timeStamping
SubjectKeyIdentifier
AuthorityKeyIdentifier
```

## 2.3. Certificate lifecycle

CA Officer quản lý:

```text
issue certificate
renew certificate
revoke certificate
view certificate status
```

Certificate status:

```text
active
revoked
expired
superseded
```

## 2.4. Chain validation

Verify module phải check:

* parse certificate
* signature chain
* validity period
* issuer/subject
* BasicConstraints
* KeyUsage
* EKU
* SKI/AKI nếu có
* trusted root
* revocation status

## 2.5. Revocation

Có thể bắt đầu với DB revocation, nhưng thiết kế phải hướng đến:

```text
CRL
OCSP
AIA
CRL Distribution Points
```

Nếu có trusted timestamp, revocation nên được xác minh theo thời điểm ký.

Nếu chưa có trusted timestamp, xác minh theo thời điểm hiện tại và cảnh báo rõ.

## 2.6. Tests

* cert expired fail
* cert not-yet-valid fail
* CA thiếu `keyCertSign` fail
* signer cert có `CA=true` fail
* signer cert thiếu `digitalSignature` fail
* TSA thiếu EKU `timeStamping` fail
* wrong issuer fail
* revoked cert fail
* unknown root fail
* broken chain fail

---

# PHASE 3 — Core Digital Signature Mechanism & Signing Protocol

## Mục tiêu

Chuẩn hóa cơ chế tạo chữ ký số và giao thức ký. Đây là phần lõi của hệ thống.

## 3.1. Client-side signing

Nguyên tắc:

* private key không gửi lên backend
* backend không ký thay user
* browser/client ký canonical payload
* backend chỉ verify signed package

Ưu tiên:

```text
WebCrypto non-extractable key
```

Nếu vẫn export private key để demo/local thì phải ghi rõ không production-ready.

## 3.2. Signing payload

Signing payload phải có:

```text
schemaVersion
documentName
documentHash
hashAlgorithm
signatureAlgorithm
signerEmail
signerName
certificateSerialNumber
certificateFingerprint
signingPurpose
signingIntent
requestId
nonce
createdAt
expiresAt
```

## 3.3. Canonicalization

Payload phải canonical hóa trước khi ký.

Yêu cầu:

* deterministic JSON
* sorted keys
* UTF-8
* không ký object tùy ý chưa chuẩn hóa
* không cho field bị thêm/sửa sau ký mà vẫn pass

## 3.4. Algorithm policy

Allow:

```text
SHA-256
SHA-384
SHA-512
RSA-PSS
ECDSA nếu triển khai
```

Reject:

```text
MD5
SHA-1
none
unknown algorithm
algorithm downgrade
```

RSA-PSS phải kiểm soát:

```text
hash
MGF1 hash
salt length
```

## 3.5. Signing request protocol

Flow:

```text
1. SIGNER chọn document.
2. Client hash document.
3. Client gọi prepare signing request.
4. Backend tạo requestId + nonce + payload.
5. User confirm bằng OTP/TOTP.
6. Client ký canonical payload.
7. Client submit signed package.
8. Backend verify.
9. Backend mark accepted/rejected.
```

## 3.6. Verify response

Verify response phải tách rõ:

```text
cryptoValid
documentHashValid
trustedChainValid
revocationValid
timestampValid
serverAccepted
signingRequestConfirmed
legalReady
warnings
errors
verificationSteps
```

## 3.7. Tests

* document sửa 1 byte fail
* payload sửa 1 field fail
* nonce mismatch fail
* requestId mismatch fail
* cert fingerprint mismatch fail
* algorithm downgrade fail
* SHA-1 fail
* MD5 fail
* signed package crypto valid nhưng chain fail report đúng
* chưa confirm OTP/TOTP thì submit fail
* confirmed rồi submit pass

---

# PHASE 4 — Digital Signature Services

## Mục tiêu

Xây hệ thống thành một dịch vụ ký số hoàn chỉnh thay vì chỉ là API ký/xác minh rời rạc.

## 4.1. Signing service

Chức năng:

* tạo signing request
* gán signer
* theo dõi trạng thái
* gửi OTP
* confirm intent
* nhận signed package
* verify
* lưu kết quả

Trạng thái signing request:

```text
draft
pending
mfa_confirmed
signed
rejected
expired
cancelled
```

## 4.2. Verification service

Chức năng:

* verify package
* verify document hash
* verify certificate chain
* verify revocation
* verify timestamp
* xuất verification report

## 4.3. Certificate service

Chức năng:

* issue certificate
* revoke certificate
* renew certificate
* list certificate
* check certificate status

## 4.4. User service

Chức năng:

* tạo user
* phân role
* disable user
* xem user profile
* quản lý MFA

## 4.5. Audit service

Chức năng:

* ghi event
* xem audit log
* verify audit chain
* export audit report

## 4.6. Tests

* signer xem được request của mình
* signer không xem được request người khác
* CA officer issue/revoke được
* verifier verify được
* auditor xem audit được
* signer không xem audit được
* audit event được tạo khi issue/revoke/sign/verify

---

# PHASE 5 — Timestamp, RFC 3161, Long-Term Validation Foundation

## Mục tiêu

Bổ sung timestamp đáng tin cậy để chứng minh thời điểm ký.

## 5.1. Timestamp abstraction

Tạo abstraction:

```text
TimestampProvider
TimestampToken
TimestampVerifier
```

Nếu chưa tích hợp TSA thật, phải ghi rõ:

```text
timestamp abstraction only
not RFC3161 production-ready
```

## 5.2. RFC 3161 direction

Thiết kế hướng đến:

```text
TimeStampReq
TimeStampResp
messageImprint
TSTInfo
TSA certificate
CMS SignedData
```

Timestamp token phải bind với document/signature imprint.

## 5.3. Timestamp verify

Verify:

* timestamp token signature
* TSA certificate chain
* TSA EKU timeStamping
* message imprint
* timestamp time
* timestamp token integrity

## 5.4. Revocation by signing time

Nếu có trusted timestamp:

```text
certificate validity/revocation nên xét tại signing time
```

Nếu không có trusted timestamp:

```text
verify theo current time và cảnh báo legalReady=false
```

## 5.5. Tests

* timestamp imprint mismatch fail
* TSA cert thiếu EKU fail
* timestamp token bị sửa fail
* expired signer cert nhưng valid tại signing time được xử lý đúng
* revoked sau signing time được xử lý đúng nếu timestamp trusted
* timestamp missing thì legalReady=false

---

# PHASE 6 — PDF Signing & PAdES

## Mục tiêu

Nâng từ signed JSON package sang ký PDF gần chuẩn PAdES.

## 6.1. PAdES baseline

Hướng tới:

```text
PAdES-B-B
PAdES-B-T
PAdES-B-LT
PAdES-B-LTA
```

Triển khai trước PAdES-B-T nếu đủ thời gian.

## 6.2. PDF signature structure

Cần có:

```text
PDF Signature Dictionary
ByteRange
Contents
SubFilter
detached CMS signature
signer certificate chain
timestamp token
```

## 6.3. Detached signature

Không ký toàn bộ PDF sau khi chèn signature placeholder sai cách.

Phải ký đúng byte ranges.

## 6.4. PAdES-B-T

Bổ sung timestamp token cho signature.

## 6.5. LTV direction

Về sau bổ sung:

```text
DSS
VRI
OCSP/CRL embedded
document timestamp
```

## 6.6. Tests

* sửa PDF 1 byte sau ký fail
* ByteRange sai fail
* CMS signature sai fail
* thiếu certificate chain warning/fail tùy policy
* timestamp imprint mismatch fail
* revoked cert reflect đúng trong report

---

# PHASE 7 — Blind Signature Module

## Mục tiêu

Bổ sung chữ ký mù như module privacy riêng. Không dùng chữ ký mù để thay thế chữ ký tài liệu thông thường.

## 7.1. Vị trí trong hệ thống

Chữ ký mù là module riêng:

```text
Privacy Token Service
Blind Signature Service
```

Không nằm trong document signing flow chính.

Document signing cần định danh người ký.

Blind signature phục vụ:

```text
anonymous approval token
privacy-preserving access token
survey/e-voting style token
anonymous receipt
```

## 7.2. Nguyên tắc bảo mật

* Blind signer key riêng.
* Không dùng CA key.
* Không dùng TSA key.
* Không expose blinding factor.
* Không log dữ liệu phá unlinkability.
* Có rate limit.
* Có purpose/domain separation.
* Có double-spend protection.

## 7.3. Blind token payload

Payload trước khi blind:

```text
schemaVersion
purpose
tokenId
nonce
issuedFor
expiresAt
domainSeparator
```

Ví dụ:

```text
SecureDoc-BlindSignature-v1:anonymous_approval
SecureDoc-BlindSignature-v1:access_token
```

## 7.4. Protocol

Flow:

```text
1. Client tạo token payload.
2. Client blind payload.
3. Client gửi blinded message lên server.
4. Server kiểm tra user có quyền request token.
5. Server ký blinded message.
6. Client unblind signature.
7. Client nhận blind-signed token.
8. Client redeem token khi cần.
9. Server verify signature và chống double-spend.
```

## 7.5. Blind token storage

Bảng:

```text
blind_signature_sessions
blind_tokens
```

Fields:

```text
id
token_id
purpose
requester_email
blinded_message_hash
signed_blind_message
final_token_hash
status
created_at
expires_at
redeemed_at
```

Nếu lưu `requester_email`, phải ghi rõ hệ thống chỉ đạt privacy-limited unlinkability.

Nếu muốn unlinkability mạnh hơn, redemption path không được nối trực tiếp final token với requester.

## 7.6. Redeem/double-spend protection

Khi redeem:

* verify blind signature
* check token purpose
* check expiry
* check final_token_hash chưa dùng
* mark redeemed
* reject token dùng lại

## 7.7. Frontend

Tạo page riêng:

```text
/privacy-tokens
```

Chức năng:

* request blind token
* unblind token
* redeem token
* verify token
* hiển thị limitation

Không đưa vào flow ký tài liệu chính.

## 7.8. Tests

* request blind token thành công
* user không có quyền request purpose bị reject
* thiếu domain separator bị reject
* token hết hạn redeem fail
* redeem 2 lần fail
* token payload bị sửa fail
* signature verify fail nếu dùng sai public key
* server không trả blinding factor
* rate limit hoạt động
* blind signer key khác CA key
* blind signer key khác TSA key

---

# PHASE 8 — Storage, Audit, Key Custody

## Mục tiêu

Hardening hệ thống để gần sản phẩm vận hành.

## 8.1. Document storage

Document cần:

```text
document_id
owner_id
content_hash
storage_path
mime_type
size
status
created_at
updated_at
```

Quy tắc:

* content hash bất biến
* không overwrite âm thầm document đã ký
* ACL theo user/role
* MIME sniffing
* extension whitelist
* path traversal protection
* versioning

## 8.2. Key custody

Không lưu private key plaintext.

CA/TSA/blind signer key:

* tách key riêng
* không hardcode
* không commit
* production nên dùng HSM/KMS
* root CA nên offline

User signing key:

* ưu tiên client-side
* WebCrypto non-extractable nếu có thể
* nếu export private key thì phải encrypt bằng passphrase và cảnh báo rõ

## 8.3. Audit log

Audit log append-only:

```text
eventId
actor
role
action
targetType
targetId
status
timestamp
metadata
previousHash
eventHash
```

Ghi log cho:

* login OTP request
* login success/fail
* issue cert
* revoke cert
* prepare signing request
* request signing OTP
* confirm signing
* submit signature
* verify signature
* audit export
* blind token request/redeem

## 8.4. Audit chain

Mỗi event hash bind với previous hash.

Nếu sửa event cũ, verify chain fail.

## 8.5. Tests

* user không có quyền không đọc được document
* path traversal bị reject
* MIME sai bị reject
* signed document không bị overwrite
* sửa audit event cũ bị phát hiện
* private key plaintext không xuất hiện trong localStorage nếu claim secure
* CA key không nằm trong repo

---

# PHASE 9 — Production Hardening, CI/CD, Final Report

## Mục tiêu

Đóng gói hệ thống để báo cáo như sản phẩm hoàn chỉnh ở mức đồ án.

## 9.1. Security hardening

* CORS allowlist
* rate limit
* request size limit
* security headers
* no secret logging
* no OTP logging
* no private key logging
* `.env.example` đầy đủ
* production check cho default secrets

## 9.2. Database

SQLite dùng local/dev.

Báo cáo cần ghi:

```text
SQLite phù hợp demo/local.
Production nên dùng PostgreSQL.
```

Nếu đủ thời gian, thêm migration bằng Alembic.

## 9.3. CI/CD

GitHub Actions:

```text
backend pytest
frontend build
lint/type check nếu có
dependency scan nếu có
```

## 9.4. Frontend UX

Role-based UX:

* Login page
* Signer dashboard
* CA Officer dashboard
* Verifier page
* Auditor page
* Admin page

Không expose:

* OTP
* JWT secret
* app password
* private key plaintext nếu claim secure
* role switch

## 9.5. Documentation

README/report cần có:

```text
architecture
threat model
RBAC model
signing flow
verification flow
certificate lifecycle
OTP/TOTP flow
timestamp flow
PAdES direction
blind signature module
audit model
limitations
future work
```

## 9.6. Final limitation section

Báo cáo phải nói rõ nếu chưa làm:

```text
chưa public CA
chưa HSM/KMS thật
chưa RFC3161 production TSA thật
chưa PAdES-LTV đầy đủ
chưa legal-grade digital signature
Gmail SMTP chỉ là sender demo/dev
SQLite chỉ là local/dev
```

## 9.7. Tests cuối

* backend pytest pass
* frontend build pass
* login OTP pass
* email OTP manual test pass
* signer sign flow pass
* verify valid signature pass
* tampered document fail
* revoked cert fail
* CA role test pass
* auditor role test pass
* blind token double redeem fail
* audit chain tamper fail

---

# Implementation Order

Không làm tất cả cùng lúc.

Thứ tự thực hiện:

```text
Phase 0  → dọn frontend, bỏ DocumentsWorkflow
Phase 1  → user/auth/RBAC/OTP/TOTP
Phase 2  → X.509/CA/chain/revocation
Phase 3  → signing mechanism/protocol
Phase 4  → digital signature services
Phase 5  → timestamp/RFC3161 foundation
Phase 6  → PDF/PAdES
Phase 7  → blind signature module
Phase 8  → storage/audit/key custody
Phase 9  → production hardening/final report
```

Sau mỗi phase chạy:

```bash
python -m pytest backend/tests -q
npm --prefix frontend run build
```

Sau mỗi phase báo cáo:

```text
Changed files:
- ...

Completed:
- ...

Tests added:
- ...

Test result:
- backend pytest:
- frontend build:

Remaining limitations:
- ...
```
