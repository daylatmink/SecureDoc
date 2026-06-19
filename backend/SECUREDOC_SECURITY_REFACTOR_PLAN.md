# SecureDoc Security & Digital Signature Refactor Plan

## Trạng thái triển khai trong repo

File này là roadmap bảo mật dài hạn. Trong lần refactor hiện tại repo đã xử lý các mục nền tảng sau:

```text
[x] Disable legacy private-key API by default
[x] Hide legacy private-key routes from OpenAPI by default
[x] Remove hard-coded demo PIN 123456 from frontend signing flow
[x] Add Email OTP model/API with hash, purpose, expiry, used_at, attempt_count
[x] Add TOTP Authenticator setup/verify primitives for MFA design
[x] Add basic demo RBAC roles for sensitive endpoints
[x] Move demo CA/TSA/blind-signer runtime keys out of backend source tree
[x] Add production guard for plaintext demo keys
[x] Split verify report into crypto/trust/revocation/timestamp/server/legal fields
[x] Add verify report warnings/errors separation
[x] Fix document hashing endpoint to respect requested hash algorithm
[x] Add request size limit, in-memory rate limit, and CORS allowlist config
[x] Disable blind-signature demo routes by default
[x] Add regression tests for the implemented security changes
[x] Add .env.example and SECURITY.md
```

Các mục sau vẫn là roadmap, chưa được coi là hoàn thành:

```text
[ ] Production authentication + RBAC backed by real accounts/JWT/session
[ ] Email delivery and full TOTP MFA login flow
[ ] Proof-of-possession for certificate issuance
[ ] Full RFC 5280 path validation
[ ] RFC 3161 TimeStampToken
[ ] PAdES/CAdES/XAdES signing profile
[ ] HSM/KMS/token-backed key custody
[ ] Distributed production rate limiting, HTTPS, CSRF/session hardening
```

Do đó repo vẫn là **educational demo**, không phải hệ thống production-ready hoặc legally-ready.

> Mục tiêu của file này: đặt vào repo để AI/code agent hoặc developer đọc và chỉnh sửa hệ thống SecureDoc theo hướng an toàn hơn, gần chuẩn chữ ký số thực tế hơn.  
> Ưu tiên chính: bỏ các luồng demo nguy hiểm, chuẩn hóa PKI/X.509, timestamp, PDF signing, xác thực người dùng, MFA, audit và kiểm thử bảo mật.

---

## 0. Nguyên tắc refactor bắt buộc

1. **Không phá luồng v2 đang pass test**, trừ khi có test mới thay thế rõ ràng.
2. **Không được để private key đi qua API client-server** trong mode bình thường.
3. **Không được gọi hệ thống là production-ready, legally-ready hoặc PAdES-compliant** nếu chưa implement đủ các phần tương ứng.
4. **Mọi thay đổi security phải có test âm tính**: sửa dữ liệu, đổi cert, dùng cert hết hạn, dùng nonce sai, dùng token sai đều phải fail.
5. **Tách rõ 3 cấp độ verify**:
   - `cryptoValid`: chữ ký và hash đúng về mặt mật mã.
   - `trustedChainValid`: certificate chain đáng tin theo trust anchor.
   - `serverAccepted`: package/signature thực sự thuộc luồng được SecureDoc tạo/nhận.

---

## 1. P0 — Tắt hoặc cô lập legacy API nguy hiểm

### Vấn đề

Legacy API vẫn expose hành vi demo nguy hiểm:

- `/api/keys/generate` trả `privateKeyPem` cho client.
- `/api/sign` nhận `privateKeyPem` từ client.

Các API này làm sai mô hình chữ ký số thực tế vì private key không được rời khỏi chủ thể ký hoặc thiết bị lưu khóa an toàn.

### Việc cần sửa

- Thêm biến môi trường:

```env
ENABLE_LEGACY_DEMO=false
```

- Nếu `ENABLE_LEGACY_DEMO=false`:
  - Không register route legacy.
  - Hoặc route trả `404 Not Found` / `410 Gone`.
  - Ẩn khỏi OpenAPI/Swagger.

- Nếu cần giữ demo cho lớp học:
  - Đưa route vào prefix riêng: `/api/demo/...`
  - Gắn cảnh báo rõ trong response và Swagger: `DEMO_ONLY_DO_NOT_USE_IN_PRODUCTION`.

### Acceptance criteria

- Khi chạy mode mặc định, gọi `/api/keys/generate` không trả private key.
- Khi chạy mode mặc định, gọi `/api/sign` không nhận `privateKeyPem`.
- OpenAPI không hiển thị legacy route trong mode bình thường.

### Test cần thêm

- `test_legacy_generate_key_disabled_by_default`
- `test_legacy_sign_disabled_by_default`
- `test_legacy_routes_hidden_from_openapi_when_disabled`

---

## 2. P0 — Bổ sung authentication, authorization và role model

### Vấn đề

Các chức năng nhạy cảm như issue certificate, revoke certificate, tạo signing request, xem audit/CRL không được public. Nếu ai cũng có thể gọi các API này thì hệ thống không có giá trị quản trị chữ ký số.

### Role đề xuất

```text
ADMIN        : quản trị hệ thống
CA_OFFICER   : cấp/revoke chứng thư
TSA_SERVICE  : ký timestamp token nội bộ
SIGNER       : người ký tài liệu
VERIFIER     : người xác minh tài liệu
AUDITOR      : xem audit log
```

### Việc cần sửa

- Thêm login/session/JWT hoặc cơ chế auth hiện có.
- Thêm middleware kiểm tra role.
- Các API phải enforce quyền:

```text
Issue user certificate        -> CA_OFFICER hoặc ADMIN
Revoke certificate            -> CA_OFFICER hoặc ADMIN
Create signing request        -> SIGNER
Submit signed package         -> SIGNER
Verify package                -> public hoặc VERIFIER, nhưng phải rate-limit
View audit log                -> AUDITOR hoặc ADMIN
Manage CA/TSA config          -> ADMIN
```

### Acceptance criteria

- User chưa login không gọi được API issue/revoke cert.
- User role `SIGNER` không revoke được cert.
- User role `VERIFIER` không issue được cert.
- API verify public nếu giữ public thì phải rate-limit.

### Test cần thêm

- `test_unauthenticated_cannot_issue_cert`
- `test_signer_cannot_revoke_cert`
- `test_ca_officer_can_issue_cert`
- `test_auditor_can_read_audit_log`

---

## 3. P0 — Thay PIN mặc định `123456` bằng Email OTP và TOTP

### Vấn đề

Không được dùng PIN mặc định như `123456` cho verification/MFA. Đây là shared secret dễ đoán, có thể bypass xác thực.

### Thiết kế mới

Dùng cả hai cơ chế nhưng chia vai trò rõ:

```text
Email OTP -> xác thực sự kiện ngắn hạn
TOTP      -> MFA đăng nhập dài hạn bằng Authenticator app
```

### Email OTP dùng cho

- Verify tài khoản sau đăng ký.
- Reset password.
- Đổi email.
- Xác nhận thao tác nhạy cảm nếu user chưa bật TOTP.

### TOTP dùng cho

- MFA khi đăng nhập.
- Xác nhận thao tác nhạy cảm nếu user đã bật MFA.

### Database đề xuất

```sql
users
----
id
email
password_hash
enabled
account_non_locked
login_attempts
last_login
created_at
updated_at
```

```sql
email_otp_tokens
----
id
user_id
purpose              -- REGISTER, RESET_PASSWORD, CHANGE_EMAIL, SENSITIVE_ACTION
otp_hash
expires_at
used_at
attempt_count
max_attempts
created_at
```

```sql
user_mfa_settings
----
id
user_id
type                 -- TOTP
secret_encrypted
enabled
verified_at
created_at
updated_at
last_used_at
```

```sql
mfa_recovery_codes
----
id
user_id
code_hash
used_at
created_at
```

### Quy tắc Email OTP

- OTP sinh bằng `SecureRandom`.
- Không lưu OTP thô, chỉ lưu hash.
- OTP hết hạn sau 5-10 phút.
- Sai quá 5 lần thì khóa token.
- Không log OTP.
- Không trả OTP trong API response.
- Resend phải có rate-limit.

### Quy tắc TOTP

- Secret riêng cho từng user.
- QR code chỉ hiển thị trong setup lần đầu.
- Không lưu QR image lâu dài trong public folder.
- Secret phải được encrypt trước khi lưu DB.
- Không log secret.
- Có recovery codes.
- Login chỉ cấp full access token sau khi pass TOTP.

### API đề xuất

```text
POST /auth/register
POST /auth/verify-email-otp
POST /auth/login
POST /auth/login/totp
POST /auth/password-reset/request
POST /auth/password-reset/confirm
POST /auth/refresh-token

POST /mfa/totp/setup
POST /mfa/totp/verify-setup
POST /mfa/totp/disable
POST /mfa/recovery-codes/regenerate
```

### Acceptance criteria

- Không còn hard-code PIN `123456` trong code production.
- OTP mỗi lần request là khác nhau.
- OTP hết hạn và không dùng lại được.
- TOTP QR chỉ hiển thị khi setup.
- Login với user bật MFA phải trả `mfaRequired=true`, chưa cấp access token đầy đủ.

### Test cần thêm

- `test_no_default_pin_123456_in_auth_flow`
- `test_email_otp_expires`
- `test_email_otp_cannot_be_reused`
- `test_email_otp_attempt_limit`
- `test_totp_setup_requires_valid_code`
- `test_login_requires_totp_when_mfa_enabled`
- `test_invalid_totp_does_not_issue_access_token`

---

## 4. P0 — Key custody cho CA/TSA/private keys

### Vấn đề

CA/TSA private key đang được ghi local plaintext hoặc dùng `NoEncryption()`. Đây là không phù hợp với hệ thống thực tế.

### Nguyên tắc

```text
Root CA key          -> offline, không dùng trực tiếp hằng ngày
Intermediate CA key  -> dùng để issue/revoke cert
TSA key              -> chỉ dùng để ký timestamp token
Signer private key   -> thuộc người ký, không thuộc backend
```

### Việc cần sửa ngắn hạn

Nếu chưa tích hợp HSM/KMS ngay:

- Encrypt private key at rest bằng passphrase hoặc master key từ env/secret manager.
- Set file permission chặt, ví dụ `0600`.
- Không commit private key vào repo.
- Không ghi key vào thư mục source code.
- Tách thư mục runtime secrets khỏi backend app.
- Thêm `.gitignore` cho key/cert runtime.

### Việc cần sửa dài hạn

- Tích hợp HSM/KMS/USB token/smart card hoặc remote signing service.
- Root CA offline.
- Intermediate CA riêng.
- Có key rotation.
- Có backup/key ceremony.
- Có audit cho mọi lần dùng CA/TSA key.

### Acceptance criteria

- Không có private key plaintext trong repo.
- Runtime key không được tạo trong source tree.
- CA/TSA private key không dùng `NoEncryption()` trong mode non-demo.
- Có warning/block nếu chạy production mà key plaintext.

### Test cần thêm

- `test_ca_private_key_not_written_plaintext_in_production_mode`
- `test_tsa_private_key_not_written_plaintext_in_production_mode`
- `test_runtime_secret_paths_are_outside_source_tree`

---

## 5. P1 — X.509 chain validation theo RFC 5280

### Vấn đề

Chain verify tự viết thường không đủ chuẩn. Không chỉ kiểm chữ ký cert này bởi cert kia, mà còn phải path validation đầy đủ.

### Cần kiểm đầy đủ

```text
- Trust anchor đúng
- BasicConstraints
- KeyUsage
- ExtendedKeyUsage
- CertificatePolicies
- SubjectKeyIdentifier
- AuthorityKeyIdentifier
- CRLDistributionPoints
- AuthorityInformationAccess
- pathLenConstraint
- notBefore/notAfter của toàn bộ chain
- signature algorithm của cert
- serial number đủ entropy
```

### Extension policy đề xuất

CA certificate:

```text
BasicConstraints: CA=true
KeyUsage: keyCertSign, cRLSign
```

User signing certificate:

```text
BasicConstraints: CA=false
KeyUsage: digitalSignature hoặc nonRepudiation/contentCommitment
ExtendedKeyUsage: documentSigning hoặc custom policy OID
```

TSA certificate:

```text
BasicConstraints: CA=false
KeyUsage: digitalSignature
ExtendedKeyUsage: timeStamping
```

### Việc cần sửa

- Không tự viết path validation nếu có thể tránh.
- Tích hợp thư viện validator chuẩn hoặc gọi OpenSSL/certvalidator.
- Nếu vẫn giữ validator nội bộ, phải có test phủ đủ các case âm tính.

### Acceptance criteria

- Cert user hết hạn -> verify fail.
- Cert CA thiếu `keyCertSign` -> chain fail.
- TSA cert thiếu EKU `timeStamping` -> timestamp fail.
- Chain thiếu intermediate -> fail, trừ khi intermediate được nhúng/tìm qua AIA.
- Cert not-yet-valid -> fail.

### Test cần thêm

- `test_chain_rejects_expired_user_cert`
- `test_chain_rejects_not_yet_valid_cert`
- `test_chain_rejects_ca_without_key_cert_sign`
- `test_chain_rejects_wrong_eku_for_tsa`
- `test_chain_rejects_missing_intermediate`

---

## 6. P1 — Certificate issuance phải có identity proofing và proof-of-possession

### Vấn đề

CA không được issue cert chỉ vì client gửi public key. Cần chứng minh người yêu cầu thật sự sở hữu private key tương ứng và subject trong cert khớp identity đã xác thực.

### Việc cần sửa

- User phải login trước khi request certificate.
- User phải verify email/identity trước khi được cấp cert.
- Client phải chứng minh proof-of-possession:
  - server gửi challenge;
  - client ký challenge bằng private key;
  - server verify bằng public key trong CSR/request.
- Subject/SubjectAltName trong cert lấy từ user identity đã xác thực, không tin hoàn toàn input client.
- CA officer/admin approve nếu hệ thống mô phỏng CA thực tế.

### Acceptance criteria

- Không issue cert cho anonymous user.
- Không issue cert nếu proof-of-possession fail.
- Không cho client tự set subject tùy ý để mạo danh người khác.

### Test cần thêm

- `test_cert_issue_requires_authenticated_user`
- `test_cert_issue_requires_proof_of_possession`
- `test_cert_subject_bound_to_verified_user_identity`

---

## 7. P1 — Thay demo timestamp JSON bằng RFC 3161 TimeStampToken

### Vấn đề

Timestamp hiện tại dạng JSON tự ký không phải RFC 3161 TSA. Timestamp chuẩn cần `TimeStampToken` dạng CMS SignedData.

### Yêu cầu tối thiểu

- Request có `messageImprint` gồm:
  - hash algorithm;
  - hashed message.
- Response có TimeStampToken dạng CMS SignedData.
- TSTInfo chứa đúng messageImprint.
- Nếu request có nonce, response phải có đúng nonce.
- TSA certificate phải có EKU `timeStamping`.
- Verify timestamp phải kiểm chữ ký TSA và chain TSA.

### Việc cần sửa

- Tách interface timestamp:

```python
class TimestampProvider:
    def request_timestamp(self, digest: bytes, hash_alg: str, nonce: bytes | None) -> bytes:
        ...

class DemoJsonTimestampProvider(TimestampProvider):
    ...

class Rfc3161TimestampProvider(TimestampProvider):
    ...
```

- Mode demo có thể dùng JSON provider, nhưng mode chuẩn phải dùng RFC 3161.
- Response verify phải có `timestampValid` riêng.

### Acceptance criteria

- Timestamp token không còn là JSON trong mode chuẩn.
- Verify fail nếu message imprint mismatch.
- Verify fail nếu nonce mismatch.
- Verify fail nếu TSA cert thiếu EKU `timeStamping`.

### Test cần thêm

- `test_rfc3161_timestamp_imprint_mismatch_fails`
- `test_rfc3161_timestamp_nonce_mismatch_fails`
- `test_rfc3161_timestamp_requires_tsa_eku`

---

## 8. P1/P2 — PDF signing chuyển từ visual stamp sang PAdES

### Vấn đề

PDF stamp/preview chỉ là hiển thị trực quan, không phải chữ ký số PDF thật. Nếu mục tiêu là ký PDF thực tế, cần PAdES.

### Mục tiêu theo giai đoạn

```text
Stage 1: PAdES-B-B
Stage 2: PAdES-B-T
Stage 3: PAdES-B-LT
Stage 4: PAdES-B-LTA
```

### Yêu cầu kỹ thuật PDF signing

- PDF Signature Dictionary.
- `ByteRange` đúng.
- `Contents` chứa CMS/CAdES detached signature.
- `SubFilter` phù hợp.
- Signed attributes tối thiểu:
  - content-type;
  - message-digest;
  - signing-certificate-v2.
- PAdES-B-T: thêm RFC 3161 timestamp.
- PAdES-B-LT: nhúng cert chain + OCSP/CRL vào DSS/VRI.
- PAdES-B-LTA: thêm document timestamp cho long-term archival.

### Việc cần sửa

- Giữ visual stamp như phần hiển thị phụ, không coi là chữ ký.
- Thêm module PDF signer chuẩn, ưu tiên dùng thư viện có hỗ trợ PAdES.
- Verify PDF phải dựa trên ByteRange/CMS, không dựa trên preview stamp.

### Acceptance criteria

- File PDF ký xong được PDF viewer/validator nhận diện là có chữ ký số.
- Sửa 1 byte trong signed ByteRange -> verify fail.
- Visual stamp bị xóa/sửa không được coi là verify chữ ký nếu cryptographic signature còn/không còn tương ứng.

### Test cần thêm

- `test_pdf_signature_byterange_tamper_fails`
- `test_pdf_signature_content_tamper_fails`
- `test_pdf_signature_has_cms_contents`
- `test_pdf_pades_bt_contains_timestamp`

---

## 9. P1 — Verify result phải tách nhiều trạng thái

### Vấn đề

Một package có thể đúng về mật mã nhưng chưa từng được SecureDoc submit/accept. Không nên trả chung một field `valid` gây hiểu nhầm.

### Response model đề xuất

```json
{
  "cryptoValid": true,
  "documentHashValid": true,
  "signatureValid": true,
  "trustedChainValid": true,
  "revocationValid": true,
  "timestampValid": true,
  "serverAccepted": false,
  "legalReady": false,
  "warnings": [
    "Package is cryptographically valid but was not submitted to SecureDoc"
  ]
}
```

### Ý nghĩa

```text
cryptoValid       : chữ ký/hash đúng
trustedChainValid : chain từ signer cert lên trust anchor hợp lệ
revocationValid   : cert chưa bị revoke tại thời điểm ký
 timestampValid   : timestamp token hợp lệ
serverAccepted    : package/requestId/nonce tồn tại trong hệ thống
legalReady         : chỉ true khi đủ policy pháp lý/kỹ thuật đã định nghĩa
```

### Acceptance criteria

- Package offline hợp lệ nhưng nonce chưa từng submit -> `cryptoValid=true`, `serverAccepted=false`.
- Package submit qua SecureDoc đúng luồng -> `serverAccepted=true`.
- UI phải hiển thị khác nhau giữa “cryptographically valid” và “accepted by SecureDoc”.

### Test cần thêm

- `test_offline_valid_package_is_not_server_accepted`
- `test_submitted_package_is_server_accepted`
- `test_ui_distinguishes_crypto_valid_from_server_accepted`

---

## 10. P1 — Revocation theo thời điểm ký

### Vấn đề

Không chỉ kiểm cert hiện tại có revoked không. Cần kiểm cert có hợp lệ tại thời điểm ký đã được timestamp không.

### Trường hợp cần xử lý

```text
Cert bị revoke sau thời điểm ký hợp lệ  -> chữ ký cũ có thể vẫn trusted
Cert bị revoke trước thời điểm ký       -> chữ ký không trusted
Không có trusted timestamp              -> khó chứng minh thời điểm ký
```

### Việc cần sửa

- Verify revocation theo `signingTime` hoặc trusted RFC3161 timestamp.
- Lưu hoặc nhúng OCSP/CRL evidence.
- Với PAdES-LT, đưa OCSP/CRL vào DSS/VRI.

### Acceptance criteria

- Cert revoked after timestamp -> old signature vẫn có thể valid nếu policy cho phép.
- Cert revoked before timestamp -> verify fail.
- Không có timestamp -> không được kết luận long-term trusted.

### Test cần thêm

- `test_signature_valid_when_cert_revoked_after_signing_time`
- `test_signature_invalid_when_cert_revoked_before_signing_time`
- `test_no_timestamp_cannot_claim_ltv_ready`

---

## 11. P1 — Canonical payload và signature binding

### Vấn đề

Ký đúng thuật toán chưa đủ. Payload được ký phải bind đầy đủ tài liệu, người ký, thuật toán, cert, nonce và signing intent. Nếu không có thể bị mix-and-match hoặc signature substitution.

### Payload đề xuất

```json
{
  "schemaVersion": "SecureDoc-Signature-v2",
  "documentHash": "...",
  "hashAlgorithm": "SHA-256",
  "signatureAlgorithm": "RSA-PSS-SHA256",
  "documentId": "...",
  "fileName": "...",
  "mimeType": "application/pdf",
  "signerCertSerial": "...",
  "signerCertFingerprint": "...",
  "issuedAt": "...",
  "nonce": "...",
  "signingIntent": "I approve and sign this document"
}
```

### Việc cần sửa

- Canonicalization phải deterministic tuyệt đối.
- Verify phải reject nếu thiếu field bắt buộc.
- Verify phải reject nếu algorithm metadata khác algorithm thực tế.
- Bind signature với cert fingerprint/serial.
- Bind signature với document hash và nonce/requestId.

### Acceptance criteria

- Đổi `documentHash` -> verify fail.
- Đổi `signerCertFingerprint` -> verify fail.
- Đổi `signatureAlgorithm` -> verify fail.
- Thiếu `schemaVersion` hoặc field bắt buộc -> verify fail.

### Test cần thêm

- `test_payload_tamper_document_hash_fails`
- `test_payload_tamper_signer_cert_fails`
- `test_payload_algorithm_confusion_fails`
- `test_payload_missing_required_field_fails`

---

## 12. P1 — Algorithm allowlist và downgrade protection

### Vấn đề

Hệ thống phải reject thuật toán yếu hoặc không được policy cho phép. Không được để client tự khai algorithm rồi backend tin theo.

### Policy đề xuất

Allowed:

```text
Hash: SHA-256, SHA-384, SHA-512
Signature: RSA-PSS-SHA256/SHA384/SHA512, ECDSA-SHA256/SHA384, Ed25519 nếu hỗ trợ đầy đủ
RSA key size: >= 3072 cho mức ~128-bit security dài hạn hơn
```

Rejected:

```text
MD5
SHA-1
RSA < 2048
RSA-PKCS1-v1_5 nếu policy chỉ cho PSS
unknown algorithm
algorithm mismatch giữa metadata và signature object
```

### Acceptance criteria

- Reject SHA-1/MD5.
- Reject RSA key quá ngắn.
- Reject algorithm không nằm trong allowlist.
- Verify không bị algorithm confusion.

### Test cần thêm

- `test_rejects_md5_digest`
- `test_rejects_sha1_digest`
- `test_rejects_small_rsa_key`
- `test_rejects_unknown_signature_algorithm`

---

## 13. P1/P2 — Blind signature chỉ được coi là demo nếu chưa chuẩn hóa

### Vấn đề

Textbook RSA blind signature bằng raw modular exponentiation trên hash không nên gọi là production blind signature.

### Việc cần sửa

- Đổi tên module/route nếu vẫn demo:

```text
/api/demo/blind-signature/...
```

- Gắn warning rõ:

```text
This is a textbook RSA blind signature demo, not production-safe.
```

- Nếu muốn nâng cấp:
  - dùng scheme chuẩn hơn như RSA-FDH blind signature;
  - domain separation;
  - rate limit;
  - anti-abuse;
  - không expose blinding factor/token nhạy cảm;
  - kiểm thử unlinkability ở mức demo;
  - chống dùng service làm signing oracle.

### Acceptance criteria

- Documentation không gọi blind signature hiện tại là production-ready.
- Route demo không enabled trong production mode.
- Không trả blinding factor/token nhạy cảm nếu không cần thiết.

### Test cần thêm

- `test_blind_signature_demo_disabled_in_production`
- `test_blind_signature_rate_limited`
- `test_blind_signature_response_does_not_expose_sensitive_blinding_factor`

---

## 14. P1/P2 — Audit log append-only

### Vấn đề

Hệ chữ ký số cần audit có khả năng truy vết. Log thường có thể bị sửa/xóa, không đủ.

### Event cần log

```text
- user login/logout
- MFA enabled/disabled
- certificate issued
- certificate revoked
- signing request created
- document signed
- package submitted
- package verified
- timestamp requested
- admin action
- failed security checks
```

### Thiết kế đề xuất

```sql
audit_events
----
id
actor_user_id
action
resource_type
resource_id
request_id
ip_address
user_agent
created_at
previous_event_hash
event_hash
```

Trong đó:

```text
event_hash = SHA256(canonical_event_without_hash + previous_event_hash)
```

### Acceptance criteria

- Mỗi event có hash.
- Event sau chứa hash của event trước.
- Không có API update/delete audit event thông thường.
- Auditor/Admin xem được audit theo quyền.

### Test cần thêm

- `test_audit_event_hash_chain_valid`
- `test_audit_event_cannot_be_modified_by_normal_api`
- `test_security_actions_create_audit_events`

---

## 15. P2 — Secure document storage

### Vấn đề

SecureDoc không chỉ cần chữ ký. File tài liệu cũng phải được bảo vệ.

### Việc cần sửa

- Lưu file theo content hash hoặc object ID, không dùng raw filename.
- Chống path traversal.
- Kiểm MIME type thật, không chỉ extension.
- Giới hạn kích thước upload.
- Quét malware nếu mô phỏng hệ thực tế.
- Mã hóa at rest nếu lưu tài liệu nhạy cảm.
- Per-document ACL: owner, signer, viewer, admin.
- Không cho overwrite file đã ký; dùng versioning/immutable object.

### Acceptance criteria

- Upload `../../evil.py` không ghi ra ngoài thư mục storage.
- File `.pdf` giả nhưng MIME không hợp lệ bị reject.
- User A không đọc được document private của User B.
- File đã ký không bị overwrite; nếu update thì tạo version mới.

### Test cần thêm

- `test_upload_rejects_path_traversal_filename`
- `test_upload_rejects_invalid_mime`
- `test_document_acl_blocks_other_user`
- `test_signed_document_is_immutable`

---

## 16. P2 — Frontend/browser signing hardening

### Vấn đề

Browser signing tốt hơn gửi private key lên server, nhưng vẫn có rủi ro XSS, dependency độc, localStorage leak.

### Việc cần sửa

- Không lưu private key plaintext trong localStorage/sessionStorage.
- Ưu tiên WebCrypto non-extractable key.
- Nếu phải export/backup key, yêu cầu passphrase mạnh và encrypt key.
- Content Security Policy nghiêm ngặt.
- Không inline script.
- Không log private key, PEM, signing payload nhạy cảm.
- Confirmation screen phải hiển thị chính xác tài liệu/hash/ý nghĩa ký trước khi ký.

### Acceptance criteria

- Không tìm thấy private key plaintext trong localStorage.
- CSP được cấu hình.
- User phải confirm nội dung trước khi ký.
- Signing payload hiển thị cho user không bị đánh tráo bởi UI.

### Test cần thêm

- `test_private_key_not_stored_plaintext_in_browser_storage`
- `test_signing_requires_user_confirmation`
- `test_frontend_has_csp_headers`

---

## 17. P2 — API hardening

### Việc cần sửa

- Rate limit:
  - login;
  - OTP verify;
  - TOTP verify;
  - issue cert;
  - revoke cert;
  - timestamp;
  - verify package;
  - blind signature.
- Replay protection cho signing request.
- CORS allowlist.
- CSRF protection nếu dùng cookie.
- HTTPS-only config.
- Secure cookie nếu có session:
  - `HttpOnly`;
  - `Secure`;
  - `SameSite`.
- Request size limit.
- Không log dữ liệu nhạy cảm.

### Acceptance criteria

- Brute force OTP/TOTP bị chặn.
- CORS không allow `*` trong production.
- Request quá lớn bị reject.
- Replay signing request bị reject.

### Test cần thêm

- `test_totp_rate_limit`
- `test_otp_rate_limit`
- `test_cors_not_wildcard_in_production`
- `test_replay_signing_request_rejected`
- `test_large_request_rejected`

---

## 18. P2 — Database migration và config production

### Việc cần sửa

- Dùng Alembic/Flyway/Liquibase hoặc migration tool phù hợp.
- Không tự động tạo/sửa schema tùy tiện trong production.
- Tách config:
  - `development`;
  - `test`;
  - `production`.
- `.env.example` chỉ chứa placeholder.
- `.gitignore` phải ignore:
  - `.env`;
  - private keys;
  - cert runtime;
  - upload storage;
  - logs;
  - local DB.

### Acceptance criteria

- Fresh clone chạy được bằng `.env.example` + migration.
- Không có secret thật trong repo.
- Production mode không dùng debug config.

### Test/check cần thêm

- CI check không có private key fixture ngoài thư mục test cho phép.
- CI check không commit `.env`.
- Migration chạy sạch trên DB mới.

---

## 19. P3 — Test strategy mới

### Test hiện tại

Backend pass 17/17 là tín hiệu tốt, nhưng chưa chứng minh hệ thống secure. Cần tăng test âm tính và interoperability test.

### Negative tests bắt buộc

```text
- Sửa 1 byte document -> verify fail
- Đổi signer cert -> fail
- Đổi cert chain -> fail
- Đổi algorithm metadata -> fail
- Cert expired -> fail
- Cert not-yet-valid -> fail
- Cert revoked before signing time -> fail
- Timestamp imprint mismatch -> fail
- Timestamp nonce mismatch -> fail
- Chain thiếu intermediate -> fail
- CA thiếu BasicConstraints CA=true -> fail
- CA thiếu keyCertSign -> fail
- TSA thiếu EKU timeStamping -> fail
- Replay nonce/requestId -> fail
```

### Interoperability tests nên có

```text
- Verify certificate chain bằng OpenSSL hoặc certvalidator
- Verify RFC3161 timestamp bằng OpenSSL ts nếu dùng RFC3161
- PDF ký xong được Adobe Reader hoặc validator nhận diện
- CMS signature verify bằng thư viện độc lập
```

### CI đề xuất

```text
backend tests
frontend build
lint/typecheck
security tests
secret scan
dependency vulnerability scan
```

---

## 20. Definition of Done theo từng mức

### Demo-safe

- Legacy API bị tắt mặc định.
- Không còn PIN mặc định.
- Không gửi private key qua API.
- Có auth cơ bản.
- Có test âm tính cho tamper document/signature.

### PKI-aware

- X.509 validation dùng validator chuẩn hoặc test phủ kỹ.
- Có revocation model.
- Có role CA officer.
- Có proof-of-possession khi issue cert.
- CA/TSA key không plaintext trong mode thường.

### Signature-system-ready

- Verify result tách nhiều trạng thái.
- Timestamp RFC3161.
- Revocation theo signing time.
- Audit append-only.
- Document ACL + immutable storage.

### PAdES-ready

- PDF signature dùng ByteRange/CMS.
- Có PAdES-B-B/B-T.
- B-LT/B-LTA nếu cần long-term validation.
- PDF verify được bởi tool bên ngoài.

### Production-ready

- HSM/KMS hoặc key custody tương đương.
- HTTPS, rate limit, CORS/CSRF, secure cookie.
- Monitoring/audit/backup/rotation.
- Migration DB.
- CI security checks.
- Documentation rõ ràng.

---

## 21. Thứ tự implement khuyến nghị

### Sprint 1 — Chặn lỗi nguy hiểm

1. Tắt legacy API.
2. Bỏ PIN `123456`, thay bằng Email OTP/TOTP design tối thiểu.
3. Thêm auth/role guard cho route nhạy cảm.
4. Tách verify response thành nhiều trạng thái.
5. Thêm test âm tính cơ bản.

### Sprint 2 — Chuẩn hóa PKI

1. Proof-of-possession khi issue cert.
2. X.509 extension policy.
3. Path validation chuẩn.
4. Revocation model.
5. CA/TSA key encryption at rest.

### Sprint 3 — Timestamp và PDF

1. RFC3161 timestamp provider.
2. PAdES-B-B.
3. PAdES-B-T.
4. PDF validation tests.

### Sprint 4 — Production hardening

1. Audit append-only.
2. Document ACL + immutable storage.
3. Rate limit/CORS/CSRF/HTTPS.
4. Frontend signing hardening.
5. CI security checks.

---

## 22. Documentation cần cập nhật

Tạo/cập nhật các file sau:

```text
README.md
SECURITY.md
docs/architecture.md
docs/security-model.md
docs/digital-signature-flow.md
docs/pki-x509-design.md
docs/timestamp-rfc3161.md
docs/pades-roadmap.md
docs/threat-model.md
docs/api.md
.env.example
```

### README cần nói rõ

- Repo hiện ở mức demo/educational hay production.
- Legacy API chỉ dùng demo.
- Luồng v2 không gửi private key lên backend.
- Các giới hạn hiện tại: chưa PAdES, chưa RFC3161 nếu chưa làm, chưa HSM/KMS.

### SECURITY.md cần có

- Cách report vulnerability.
- Không commit secrets.
- Key handling rules.
- Supported security modes.
- Production warning.

---

## 23. Ghi chú quan trọng cho AI/code agent

Khi sửa repo, không được chỉ đổi text/documentation rồi coi là hoàn tất. Với mỗi mục P0/P1, cần:

```text
1. Sửa code.
2. Thêm hoặc sửa test.
3. Cập nhật docs.
4. Chạy test backend.
5. Chạy build frontend nếu ảnh hưởng UI.
6. Ghi rõ phần nào còn là demo.
```

Không được tạo cảm giác hệ thống đã đạt chuẩn pháp lý nếu chưa có:

```text
- trusted CA thực tế;
- RFC3161 timestamp thật;
- PAdES thật cho PDF;
- revocation checking đúng;
- key custody bằng HSM/KMS/token hoặc tương đương;
- identity proofing và quy trình vận hành.
```

---

## 24. Checklist nhanh

```text
[x] Disable legacy private-key API by default
[x] Remove default PIN 123456
[x] Implement Email OTP with expiry, hash, attempt limit
[x] Implement TOTP MFA setup primitives
[ ] Add recovery codes
[x] Add demo auth + RBAC
[ ] Encrypt CA/TSA keys or integrate KMS/HSM
[ ] Add proof-of-possession for cert issuance
[ ] Improve X.509 validation
[ ] Add EKU/KeyUsage/BasicConstraints policies
[ ] Implement revocation semantics by signing time
[ ] Replace demo timestamp with RFC3161 provider
[ ] Implement PAdES roadmap for PDF
[x] Split verify result fields
[ ] Add canonical payload binding checks
[ ] Add algorithm allowlist
[x] Gate blind signature demo
[ ] Add append-only audit log
[ ] Add document ACL and immutable storage
[ ] Harden frontend signing and browser key storage
[x] Add rate limit and CORS config
[ ] Add CSRF/HTTPS/session hardening
[ ] Add migration and production config
[ ] Add negative tests
[ ] Add interoperability tests
[x] Update README/SECURITY/docs
```
