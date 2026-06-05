# Kịch bản trình bày SecureDoc

Tài liệu này dùng để trình bày repo SecureDoc trong báo cáo/thuyết trình chủ đề **chữ ký số**. Nội dung tập trung vào: mục tiêu nhóm, hệ thống đã hình thành, kịch bản triển khai, từng giai đoạn dùng cơ chế/thuật toán nào, vai trò của từng cơ chế trong hệ thống, các tình huống tấn công và hướng cải tiến nâng cao.

## 1. Mục tiêu của nhóm

Mục tiêu của nhóm là xây dựng một hệ thống web demo để minh họa quy trình chữ ký số cho tài liệu điện tử.

Hệ thống cần cho thấy được các ý chính của chủ đề chữ ký số:

```text
1. Tài liệu được băm như thế nào.
2. Chữ ký số được tạo ra từ private key như thế nào.
3. Chữ ký được xác minh bằng public key như thế nào.
4. Certificate giúp gắn public key với danh tính người ký như thế nào.
5. CA giúp certificate đáng tin hơn như thế nào.
6. Certificate bị thu hồi thì hệ thống xử lý ra sao.
7. Chữ ký mù hoạt động về nguyên lý như thế nào.
```

Nói ngắn gọn:

```text
Nhóm xây dựng SecureDoc để mô phỏng một luồng ký số tài liệu từ đầu đến cuối:
tạo khóa -> cấp certificate -> ký tài liệu -> tạo signed package -> xác minh -> phát hiện tấn công/sai lệch.
```

Đây là hệ thống học thuật, không phải hệ thống ký số pháp lý hoặc production.

## 2. Hệ thống đã hình thành

Repo hiện hình thành một web app tên **SecureDoc** gồm:

```text
Frontend: React + Vite
Backend: FastAPI
Database: SQLite
Crypto library: cryptography của Python
```

Các chức năng chính:

```text
1. Băm file bằng SHA-256.
2. Sinh cặp khóa RSA 2048-bit.
3. Tạo certificate JSON cho người ký.
4. Demo CA ký certificate.
5. Ký tài liệu bằng RSA-PSS.
6. Tạo signed_package.json.
7. Xác minh tài liệu và chữ ký.
8. Thu hồi certificate.
9. Mô phỏng chữ ký mù RSA.
```

Các endpoint/API chính:

```text
POST /api/documents/hash
POST /api/keys/generate
GET  /api/ca/public-key
POST /api/sign
POST /api/verify
POST /api/certificates/revoke
POST /api/blind-signature/demo
```

## 3. Kịch bản tổng thể của hệ thống

Luồng triển khai chính:

```text
Giai đoạn 1: Băm tài liệu
Giai đoạn 2: Tạo khóa người ký
Giai đoạn 3: Demo CA cấp và ký certificate
Giai đoạn 4: Ký tài liệu
Giai đoạn 5: Tạo signed package
Giai đoạn 6: Xác minh tài liệu
Giai đoạn 7: Kiểm thử các tình huống sai lệch/tấn công
Giai đoạn 8: Thu hồi certificate
Giai đoạn 9: Mô phỏng chữ ký mù
```

Ý tưởng chính:

```text
Người ký có private key để ký.
Người nhận dùng public key để xác minh.
Certificate giúp biết public key thuộc về ai.
Demo CA giúp certificate không bị sửa tùy ý.
Server DB giúp kiểm tra certificate đã bị thu hồi chưa.
```

## 4. Giai đoạn 1: Băm tài liệu

### Người dùng làm gì?

Người dùng upload một file vào tab `Băm file`.

### Hệ thống dùng thuật toán gì?

```text
SHA-256
```

### SHA-256 là gì?

SHA-256 là hàm băm mật mã học. Nó nhận dữ liệu đầu vào có độ dài bất kỳ và sinh ra một giá trị băm có độ dài cố định 256 bit.

Ví dụ:

```text
file gốc -> SHA-256 -> documentHash
```

### Mục đích của SHA-256

Mục đích là tạo một giá trị đại diện cho nội dung tài liệu.

Nếu file bị sửa dù chỉ một ký tự, hash gần như chắc chắn sẽ thay đổi hoàn toàn.

### Vai trò trong hệ thống

Hệ thống không ký trực tiếp toàn bộ file. Thay vào đó, hệ thống ký hash của file.

Lý do:

```text
1. Hash có kích thước cố định.
2. Ký hash nhanh hơn ký toàn bộ file.
3. Hash giúp phát hiện tài liệu bị sửa sau khi ký.
```

Đầu vào:

```text
file tài liệu
```

Đầu ra:

```text
documentHash
```

## 5. Giai đoạn 2: Tạo khóa người ký

### Người dùng làm gì?

Người dùng nhập họ tên và email ở tab `Tạo khóa`.

### Hệ thống dùng thuật toán gì?

```text
RSA 2048-bit
```

### RSA là gì?

RSA là thuật toán mật mã bất đối xứng. Nó dùng một cặp khóa:

```text
Private key: giữ bí mật, dùng để ký.
Public key: công khai, dùng để xác minh.
```

### Mục đích của RSA trong chữ ký số

RSA giúp tạo chữ ký mà chỉ người có private key mới tạo được, nhưng bất kỳ ai có public key tương ứng đều có thể kiểm tra.

### Vai trò trong hệ thống

Ở SecureDoc:

```text
private_key.pem dùng để ký tài liệu
public_key.pem dùng để xác minh chữ ký
```

Đầu ra của bước này:

```text
private_key.pem
public_key.pem
certificate.json
```

Điểm quan trọng:

```text
Private key phải được giữ bí mật.
Nếu private key bị lộ, người khác có thể giả mạo chữ ký.
```

## 6. Giai đoạn 3: Demo CA cấp và ký certificate

### Certificate là gì?

Certificate là chứng thư số. Trong repo này, certificate là file JSON chứa:

```text
serialNumber
ownerName
email
publicKeyPem
issuer
issuedAt
expiresAt
status
caSignatureAlgorithm
caSignatureBase64
```

### Certificate dùng để làm gì?

Certificate giúp gắn public key với danh tính người ký.

Nếu chỉ có public key, hệ thống chỉ biết:

```text
Chữ ký này khớp với public key X.
```

Nhưng hệ thống chưa biết:

```text
Public key X thuộc về ai?
```

Certificate trả lời câu hỏi đó:

```text
Public key X thuộc về Nguyễn Văn A, email student@example.com.
```

### CA là gì?

CA là Certificate Authority, tức là bên cấp chứng thư số.

Vai trò của CA:

```text
Xác nhận public key trong certificate thuộc về đúng danh tính được ghi trong certificate.
```

Trong repo này, CA là:

```text
SecureDoc Demo CA
```

### CA ký certificate là gì?

Demo CA lấy các trường quan trọng trong certificate:

```text
serialNumber
ownerName
email
publicKeyPem
issuer
issuedAt
expiresAt
```

rồi ký các trường đó bằng private key của CA.

Thuật toán dùng:

```text
RSA-PSS + SHA-256
```

Kết quả là certificate có:

```text
caSignatureAlgorithm = RSA-PSS-SHA256
caSignatureBase64 = chữ ký của CA
```

### Tại sao cần CA?

Nếu không có CA, hacker có thể tự tạo certificate giả:

```json
{
  "ownerName": "Nguyen Van A",
  "email": "student@example.com",
  "publicKeyPem": "public key của hacker"
}
```

Sau đó hacker ký tài liệu bằng private key của nó.

Nếu hệ thống chỉ kiểm tra chữ ký với public key trong JSON, kết quả vẫn có thể là:

```text
signature valid
```

Nhưng thực chất người ký là hacker, không phải Nguyễn Văn A.

CA giúp chống giả mạo danh tính này.

### Hacker có sửa được CA không?

Cần tách thành nhiều trường hợp:

```text
1. Hacker sửa certificate JSON:
   Sửa được file, nhưng không tạo lại được chữ ký CA hợp lệ.

2. Hacker tự tạo certificate giả:
   Không được hệ thống tin vì không có chữ ký Demo CA hợp lệ.

3. Hacker lấy được private key của CA:
   Rất nguy hiểm, vì hacker có thể ký certificate giả.

4. Hacker thay được public key CA mà backend tin:
   Rất nguy hiểm, vì hacker có thể dựng CA giả.

5. Hacker sửa được database revocation:
   Có thể làm certificate revoked thành valid.
```

Vì vậy trong hệ thống thật, private key CA, CA public key và database revocation phải được bảo vệ rất nghiêm ngặt.

### Vai trò của CA trong hệ thống

Demo CA giúp hệ thống kiểm tra:

```text
1. Certificate có đúng do Demo CA cấp không.
2. Thông tin trong certificate có bị sửa không.
3. Public key trong certificate có đáng tin hơn không.
```

Nếu sửa `ownerName`, `email`, `publicKeyPem`, `issuedAt` hoặc `expiresAt`, backend sẽ phát hiện:

```text
caSignatureValid = false
reason = certificate not issued by demo CA
```

## 7. Giai đoạn 4: Ký tài liệu

### Người dùng làm gì?

Người dùng vào tab `Ký tài liệu` và upload:

```text
file gốc
private_key.pem
certificate.json
```

### Backend kiểm tra gì trước khi ký?

Backend thực hiện:

```text
1. Parse certificate JSON.
2. Kiểm tra certificate có chữ ký hợp lệ của Demo CA không.
3. Tra DB xem certificate đã bị revoke chưa.
4. Tính SHA-256 của file.
5. Ký documentHash bằng private key người ký.
6. Kiểm tra private key có khớp public key trong certificate không.
```

### Thuật toán/cơ chế dùng

```text
SHA-256: băm tài liệu.
RSA-PSS: ký hash tài liệu.
CA signature verify: kiểm tra certificate.
SQLite lookup: kiểm tra trạng thái revoke.
```

### RSA-PSS là gì?

RSA-PSS là cơ chế chữ ký số dựa trên RSA. So với padding RSA cũ, RSA-PSS được thiết kế an toàn hơn cho chữ ký số hiện đại.

Trong SecureDoc:

```text
documentHash + private key -> RSA-PSS -> signatureBase64
```

### Vai trò của bước ký

Bước này tạo bằng chứng rằng:

```text
Người có private key tương ứng đã ký lên hash của tài liệu.
```

Đầu ra:

```text
signed_package.json
```

## 8. Giai đoạn 5: Tạo signed package

### signed_package.json là gì?

`signed_package.json` là gói kết quả sau khi ký tài liệu.

Nó chứa:

```text
documentName
documentHash
hashAlgorithm
signatureAlgorithm
signatureBase64
signedAt
certificate
```

### Mục đích của signed package

Người nhận không chỉ cần file gốc, mà còn cần thông tin để xác minh:

```text
hash ban đầu của tài liệu
chữ ký số
thuật toán đã dùng
certificate của người ký
thời điểm ký
```

### Vai trò trong hệ thống

`signed_package.json` đóng vai trò như bằng chứng đi kèm tài liệu.

Khi người nhận verify, họ upload:

```text
file cần kiểm tra
signed_package.json
```

## 9. Giai đoạn 6: Xác minh tài liệu

### Người dùng làm gì?

Người nhận upload:

```text
file cần kiểm tra
signed_package.json
```

### Backend xác minh theo thứ tự nào?

Backend thực hiện:

```text
1. Tính lại SHA-256 của file upload.
2. So sánh hash mới với documentHash trong signed_package.json.
3. Kiểm tra chữ ký CA trên certificate.
4. Tra trạng thái certificate trong SQLite theo serialNumber.
5. Kiểm tra certificate còn hạn.
6. Verify chữ ký tài liệu bằng public key trong certificate.
```

### Thuật toán/cơ chế dùng

```text
SHA-256: kiểm tra file có bị sửa không.
RSA-PSS verify: kiểm tra chữ ký tài liệu.
CA public key: kiểm tra certificate.
SQLite DB: kiểm tra trạng thái thu hồi.
```

### Ý nghĩa của từng kiểm tra

Kiểm tra hash:

```text
Phát hiện file bị sửa sau khi ký.
```

Kiểm tra chữ ký CA:

```text
Phát hiện certificate bị sửa hoặc certificate giả.
```

Kiểm tra DB revoke:

```text
Phát hiện certificate đã bị thu hồi.
```

Kiểm tra hạn certificate:

```text
Đảm bảo certificate chưa hết hạn.
```

Verify chữ ký tài liệu:

```text
Đảm bảo chữ ký được tạo bởi private key khớp với public key trong certificate.
```

### Kết quả hợp lệ

```text
valid = true
reason = signature valid
hashMatches = true
caSignatureValid = true
certificateStatusFromServer = valid
signatureValid = true
```

## 10. Giai đoạn 7: Kiểm thử tình huống tấn công

### Tấn công 1: Sửa file sau khi ký

Hacker sửa nội dung tài liệu.

Hệ thống phát hiện bằng:

```text
SHA-256
```

Kết quả:

```text
valid = false
reason = document modified
hashMatches = false
```

Ý nghĩa:

```text
Chữ ký số bảo vệ tính toàn vẹn của tài liệu.
```

### Tấn công 2: Sửa tên/email trong certificate

Hacker sửa danh tính người ký trong certificate.

Hệ thống phát hiện bằng:

```text
CA signature verification
```

Kết quả:

```text
valid = false
reason = certificate not issued by demo CA
caSignatureValid = false
```

Ý nghĩa:

```text
Certificate không thể bị sửa tùy ý nếu không có private key CA.
```

### Tấn công 3: Thay public key trong certificate

Hacker thay public key của người ký bằng public key của hacker.

Hệ thống phát hiện bằng:

```text
CA signature verification
```

Kết quả:

```text
certificate not issued by demo CA
```

Ý nghĩa:

```text
CA giúp bảo vệ liên kết giữa danh tính và public key.
```

### Tấn công 4: Dùng sai private key khi ký

Người dùng dùng private key B nhưng certificate A.

Hệ thống phát hiện bằng:

```text
Verify chữ ký thử bằng public key trong certificate A.
```

Kết quả:

```text
Private key does not match certificate public key
```

Ý nghĩa:

```text
Private key phải đúng là khóa tương ứng với public key trong certificate.
```

### Tấn công 5: Certificate bị thu hồi

Certificate trước đây hợp lệ nhưng hiện bị thu hồi.

Hệ thống phát hiện bằng:

```text
SQLite DB lookup theo serialNumber
```

Kết quả:

```text
valid = false
reason = certificate revoked
certificateStatusInPackage = valid
certificateStatusFromServer = revoked
```

Ý nghĩa:

```text
Hệ thống không chỉ tin status trong file JSON người dùng upload.
Trạng thái tin cậy phải được kiểm tra từ server.
```

## 11. Giai đoạn 8: Thu hồi certificate

### Người dùng làm gì?

Người dùng vào tab `Thu hồi`, upload `certificate.json`, rồi bấm thu hồi.

### Hệ thống dùng gì?

```text
serialNumber
SQLite DB
```

### Revocation là gì?

Revocation là quá trình thu hồi certificate. Một certificate có thể từng hợp lệ, nhưng sau đó không còn được tin nữa.

Ví dụ:

```text
private key bị lộ
người ký không còn quyền ký
certificate cấp sai
```

### Vai trò trong hệ thống

Revocation giúp hệ thống từ chối certificate ngay cả khi:

```text
certificate chưa hết hạn
chữ ký CA vẫn hợp lệ
signed_package.json vẫn ghi status = valid
```

Điểm cải tiến của repo:

```text
Verify tra trạng thái từ server DB thay vì tin hoàn toàn vào status trong signed package.
```

## 12. Giai đoạn 9: Chữ ký mù

### Chữ ký mù là gì?

Chữ ký mù là cơ chế cho phép signer ký một thông điệp mà không nhìn thấy nội dung thật của thông điệp.

Ứng dụng thường gặp:

```text
bỏ phiếu điện tử
token ẩn danh
tiền điện tử ẩn danh
quy trình xác nhận nhưng cần bảo vệ quyền riêng tư
```

### Repo mô phỏng chữ ký mù như thế nào?

Hệ thống dùng mô phỏng RSA blind signature.

Các bước:

```text
1. Hash message bằng SHA-256.
2. Chọn blinding factor r.
3. Làm mù message: m' = m * r^e mod n.
4. Signer ký bản đã làm mù: s' = (m')^d mod n.
5. Requester bỏ mù: s = s' * r^-1 mod n.
6. Verify: s^e mod n == m.
```

### Thuật toán/cơ chế dùng

```text
SHA-256
RSA
modular exponentiation
modular inverse
blinding factor
```

### Ý nghĩa trong hệ thống

Phần này giúp repo chạm tới mục "chữ ký mù" trong chủ đề.

Nó cho thấy:

```text
Signer có thể ký mà không biết nội dung gốc.
Người nhận vẫn có thể xác minh chữ ký sau khi bỏ mù.
```

Lưu ý:

```text
Đây là mô phỏng học thuật, chưa phải giao thức chữ ký mù production.
```

## 13. Bảng tổng hợp cơ chế và vai trò

| Cơ chế/thuật toán | Dùng ở đâu | Làm gì | Vai trò trong hệ thống |
|---|---|---|---|
| SHA-256 | Băm file, băm message chữ ký mù | Tạo digest cố định | Kiểm tra toàn vẹn dữ liệu |
| RSA 2048-bit | Tạo key người ký, Demo CA | Sinh private/public key | Nền tảng mật mã bất đối xứng |
| RSA-PSS | Ký tài liệu, ký certificate | Tạo chữ ký số | Chứng minh người có private key đã ký |
| CA signature | Certificate | Ký thông tin danh tính + public key | Chống sửa certificate, chống giả danh public key |
| Public key verify | Verify tài liệu và certificate | Kiểm tra chữ ký | Xác minh tính hợp lệ |
| SQLite revocation lookup | Verify, revoke | Lưu trạng thái certificate | Không tin trạng thái trong JSON upload |
| Base64 | Signature output | Mã hóa bytes thành text | Giúp lưu chữ ký trong JSON |
| PEM | Key format | Lưu key dạng text | Dễ upload/download trong demo |
| RSA blind signature | Tab chữ ký mù | Ký message đã làm mù | Minh họa quyền riêng tư khi ký |

## 14. Hệ thống đã cải tiến gì so với luồng cơ bản?

Luồng cơ bản ban đầu:

```text
tạo key
hash file
ký hash
verify chữ ký
certificate chỉ là JSON tự khai
revocation dựa vào status trong JSON
```

Luồng hiện tại:

```text
1. Có tab băm file riêng.
2. Certificate được Demo CA ký.
3. Verify kiểm tra chữ ký CA.
4. Backend kiểm tra private key khớp public key trước khi ký.
5. Revocation tra từ SQLite server DB.
6. Có tab thu hồi certificate.
7. Có tab mô phỏng chữ ký mù.
8. Có tài liệu API, crypto flow, test scenarios và kịch bản thuyết trình.
```

Điểm quan trọng nhất:

```text
Repo không còn chỉ chứng minh "chữ ký khớp public key".
Repo đã bắt đầu chứng minh thêm "public key đó thuộc về certificate được CA xác nhận" và "certificate hiện có còn được server tin hay không".
```

## 15. Cải tiến hợp lý cho tương lai

### Cải tiến 1: Không gửi private key lên backend

Hiện tại người dùng upload private key lên backend để ký. Đây là điểm yếu lớn.

Hướng nâng cấp:

```text
Ký ở frontend bằng WebCrypto.
Dùng USB token/smart card.
Dùng HSM.
Dùng signing service bảo vệ khóa.
```

Ý nghĩa:

```text
Private key không rời khỏi môi trường an toàn.
Giảm nguy cơ lộ private key.
```

### Cải tiến 2: Dùng certificate chuẩn X.509

Hiện tại certificate là JSON tự định nghĩa.

Hướng nâng cấp:

```text
Dùng certificate X.509.
Parse certificate bằng thư viện chuẩn.
Lưu issuer, subject, serial, validity, public key theo chuẩn.
```

Ý nghĩa:

```text
Gần với hệ thống PKI thực tế hơn.
Dễ giải thích chain of trust.
```

### Cải tiến 3: Xây dựng chain of trust

Hiện tại chỉ có một Demo CA local.

Hướng nâng cấp:

```text
Root CA
Intermediate CA
End-user certificate
Verify toàn bộ chain
```

Ý nghĩa:

```text
Mô phỏng hệ thống CA thật.
Phân tách trust anchor và CA cấp phát.
```

### Cải tiến 4: Revocation theo CRL/OCSP

Hiện tại revocation dùng SQLite local.

Hướng nâng cấp:

```text
CRL: Certificate Revocation List.
OCSP: Online Certificate Status Protocol.
Endpoint kiểm tra trạng thái certificate riêng.
```

Ý nghĩa:

```text
Giống cách hệ thống thật kiểm tra certificate còn được tin hay không.
```

### Cải tiến 5: Timestamp Authority

Hiện tại `signedAt` chỉ là thời gian server.

Hướng nâng cấp:

```text
TSA giả lập ký timestamp.
Timestamp token.
Kiểm tra thời điểm ký với thời hạn certificate.
```

Ý nghĩa:

```text
Chứng minh tài liệu được ký tại một thời điểm đáng tin cậy.
```

### Cải tiến 6: Authentication và authorization

Hiện tại ai cũng có thể tạo key, ký, revoke.

Hướng nâng cấp:

```text
Đăng nhập.
Phân quyền user/admin.
Chỉ admin được revoke.
Chỉ chủ sở hữu được dùng certificate của mình.
```

Ý nghĩa:

```text
Ngăn người dùng trái phép thao tác với certificate hoặc dịch vụ ký.
```

### Cải tiến 7: Audit log

Hệ thống thật cần lưu lại hành động.

Hướng nâng cấp:

```text
Log tạo key/certificate.
Log ký tài liệu.
Log verify.
Log revoke.
Log user, IP, thời gian.
```

Ý nghĩa:

```text
Truy vết sự cố.
Tăng tính minh bạch và trách nhiệm.
```

### Cải tiến 8: Bảo vệ production

Hướng nâng cấp:

```text
HTTPS.
Rate limit.
Giới hạn kích thước file.
Validate file type.
Backup DB.
Không trả lỗi quá chi tiết cho attacker.
Quản lý secret bằng biến môi trường hoặc secret manager.
```

Ý nghĩa:

```text
Giúp hệ thống an toàn hơn nếu triển khai thật.
```

### Cải tiến 9: Nâng cấp chữ ký mù

Hiện tại chữ ký mù là mô phỏng giáo dục.

Hướng nâng cấp:

```text
Tách vai trò requester và signer.
Không để backend biết message gốc.
Thêm giao thức request/approve/sign.
Thêm use case bỏ phiếu ẩn danh.
```

Ý nghĩa:

```text
Biến phần chữ ký mù từ mô phỏng thuật toán thành một kịch bản ứng dụng rõ ràng.
```

## 16. Câu trả lời mẫu khi thuyết trình

```text
Mục tiêu của nhóm em là xây dựng SecureDoc, một hệ thống web demo minh họa chữ ký số cho tài liệu điện tử. Hệ thống mô phỏng đầy đủ các bước chính: băm tài liệu bằng SHA-256, tạo cặp khóa RSA 2048-bit, cấp certificate cho người ký, dùng Demo CA ký certificate, ký hash tài liệu bằng RSA-PSS, tạo signed_package.json và xác minh lại tài liệu. Khi xác minh, backend kiểm tra hash tài liệu, chữ ký CA trên certificate, trạng thái thu hồi certificate từ server DB và chữ ký tài liệu bằng public key. Ngoài luồng chính, nhóm em còn thêm các kịch bản tấn công như sửa file, sửa certificate, dùng sai private key, revoke certificate, và mô phỏng chữ ký mù RSA. Hệ thống hiện vẫn là demo học thuật; hướng phát triển tiếp là không gửi private key lên server, dùng certificate X.509, xây dựng chain of trust, CRL/OCSP, timestamp authority, authentication, authorization, audit log và bảo vệ production tốt hơn.
```
