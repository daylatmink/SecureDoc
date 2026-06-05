# Crypto Flow

Tài liệu này giải thích các thành phần crypto của SecureDoc bằng tiếng Việt đơn giản.

## SHA-256 dùng để làm gì?

SHA-256 là hàm băm mật mã học. Nó nhận dữ liệu đầu vào như file TXT, PDF hoặc JSON và tạo ra một giá trị băm có độ dài cố định. Nếu nội dung file thay đổi chỉ một ký tự, giá trị SHA-256 gần như chắc chắn sẽ thay đổi hoàn toàn.

Trong SecureDoc, backend không ký trực tiếp toàn bộ file. Backend tính SHA-256 của file trước, sau đó ký giá trị băm này.

## RSA-PSS dùng để làm gì?

RSA-PSS là cơ chế chữ ký số dựa trên RSA. Người ký dùng private key để tạo chữ ký trên digest SHA-256. Người xác minh dùng public key từ certificate để kiểm tra chữ ký.

RSA-PSS được ưu tiên hơn padding RSA cũ vì có thiết kế an toàn hơn cho chữ ký số hiện đại.

## Private key và public key khác nhau thế nào?

Private key là khóa bí mật. Chỉ người ký được giữ private key và dùng nó để tạo chữ ký. Nếu private key bị lộ, người khác có thể giả mạo chữ ký.

Public key là khóa công khai. Nó có thể chia sẻ cho người xác minh. Public key không dùng để tạo chữ ký, mà dùng để kiểm tra chữ ký được tạo bằng private key tương ứng.

## Demo CA giải quyết vấn đề gì?

Nếu certificate chỉ là JSON tự khai, người dùng có thể sửa `ownerName`, `email`, `expiresAt` hoặc `publicKeyPem`. Vì vậy bản mới thêm `SecureDoc Demo CA`.

Khi tạo certificate, backend ký các trường quan trọng bằng private key của Demo CA:

- `serialNumber`
- `ownerName`
- `email`
- `publicKeyPem`
- `issuer`
- `issuedAt`
- `expiresAt`

Certificate sẽ có thêm:

- `caSignatureAlgorithm`: thuật toán chữ ký CA.
- `caSignatureBase64`: chữ ký của Demo CA trên certificate.

Khi verify, backend kiểm tra chữ ký CA trước khi tin thông tin danh tính và public key trong certificate.

## Revocation được kiểm tra như thế nào?

Trạng thái thu hồi không nên chỉ tin vào trường `status` trong signed package, vì file JSON có thể bị sửa. SecureDoc lưu certificate trong SQLite theo `serialNumber`.

Khi verify, backend tra DB để lấy `certificateStatusFromServer`. Nếu DB báo `revoked`, chữ ký bị từ chối ngay cả khi signed package vẫn ghi `status: valid`.

## Vì sao sửa tài liệu thì verify fail?

Khi ký, SecureDoc lưu `documentHash` trong signed package. Khi verify, backend tính lại SHA-256 của file upload. Nếu file đã bị sửa, hash mới sẽ khác hash ban đầu.

Vì chữ ký được tạo trên hash ban đầu, hash mới không khớp sẽ bị reject với reason `document modified`.

## Chữ ký mù trong demo

SecureDoc có endpoint và tab mô phỏng RSA blind signature:

1. Requester băm thông điệp.
2. Requester chọn blinding factor `r`.
3. Requester tạo bản đã làm mù: `m' = m * r^e mod n`.
4. Signer ký bản đã làm mù: `s' = (m')^d mod n`.
5. Requester bỏ mù: `s = s' * r^-1 mod n`.
6. Verify: `s^e mod n == m`.

Phần này dùng để minh họa nguyên lý chữ ký mù, chưa phải giao thức production.
