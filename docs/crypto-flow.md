# Crypto Flow

Tài liệu này giải thích các thành phần crypto của SecureDoc bằng tiếng Việt đơn giản.

## SHA-256 dùng để làm gì?

SHA-256 là hàm băm mật mã học. Nó nhận dữ liệu đầu vào như file TXT, PDF hoặc JSON và tạo ra một giá trị băm có độ dài cố định. Nếu nội dung file thay đổi chỉ một ký tự, giá trị SHA-256 gần như chắc chắn sẽ thay đổi hoàn toàn.

Trong SecureDoc, backend không ký trực tiếp toàn bộ file. Backend tính hash của file trước, sau đó ký giá trị băm này.

SHA-256 vẫn là lựa chọn phổ biến và hợp lệ trong nhiều hệ thống chữ ký số hiện nay. SecureDoc giữ SHA-256 làm mặc định vì nó dễ giải thích, tương thích tốt và đủ thực tế cho demo. Để repo mang tính ứng dụng hiện đại hơn, backend/frontend cũng hỗ trợ thêm:

- `SHA-384`: profile SHA-2 mạnh hơn, thường dùng khi muốn mức an toàn cao hơn.
- `SHA-512`: digest dài hơn, phù hợp để minh họa profile bảo mật cao.
- `SHA3-256`: thuộc họ SHA-3, dùng cấu trúc sponge/Keccak khác SHA-2.

Khi ký, signed package lưu `hashAlgorithm`. Khi xác minh, backend dùng chính thuật toán này để băm lại file, rồi mới verify chữ ký RSA-PSS.

## RSA-PSS dùng để làm gì?

RSA-PSS là cơ chế chữ ký số dựa trên RSA. Người ký dùng private key để tạo chữ ký trên digest của tài liệu. Người xác minh dùng public key từ certificate để kiểm tra chữ ký.

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

Khi ký, SecureDoc lưu `documentHash` và `hashAlgorithm` trong signed package. Khi verify, backend tính lại hash của file upload bằng đúng thuật toán đó. Nếu file đã bị sửa, hash mới sẽ khác hash ban đầu.

Vì chữ ký được tạo trên hash ban đầu, hash mới không khớp sẽ bị reject với reason `document modified`.

Kết quả verify có thêm `verificationSteps` để mô phỏng rõ quy trình xác minh:

1. Kiểm tra thuật toán được khai báo.
2. Tính lại hash của tài liệu.
3. Kiểm tra chữ ký CA trên certificate.
4. Tra certificate trong server database.
5. So khớp certificate với bản ghi server.
6. Kiểm tra thời hạn certificate.
7. Kiểm tra trạng thái thu hồi.
8. Verify chữ ký tài liệu bằng public key.

## Chữ ký mù trong demo

SecureDoc có endpoint và tab mô phỏng RSA blind signature:

1. Requester băm thông điệp.
2. Requester chọn blinding factor `r`.
3. Requester tạo bản đã làm mù: `m' = m * r^e mod n`.
4. Signer ký bản đã làm mù: `s' = (m')^d mod n`.
5. Requester bỏ mù: `s = s' * r^-1 mod n`.
6. Verify: `s^e mod n == m`.

Phần này dùng để minh họa nguyên lý chữ ký mù, chưa phải giao thức production.
