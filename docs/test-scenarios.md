# Kịch bản kiểm thử SecureDoc

Tài liệu này dùng để kiểm thử thủ công qua giao diện web hoặc Swagger docs.

## Chuẩn bị

- Backend đang chạy tại `http://127.0.0.1:8000`.
- Frontend đang chạy tại `http://127.0.0.1:5173`.
- Có một file mẫu để ký, ví dụ `demo.txt`.

Nội dung gợi ý cho `demo.txt`:

```text
Tai lieu mau dung de kiem thu chu ky so SecureDoc.
```

## Kịch bản 1: Băm tài liệu

1. Mở tab `Băm file`.
2. Upload `demo.txt`.
3. Bấm `Tính SHA-256`.

Kết quả mong đợi:

- Giao diện hiển thị `hashAlgorithm` là `SHA-256`.
- `documentHash` là chuỗi hex đại diện cho nội dung file.

## Kịch bản 2: Tạo khóa và certificate

1. Mở tab `Tạo khóa`.
2. Nhập họ tên và email người ký.
3. Bấm `Tạo key pair`.
4. Tải về hoặc sao chép `private_key.pem`, `public_key.pem` và `certificate.json`.

Kết quả mong đợi:

- Backend sinh RSA key pair 2048-bit.
- Certificate có `status` là `valid`.
- Certificate chứa public key và thông tin người ký.
- Certificate có `caSignatureAlgorithm` và `caSignatureBase64`, chứng minh certificate được Demo CA ký.

## Kịch bản 3: Ký tài liệu thành công

1. Mở tab `Ký tài liệu`.
2. Upload file gốc.
3. Upload hoặc dán `private_key.pem`.
4. Upload hoặc dán `certificate.json`.
5. Bấm `Ký tài liệu`.
6. Tải `signed_package.json`.

Kết quả mong đợi:

- Giao diện hiển thị hash tài liệu, thời điểm ký, chữ ký tài liệu và chữ ký CA trên certificate.
- `signed_package.json` chứa `documentHash`, `signatureBase64`, `signatureAlgorithm` là `RSA-PSS` và certificate đã được CA ký.

## Kịch bản 4: Xác minh tài liệu hợp lệ

1. Mở tab `Xác minh tài liệu`.
2. Upload đúng file gốc đã ký.
3. Upload hoặc dán đúng `signed_package.json`.
4. Bấm `Xác minh`.

Kết quả mong đợi:

- `valid` là `true`.
- Lý do trả về là `signature valid`.
- `details.hashMatches` là `true`.
- `details.caSignatureValid` là `true`.
- `details.certificateStatusFromServer` là `valid`.
- `details.signatureValid` là `true`.

## Kịch bản 5: File bị sửa sau khi ký

1. Mở file gốc đã ký và sửa một ký tự bất kỳ.
2. Upload file đã sửa trong tab `Xác minh tài liệu`.
3. Dùng lại `signed_package.json` cũ.
4. Bấm `Xác minh`.

Kết quả mong đợi:

- `valid` là `false`.
- Lý do trả về là `document modified`.
- `details.hashMatches` là `false`.

## Kịch bản 6: Certificate bị sửa danh tính

1. Mở `signed_package.json`.
2. Sửa `certificate.ownerName` hoặc `certificate.email`.
3. Upload file gốc và signed package đã sửa.
4. Bấm `Xác minh`.

Kết quả mong đợi:

- `valid` là `false`.
- Lý do trả về là `certificate not issued by demo CA`.
- `details.caSignatureValid` là `false`.

## Kịch bản 7: Certificate dùng sai public key

1. Tạo thêm một cặp khóa khác.
2. Mở `signed_package.json` của tài liệu đã ký ban đầu.
3. Thay `certificate.publicKeyPem` bằng public key của cặp khóa mới.
4. Upload file gốc và signed package đã sửa.
5. Bấm `Xác minh`.

Kết quả mong đợi:

- `valid` là `false`.
- Lý do trả về là `certificate not issued by demo CA` nếu public key bị sửa nhưng chữ ký CA không đổi.

## Kịch bản 8: Certificate hết hạn

1. Mở `signed_package.json`.
2. Sửa `certificate.expiresAt` thành một thời điểm trong quá khứ, ví dụ `2020-01-01T00:00:00+00:00`.
3. Upload file gốc và signed package đã sửa.
4. Bấm `Xác minh`.

Kết quả mong đợi:

- `valid` là `false`.
- Nếu chỉ sửa `expiresAt`, chữ ký CA cũng hỏng, nên lý do là `certificate not issued by demo CA`.
- Với certificate hết hạn được CA ký thật, lý do sẽ là `certificate expired`.

## Kịch bản 9: Certificate bị thu hồi

1. Mở tab `Thu hồi`.
2. Upload hoặc dán `certificate.json`.
3. Bấm `Thu hồi certificate`.
4. Mở lại tab `Xác minh tài liệu`.
5. Upload file gốc và `signed_package.json` đã tạo trước đó.
6. Bấm `Xác minh`.

Kết quả mong đợi:

- `valid` là `false`.
- Lý do trả về là `certificate revoked`.
- `details.certificateStatusInPackage` vẫn có thể là `valid`.
- `details.certificateStatusFromServer` là `revoked`.

Điểm này chứng minh hệ thống không chỉ tin vào trường `status` trong file JSON người dùng upload.

## Kịch bản 10: Chữ ký mù

1. Mở tab `Chữ ký mù`.
2. Nhập một thông điệp.
3. Bấm `Chạy mô phỏng`.

Kết quả mong đợi:

- Giao diện hiển thị message hash.
- Có blinded message, blind signature và unblinded signature.
- Kết quả `valid` là `true`.

## Kịch bản 11: Sai private key khi ký

1. Tạo cặp khóa A và certificate A.
2. Tạo thêm cặp khóa B.
3. Mở tab `Ký tài liệu`.
4. Upload file gốc.
5. Dùng private key B nhưng certificate A.
6. Bấm `Ký tài liệu`.

Kết quả mong đợi:

- Backend từ chối với lỗi `Private key does not match certificate public key`.
