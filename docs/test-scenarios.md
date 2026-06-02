# Kịch bản kiểm thử SecureDoc

Tài liệu này thay cho trang kịch bản tấn công trong frontend. Dùng các bước dưới đây để kiểm thử thủ công qua giao diện web hoặc Swagger docs.

## Chuẩn bị

- Backend đang chạy tại `http://127.0.0.1:8000`.
- Frontend đang chạy tại `http://127.0.0.1:5173`.
- Có một file mẫu để ký, ví dụ `demo.txt`.

Nội dung gợi ý cho `demo.txt`:

```text
Tai lieu mau dung de kiem thu chu ky so SecureDoc.
```

## Kịch bản 1: Tạo khóa và certificate

1. Mở tab `Tạo khóa`.
2. Nhập họ tên và email người ký.
3. Bấm `Tạo key pair`.
4. Tải về hoặc sao chép `private_key.pem`, `public_key.pem` và `certificate.json`.

Kết quả mong đợi:

- Backend sinh RSA key pair 2048-bit.
- Certificate có `status` là `valid`.
- Certificate chứa public key và thông tin người ký.

## Kịch bản 2: Ký tài liệu thành công

1. Mở tab `Ký tài liệu`.
2. Upload file gốc.
3. Upload hoặc dán `private_key.pem`.
4. Upload hoặc dán `certificate.json`.
5. Bấm `Ký tài liệu`.
6. Tải `signed_package.json`.

Kết quả mong đợi:

- Giao diện hiển thị hash tài liệu, thời điểm ký và một phần chữ ký.
- `signed_package.json` chứa `documentHash`, `signatureBase64`, `signatureAlgorithm` là `RSA-PSS` và certificate.

## Kịch bản 3: Xác minh tài liệu hợp lệ

1. Mở tab `Xác minh tài liệu`.
2. Upload đúng file gốc đã ký.
3. Upload hoặc dán đúng `signed_package.json`.
4. Bấm `Xác minh`.

Kết quả mong đợi:

- `valid` là `true`.
- Lý do trả về là `signature valid`.
- `details.hashMatches` là `true`.
- `details.signatureValid` là `true`.

## Kịch bản 4: File bị sửa sau khi ký

1. Mở file gốc đã ký và sửa một ký tự bất kỳ.
2. Upload file đã sửa trong tab `Xác minh tài liệu`.
3. Dùng lại `signed_package.json` cũ.
4. Bấm `Xác minh`.

Kết quả mong đợi:

- `valid` là `false`.
- Lý do trả về là `document modified`.
- `details.hashMatches` là `false`.

## Kịch bản 5: Certificate dùng sai public key

1. Tạo thêm một cặp khóa khác.
2. Mở `signed_package.json` của tài liệu đã ký ban đầu.
3. Thay `certificate.publicKeyPem` bằng public key của cặp khóa mới.
4. Upload file gốc và signed package đã sửa.
5. Bấm `Xác minh`.

Kết quả mong đợi:

- `valid` là `false`.
- Lý do trả về là `invalid signature or public key mismatch`.

## Kịch bản 6: Certificate hết hạn

1. Mở `signed_package.json`.
2. Sửa `certificate.expiresAt` thành một thời điểm trong quá khứ, ví dụ `2020-01-01T00:00:00+00:00`.
3. Upload file gốc và signed package đã sửa.
4. Bấm `Xác minh`.

Kết quả mong đợi:

- `valid` là `false`.
- Lý do trả về là `certificate expired`.

## Kịch bản 7: Certificate bị thu hồi

Cách 1: sửa trực tiếp signed package.

1. Mở `signed_package.json`.
2. Sửa `certificate.status` từ `valid` thành `revoked`.
3. Upload file gốc và signed package đã sửa.
4. Bấm `Xác minh`.

Cách 2: dùng API `POST /api/certificates/revoke`.

1. Gửi certificate hiện tại vào endpoint revoke.
2. Lấy certificate trả về có `status` là `revoked`.
3. Thay certificate trong signed package bằng certificate đã revoke.
4. Xác minh lại file gốc.

Kết quả mong đợi:

- `valid` là `false`.
- Lý do trả về là `certificate revoked`.
