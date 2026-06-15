# SecureDoc

SecureDoc là web app demo cho môn Nhập môn An toàn thông tin, chủ đề **chữ ký số**. Project minh họa cách băm tài liệu bằng SHA-256/SHA-384/SHA-512/SHA3-256, ký digest bằng RSA-PSS/private key, xác minh bằng public key, dùng certificate do Demo CA ký để liên kết public key với danh tính người ký, và mô phỏng chữ ký mù RSA.

Đây là bản demo chạy local cho mục tiêu học thuật, chưa phải hệ thống ký số production.

## Kiến trúc

```text
SecureDoc/
  backend/    FastAPI, cryptography, SQLite, SQLAlchemy
  frontend/   React + Vite + TypeScript
  docs/       Giải thích crypto flow, API và kịch bản kiểm thử
```

## Chạy backend

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Backend mặc định chạy tại `http://127.0.0.1:8000`. Swagger docs: `http://127.0.0.1:8000/docs`.

## Chạy frontend

```powershell
cd frontend
npm install
npm run dev
```

Frontend mặc định chạy tại `http://127.0.0.1:5173`.

## Repo đã demo được gì

- Tính hash cho file upload bằng SHA-256, SHA-384, SHA-512 hoặc SHA3-256.
- Sinh RSA key pair 2048-bit cho người ký.
- Tạo certificate JSON có chữ ký của `SecureDoc Demo CA`.
- Ký tài liệu bằng RSA-PSS trên hash SHA-256.
- Xuất `signed_package.json` gồm hash, chữ ký tài liệu, thời điểm ký và certificate.
- Xác minh tài liệu bằng checklist từng bước: kiểm tra thuật toán, hash, chữ ký CA của certificate, trạng thái thu hồi trong server DB, thời hạn certificate và chữ ký tài liệu.
- Thu hồi certificate theo `serialNumber`.
- Mô phỏng chữ ký mù RSA cho phần mở rộng lý thuyết.

## Luồng ký

1. Người dùng tạo key pair với tên và email.
2. Backend sinh RSA 2048-bit private/public key.
3. Backend tạo certificate JSON và ký các trường định danh bằng private key của Demo CA.
4. Người dùng upload file, private key PEM và certificate JSON.
5. Backend kiểm tra certificate có chữ ký hợp lệ của Demo CA và chưa bị thu hồi.
6. Backend tính hash của file theo thuật toán người dùng chọn.
7. Backend ký digest bằng RSA-PSS + SHA-256.
8. Backend trả về `signed_package.json`.

## Luồng xác minh

1. Người dùng upload file cần verify và `signed_package.json`.
2. Backend tính lại hash của file theo thuật toán ghi trong signed package.
3. Backend so sánh hash mới với `documentHash`.
4. Backend kiểm tra chữ ký CA trên certificate.
5. Backend tra trạng thái certificate từ SQLite theo `serialNumber`.
6. Backend kiểm tra certificate chưa hết hạn.
7. Backend verify chữ ký tài liệu bằng public key trong certificate.

## Kịch bản kiểm thử

Xem kịch bản kiểm thử thủ công trong `docs/test-scenarios.md`.

## Giới hạn bảo mật của demo

- Demo CA vẫn chạy local, private key CA được tạo trong thư mục backend để phục vụ demo.
- Private key người ký vẫn được paste/upload lên backend để ký; hệ thống thật nên ký ở client, USB token, smart card, HSM hoặc dịch vụ ký số bảo vệ khóa.
- Chưa có CA thật, chain of trust thật, OCSP/CRL thật hay quy trình định danh người ký.
- Chưa có authentication, authorization, audit log đầy đủ, rate limit, HTTPS bắt buộc hay hardening production.
- Demo chữ ký mù dùng mô phỏng RSA giáo dục, chưa phải giao thức production.

## File chính

- `backend/app/main.py`: các API FastAPI.
- `backend/app/crypto_utils.py`: SHA-256, RSA key generation, RSA-PSS sign/verify, Demo CA, chữ ký mù.
- `backend/app/models.py`: SQLAlchemy certificate record.
- `frontend/src/main.tsx`: UI React cho các tab demo.
- `docs/crypto-flow.md`: giải thích crypto flow.
- `docs/api.md`: mô tả API và payload mẫu.
- `docs/test-scenarios.md`: kịch bản kiểm thử thủ công.
