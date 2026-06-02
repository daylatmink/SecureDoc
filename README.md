# SecureDoc

SecureDoc la web app demo cho mon Nhap mon An toan thong tin, chu de "Chu ky so". Project minh hoa cach bam tai lieu bang SHA-256, ky digest bang RSA-PSS/private key, xac minh bang public key, va dung certificate JSON gia lap de lien ket public key voi danh tinh nguoi ky.

Day la ban MVP chay local, khong phai he thong ky so san xuat.

## Kien truc

```text
SecureDoc/
  backend/    FastAPI, cryptography, SQLite, SQLAlchemy
  frontend/   React + Vite + TypeScript
  docs/       Giai thich crypto flow, API va kich ban kiem thu
```

## Chay backend

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Backend mac dinh chay tai `http://127.0.0.1:8000`. Swagger docs: `http://127.0.0.1:8000/docs`.

## Chay frontend

```powershell
cd frontend
npm install
npm run dev
```

Frontend mac dinh chay tai `http://127.0.0.1:5173`.

## Luong ky

1. Nguoi dung tao key pair voi ten va email.
2. Backend sinh RSA 2048-bit private/public key.
3. Backend tao certificate JSON gia lap gom serial number, owner, email, public key, issuer, ngay cap, ngay het han va status.
4. Nguoi dung upload file, private key PEM va certificate JSON.
5. Backend tinh SHA-256 cua file.
6. Backend ky digest bang RSA-PSS + SHA-256.
7. Backend tra ve `signed_package.json` gom hash, signature Base64, thoi diem ky va certificate.

## Luong xac minh

1. Nguoi dung upload file can verify va `signed_package.json`.
2. Backend tinh lai SHA-256 cua file.
3. Backend so sanh hash moi voi `documentHash`.
4. Backend kiem tra certificate chua het han va `status` la `valid`.
5. Backend verify signature bang public key trong certificate.
6. Ket qua tra ve `valid`, `reason`, signer info, hash va verification details.

## Kich ban kiem thu

Xem kịch bản kiểm thử thủ công trong `docs/test-scenarios.md`.

## Gioi han bao mat cua demo

- Private key duoc paste/upload tu nguoi dung de demo. He thong that khong nen luu private key plaintext va khong nen gui private key len server neu khong co mo hinh bao ve phu hop.
- Certificate chi la JSON gia lap, chua co CA thuc, chain of trust, OCSP/CRL that, hay co che chong sua certificate.
- Revocation trong demo chu yeu dua vao truong `status` cua certificate.
- Khong co authentication, authorization, audit log day du, rate limit hay hardening production.
- Khong duoc thay RSA-PSS/SHA-256 bang MD5, SHA-1 hoac thuat toan yeu.

## File chinh

- `backend/app/main.py`: cac API FastAPI.
- `backend/app/crypto_utils.py`: SHA-256, RSA key generation, RSA-PSS sign/verify.
- `backend/app/models.py`: SQLAlchemy certificate record.
- `frontend/src/main.tsx`: UI React cho cac tab demo.
- `docs/crypto-flow.md`: giai thich crypto flow.
- `docs/api.md`: mo ta API va payload mau.
- `docs/test-scenarios.md`: kich ban kiem thu thu cong.
