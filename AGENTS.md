# SecureDoc Agents Guide

## Mo ta project

SecureDoc la monorepo demo chu ky so va xac minh tai lieu dien tu. Backend dung FastAPI, Python `cryptography`, SQLite va SQLAlchemy. Frontend dung React + Vite + TypeScript.

## Setup backend

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Setup frontend

```powershell
cd frontend
npm install
```

## Lenh chay dev

```powershell
cd backend
uvicorn app.main:app --reload
```

```powershell
cd frontend
npm run dev
```

## Lenh test

Hien chua co test tu dong. Kiem tra thu cong qua Swagger docs hoac frontend:

1. Generate keys.
2. Sign document.
3. Verify document goc.
4. Sua document va verify lai.
5. Revoke certificate hoac sua `status` thanh `revoked` va verify lai.

## Quy uoc code

- Giu backend tach ro API, schema, database va crypto helper.
- Xu ly loi ro rang bang `HTTPException` hoac response `reason`.
- Frontend uu tien UI don gian, de demo tren lop, khong them flow phuc tap ngoai MVP.
- Khong them authentication neu khong co yeu cau rieng.

## Quy tac bao mat crypto

- Khong tu implement RSA thu cong.
- Phai dung thu vien `cryptography` cho RSA key generation, sign va verify.
- Khong dung MD5 hoac SHA-1.
- Khong thay RSA-PSS/SHA-256 bang thuat toan yeu.
- Khong ky truc tiep toan bo file tho. File phai duoc bam SHA-256 truoc, sau do ky digest.
- Private key plaintext chi chap nhan trong demo. He thong that khong nen luu private key plaintext.

