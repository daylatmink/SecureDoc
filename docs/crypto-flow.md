# Crypto Flow

Tai lieu nay giai thich cac thanh phan crypto cua SecureDoc bang tieng Viet don gian.

## SHA-256 dung de lam gi?

SHA-256 la ham bam mat ma hoc. No nhan du lieu dau vao nhu file TXT, PDF hoac JSON va tao ra mot gia tri bam co do dai co dinh. Neu noi dung file thay doi chi mot ky tu, gia tri SHA-256 gan nhu chac chan se thay doi hoan toan.

Trong SecureDoc, backend khong ky truc tiep toan bo file. Backend tinh SHA-256 cua file truoc, sau do ky gia tri bam nay.

## RSA-PSS dung de lam gi?

RSA-PSS la co che chu ky so dua tren RSA. Nguoi ky dung private key de tao chu ky tren digest SHA-256. Nguoi xac minh dung public key tu certificate de kiem tra chu ky.

RSA-PSS duoc uu tien hon cac padding RSA cu vi co thiet ke an toan hon cho chu ky so hien dai.

## Private key va public key khac nhau the nao?

Private key la khoa bi mat. Chi nguoi ky duoc giu private key va dung no de tao chu ky. Neu private key bi lo, nguoi khac co the gia mao chu ky.

Public key la khoa cong khai. No co the chia se cho nguoi xac minh. Public key khong dung de tao chu ky, ma dung de kiem tra chu ky duoc tao bang private key tuong ung.

## Certificate gia lap la gi?

Certificate trong SecureDoc la mot JSON demo gom:

- `serialNumber`: ma so certificate.
- `ownerName` va `email`: danh tinh nguoi ky.
- `publicKeyPem`: public key cua nguoi ky.
- `issuer`: don vi cap gia lap, mac dinh `SecureDoc Demo CA`.
- `issuedAt` va `expiresAt`: ngay cap va ngay het han.
- `status`: `valid` hoac `revoked`.

Trong he thong that, certificate can duoc CA ky va co chain of trust. Ban demo nay chi minh hoa y tuong lien ket public key voi danh tinh.

## Vi sao sua tai lieu thi verify fail?

Khi ky, SecureDoc luu `documentHash` trong signed package. Khi verify, backend tinh lai SHA-256 cua file upload. Neu file da bi sua, hash moi se khac hash ban dau.

Vi chu ky duoc tao tren hash ban dau, hash moi khong khop se bi reject voi reason `document modified`. Ngay ca khi bo qua buoc so sanh hash, chu ky RSA-PSS cung chi hop le voi digest da ky ban dau.

