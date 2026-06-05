import React, { useId, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  BadgeCheck,
  Ban,
  CheckCircle2,
  Download,
  EyeOff,
  FileCheck,
  FileSignature,
  Fingerprint,
  Hash,
  KeyRound,
  RotateCcw,
  ShieldCheck,
  Upload
} from "lucide-react";
import "./styles.css";

const API_BASE = "http://127.0.0.1:8000";

type Certificate = {
  serialNumber: string;
  ownerName: string;
  email: string;
  publicKeyPem: string;
  issuer: string;
  issuedAt: string;
  expiresAt: string;
  status: string;
  caSignatureAlgorithm?: string;
  caSignatureBase64?: string;
};

type SignedPackage = {
  documentName: string;
  documentHash: string;
  hashAlgorithm: string;
  signatureAlgorithm: string;
  signatureBase64: string;
  signedAt: string;
  certificate: Certificate;
};

type HashResult = {
  documentName: string;
  hashAlgorithm: string;
  documentHash: string;
};

type VerifyResult = {
  valid: boolean;
  reason: string;
  signer: { name: string; email: string; serialNumber: string } | null;
  documentHash: string;
  signedAt: string | null;
  details: Record<string, unknown>;
};

type BlindSignatureResult = {
  message: string;
  hashAlgorithm: string;
  messageHash: string;
  scheme: string;
  publicKey: { modulusHex: string; publicExponent: number };
  blindedMessageBase64: string;
  blindSignatureBase64: string;
  unblindedSignatureBase64: string;
  verificationValueHex: string;
  valid: boolean;
};

type Tab = "home" | "hash" | "keys" | "sign" | "verify" | "revoke" | "blind";

const tabs: Array<{ tab: Tab; label: string; helper: string; icon: React.ReactNode }> = [
  { tab: "home", label: "Tổng quan", helper: "Luồng demo", icon: <BadgeCheck size={18} /> },
  { tab: "hash", label: "Băm file", helper: "SHA-256", icon: <Hash size={18} /> },
  { tab: "keys", label: "Tạo khóa", helper: "RSA + CA", icon: <KeyRound size={18} /> },
  { tab: "sign", label: "Ký tài liệu", helper: "RSA-PSS", icon: <FileSignature size={18} /> },
  { tab: "verify", label: "Xác minh", helper: "Trust + revoke", icon: <FileCheck size={18} /> },
  { tab: "revoke", label: "Thu hồi", helper: "Server DB", icon: <RotateCcw size={18} /> },
  { tab: "blind", label: "Chữ ký mù", helper: "RSA blind", icon: <EyeOff size={18} /> }
];

function App() {
  const [activeTab, setActiveTab] = useState<Tab>("home");

  return (
    <div className="appShell">
      <aside className="sidebar" aria-label="Điều hướng SecureDoc">
        <div className="brand">
          <div className="brandMark" aria-hidden="true">
            <Fingerprint size={26} />
          </div>
          <div>
            <h1>SecureDoc</h1>
            <span>Demo chữ ký số</span>
          </div>
        </div>
        <nav className="navList">
          {tabs.map((item) => (
            <TabButton key={item.tab} {...item} active={activeTab} setActive={setActiveTab} />
          ))}
        </nav>
        <div className="sidebarNote">
          <ShieldCheck size={18} />
          <p>Luồng hiện có thêm Demo CA, kiểm tra chữ ký certificate và tra trạng thái thu hồi từ server.</p>
        </div>
      </aside>

      <main>
        {activeTab === "home" && <Home setActiveTab={setActiveTab} />}
        {activeTab === "hash" && <HashDocument />}
        {activeTab === "keys" && <GenerateKeys />}
        {activeTab === "sign" && <SignDocument />}
        {activeTab === "verify" && <VerifyDocument />}
        {activeTab === "revoke" && <RevokeCertificate />}
        {activeTab === "blind" && <BlindSignatureDemo />}
      </main>
    </div>
  );
}

function TabButton(props: {
  icon: React.ReactNode;
  label: string;
  helper: string;
  tab: Tab;
  active: Tab;
  setActive: (tab: Tab) => void;
}) {
  const isActive = props.active === props.tab;

  return (
    <button className={isActive ? "navButton active" : "navButton"} onClick={() => props.setActive(props.tab)} aria-current={isActive ? "page" : undefined}>
      {props.icon}
      <span>
        <strong>{props.label}</strong>
        <small>{props.helper}</small>
      </span>
    </button>
  );
}

function Home({ setActiveTab }: { setActiveTab: (tab: Tab) => void }) {
  return (
    <section className="page">
      <div className="heroPanel">
        <div className="pageHeader">
          <p className="eyebrow">Nhập môn An toàn thông tin</p>
          <h2>Demo ký số và xác minh tài liệu điện tử</h2>
          <p>
            SecureDoc minh họa chữ ký số bằng SHA-256, RSA-PSS, certificate do Demo CA ký, kiểm tra thu hồi từ server và một mô phỏng chữ ký mù RSA.
          </p>
        </div>
        <button className="primary heroAction" onClick={() => setActiveTab("keys")}>
          <KeyRound size={18} />
          Bắt đầu tạo khóa
        </button>
      </div>

      <div className="workflowGrid" aria-label="Quy trình demo">
        <StepCard number="01" title="Tạo khóa" text="Sinh RSA key pair 2048-bit và certificate JSON được Demo CA ký." />
        <StepCard number="02" title="Ký tài liệu" text="Băm file bằng SHA-256, ký digest bằng RSA-PSS và xuất signed package." />
        <StepCard number="03" title="Xác minh" text="So khớp hash, kiểm tra chữ ký CA, trạng thái thu hồi và chữ ký tài liệu." />
      </div>

      <div className="metricGrid">
        <InfoBox title="SHA-256" text="Băm file thành digest cố định để phát hiện thay đổi nội dung." />
        <InfoBox title="RSA-PSS" text="Tạo và xác minh chữ ký số bằng cặp khóa bất đối xứng." />
        <InfoBox title="Demo CA" text="Certificate không còn là JSON tự khai mà có chữ ký của CA giả lập." />
        <InfoBox title="Chữ ký mù" text="Có mô phỏng RSA blind signature để khớp phần mở rộng của chủ đề." />
      </div>
    </section>
  );
}

function StepCard({ number, title, text }: { number: string; title: string; text: string }) {
  return (
    <article className="stepCard">
      <span>{number}</span>
      <h3>{title}</h3>
      <p>{text}</p>
    </article>
  );
}

function InfoBox({ title, text }: { title: string; text: string }) {
  return (
    <article className="infoBox">
      <h3>{title}</h3>
      <p>{text}</p>
    </article>
  );
}

function HashDocument() {
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<HashResult | null>(null);
  const [error, setError] = useState("");

  async function submit() {
    if (!file) {
      setError("Vui lòng chọn tài liệu trước");
      return;
    }
    setError("");
    setResult(null);
    const body = new FormData();
    body.append("file", file);
    try {
      const response = await fetch(`${API_BASE}/api/documents/hash`, { method: "POST", body });
      setResult(await parseResponse<HashResult>(response));
    } catch (err) {
      setError(errorMessage(err, "Không thể băm tài liệu"));
    }
  }

  return (
    <section className="page taskPage">
      <PageHeader title="Băm tài liệu" description="Tính SHA-256 của file để thấy nền tảng toàn vẹn trước khi ký số." />
      <div className="surface">
        <FileInput label="Tài liệu" onFile={setFile} />
        <button className="primary" onClick={submit}>
          <Hash size={18} />
          Tính SHA-256
        </button>
        {error && <p className="errorText" role="alert">{error}</p>}
      </div>
      {result && (
        <div className="resultPanel" aria-label="Kết quả băm tài liệu">
          <div className="resultHeader">
            <CheckCircle2 size={22} />
            <div>
              <h3>Đã tính hash</h3>
              <p>{result.documentName}</p>
            </div>
          </div>
          <dl className="detailList">
            <DetailItem label="Thuật toán" value={result.hashAlgorithm} />
            <DetailItem label="Document hash" value={result.documentHash} />
          </dl>
        </div>
      )}
    </section>
  );
}

function GenerateKeys() {
  const [name, setName] = useState("Nguyễn Văn A");
  const [email, setEmail] = useState("student@example.com");
  const [result, setResult] = useState<{ privateKeyPem: string; publicKeyPem: string; certificate: Certificate } | null>(null);
  const [error, setError] = useState("");

  async function submit() {
    setError("");
    setResult(null);
    try {
      const response = await fetch(`${API_BASE}/api/keys/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, email })
      });
      setResult(await parseResponse<{ privateKeyPem: string; publicKeyPem: string; certificate: Certificate }>(response));
    } catch (err) {
      setError(errorMessage(err, "Không thể tạo khóa"));
    }
  }

  return (
    <section className="page taskPage">
      <PageHeader title="Tạo khóa" description="Tạo RSA key pair 2048-bit và certificate JSON được Demo CA ký." />
      <div className="surface">
        <div className="formGrid">
          <label>
            Họ tên
            <input value={name} onChange={(event) => setName(event.target.value)} />
          </label>
          <label>
            Email
            <input value={email} onChange={(event) => setEmail(event.target.value)} />
          </label>
        </div>
        <button className="primary" onClick={submit}>
          <KeyRound size={18} />
          Tạo key pair
        </button>
        {error && <p className="errorText" role="alert">{error}</p>}
      </div>
      {result && (
        <div className="outputStack" aria-label="Kết quả tạo khóa">
          <PemBlock title="Private key" value={result.privateKeyPem} filename="private_key.pem" />
          <PemBlock title="Public key" value={result.publicKeyPem} filename="public_key.pem" />
          <PemBlock title="Certificate do Demo CA ký" value={JSON.stringify(result.certificate, null, 2)} filename="certificate.json" />
        </div>
      )}
    </section>
  );
}

function SignDocument() {
  const [file, setFile] = useState<File | null>(null);
  const [privateKey, setPrivateKey] = useState("");
  const [certificate, setCertificate] = useState("");
  const [result, setResult] = useState<SignedPackage | null>(null);
  const [error, setError] = useState("");

  async function submit() {
    if (!file) {
      setError("Vui lòng chọn tài liệu trước");
      return;
    }
    setError("");
    setResult(null);
    const body = new FormData();
    body.append("file", file);
    body.append("privateKeyPem", privateKey);
    body.append("certificate", certificate);
    try {
      const response = await fetch(`${API_BASE}/api/sign`, { method: "POST", body });
      setResult(await parseResponse<SignedPackage>(response));
    } catch (err) {
      setError(errorMessage(err, "Không thể ký tài liệu"));
    }
  }

  return (
    <section className="page taskPage">
      <PageHeader title="Ký tài liệu" description="Upload file, private key và certificate hợp lệ để tạo signed package." />
      <div className="surface">
        <FileInput label="Tài liệu" onFile={setFile} />
        <TextOrFile label="Private key PEM" value={privateKey} setValue={setPrivateKey} />
        <TextOrFile label="Certificate JSON" value={certificate} setValue={setCertificate} />
        <button className="primary" onClick={submit}>
          <FileSignature size={18} />
          Ký tài liệu
        </button>
        {error && <p className="errorText" role="alert">{error}</p>}
      </div>
      {result && (
        <div className="resultPanel" aria-label="Kết quả ký tài liệu">
          <div className="resultHeader">
            <CheckCircle2 size={22} />
            <div>
              <h3>Đã tạo signed package</h3>
              <p>Tải file JSON này để dùng ở bước xác minh.</p>
            </div>
          </div>
          <dl className="detailList">
            <DetailItem label="Hash tài liệu" value={result.documentHash} />
            <DetailItem label="Thời điểm ký" value={result.signedAt} />
            <DetailItem label="Chữ ký tài liệu" value={`${result.signatureBase64.slice(0, 120)}...`} />
            <DetailItem label="Chữ ký CA trên certificate" value={`${result.certificate.caSignatureBase64?.slice(0, 120) ?? ""}...`} />
          </dl>
          <button className="secondary" onClick={() => downloadText("signed_package.json", JSON.stringify(result, null, 2))}>
            <Download size={18} />
            Tải signed_package.json
          </button>
        </div>
      )}
    </section>
  );
}

function VerifyDocument() {
  const [file, setFile] = useState<File | null>(null);
  const [packageText, setPackageText] = useState("");
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [error, setError] = useState("");

  async function submit() {
    if (!file) {
      setError("Vui lòng chọn tài liệu trước");
      return;
    }
    setError("");
    setResult(null);
    const body = new FormData();
    body.append("file", file);
    body.append("signedPackage", packageText);
    try {
      const response = await fetch(`${API_BASE}/api/verify`, { method: "POST", body });
      setResult(await parseResponse<VerifyResult>(response));
    } catch (err) {
      setError(errorMessage(err, "Không thể xác minh tài liệu"));
    }
  }

  return (
    <section className="page taskPage">
      <PageHeader title="Xác minh tài liệu" description="Kiểm tra hash, chữ ký CA của certificate, trạng thái thu hồi trên server và chữ ký tài liệu." />
      <div className="surface">
        <FileInput label="Tài liệu" onFile={setFile} />
        <TextOrFile label="signed_package.json" value={packageText} setValue={setPackageText} />
        <button className="primary" onClick={submit}>
          <FileCheck size={18} />
          Xác minh
        </button>
        {error && <p className="errorText" role="alert">{error}</p>}
      </div>
      {result && (
        <div className={result.valid ? "verifyBox valid" : "verifyBox invalid"} role="status" aria-live="polite">
          <div className="statusIcon" aria-hidden="true">
            {result.valid ? <BadgeCheck size={24} /> : <Ban size={24} />}
          </div>
          <div>
            <h3>{result.valid ? "Chữ ký hợp lệ" : "Chữ ký không hợp lệ"}</h3>
            <p>{result.reason}</p>
            {result.signer && <p>Người ký: {result.signer.name} ({result.signer.email})</p>}
            <pre>{JSON.stringify(result.details, null, 2)}</pre>
          </div>
        </div>
      )}
    </section>
  );
}

function RevokeCertificate() {
  const [certificateText, setCertificateText] = useState("");
  const [result, setResult] = useState<{ certificate: Certificate } | null>(null);
  const [error, setError] = useState("");

  async function submit() {
    setError("");
    setResult(null);
    try {
      const certificate = JSON.parse(certificateText);
      const response = await fetch(`${API_BASE}/api/certificates/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ certificate })
      });
      setResult(await parseResponse<{ certificate: Certificate }>(response));
    } catch (err) {
      setError(errorMessage(err, "Không thể thu hồi certificate"));
    }
  }

  return (
    <section className="page taskPage">
      <PageHeader title="Thu hồi certificate" description="Đánh dấu certificate là revoked trong server DB; bước verify sẽ tra trạng thái này theo serial number." />
      <div className="surface">
        <TextOrFile label="Certificate JSON" value={certificateText} setValue={setCertificateText} />
        <button className="primary" onClick={submit}>
          <RotateCcw size={18} />
          Thu hồi certificate
        </button>
        {error && <p className="errorText" role="alert">{error}</p>}
      </div>
      {result && (
        <div className="outputStack">
          <div className="resultPanel">
            <div className="resultHeader">
              <Ban size={22} />
              <div>
                <h3>Certificate đã bị thu hồi</h3>
                <p>Serial: {result.certificate.serialNumber}</p>
              </div>
            </div>
          </div>
          <PemBlock title="Certificate revoked" value={JSON.stringify(result.certificate, null, 2)} filename="certificate_revoked.json" />
        </div>
      )}
    </section>
  );
}

function BlindSignatureDemo() {
  const [message, setMessage] = useState("Phiếu bình chọn ẩn danh số 01");
  const [result, setResult] = useState<BlindSignatureResult | null>(null);
  const [error, setError] = useState("");

  async function submit() {
    setError("");
    setResult(null);
    try {
      const response = await fetch(`${API_BASE}/api/blind-signature/demo`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message })
      });
      setResult(await parseResponse<BlindSignatureResult>(response));
    } catch (err) {
      setError(errorMessage(err, "Không thể chạy demo chữ ký mù"));
    }
  }

  return (
    <section className="page taskPage">
      <PageHeader title="Chữ ký mù" description="Mô phỏng RSA blind signature: làm mù thông điệp, ký bản đã làm mù, bỏ mù và xác minh." />
      <div className="surface">
        <label>
          Thông điệp
          <textarea value={message} onChange={(event) => setMessage(event.target.value)} />
        </label>
        <button className="primary" onClick={submit}>
          <EyeOff size={18} />
          Chạy mô phỏng
        </button>
        {error && <p className="errorText" role="alert">{error}</p>}
      </div>
      {result && (
        <div className={result.valid ? "verifyBox valid" : "verifyBox invalid"} role="status" aria-live="polite">
          <div className="statusIcon" aria-hidden="true">
            {result.valid ? <BadgeCheck size={24} /> : <Ban size={24} />}
          </div>
          <div>
            <h3>{result.valid ? "Chữ ký mù hợp lệ" : "Chữ ký mù không hợp lệ"}</h3>
            <p>{result.scheme}</p>
            <dl className="detailList">
              <DetailItem label="Message hash" value={result.messageHash} />
              <DetailItem label="Public exponent" value={String(result.publicKey.publicExponent)} />
              <DetailItem label="Blinded message" value={`${result.blindedMessageBase64.slice(0, 140)}...`} />
              <DetailItem label="Blind signature" value={`${result.blindSignatureBase64.slice(0, 140)}...`} />
              <DetailItem label="Unblinded signature" value={`${result.unblindedSignatureBase64.slice(0, 140)}...`} />
            </dl>
          </div>
        </div>
      )}
    </section>
  );
}

function PageHeader({ title, description }: { title: string; description: string }) {
  return (
    <div className="pageHeader compact">
      <h2>{title}</h2>
      <p>{description}</p>
    </div>
  );
}

function DetailItem({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function FileInput({ label, onFile }: { label: string; onFile: (file: File | null) => void }) {
  return (
    <label className="fileRow">
      <span>{label}</span>
      <span className="fileControl">
        <Upload size={18} />
        <input type="file" onChange={(event) => onFile(event.target.files?.[0] ?? null)} />
      </span>
    </label>
  );
}

function TextOrFile({ label, value, setValue }: { label: string; value: string; setValue: (value: string) => void }) {
  const id = useId();

  async function readFile(file: File | null) {
    if (file) setValue(await file.text());
  }

  return (
    <label htmlFor={id} className="textFileField">
      <span>{label}</span>
      <input type="file" onChange={(event) => readFile(event.target.files?.[0] ?? null)} />
      <textarea id={id} value={value} onChange={(event) => setValue(event.target.value)} spellCheck={false} />
    </label>
  );
}

function PemBlock({ title, value, filename }: { title: string; value: string; filename: string }) {
  return (
    <article className="pemBlock">
      <header>
        <h3>{title}</h3>
        <button className="iconButton" onClick={() => downloadText(filename, value)} title={`Tải ${filename}`} aria-label={`Tải ${filename}`}>
          <Download size={18} />
        </button>
      </header>
      <pre>{value}</pre>
    </article>
  );
}

async function parseResponse<T>(response: Response): Promise<T> {
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = data && typeof data.detail === "string" ? data.detail : "Yêu cầu thất bại";
    throw new Error(detail);
  }
  return data as T;
}

function errorMessage(error: unknown, fallback: string) {
  return error instanceof Error ? error.message : fallback;
}

function downloadText(filename: string, content: string) {
  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

createRoot(document.getElementById("root")!).render(<App />);
