import React, { useId, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  BadgeCheck,
  Ban,
  CheckCircle2,
  Download,
  FileCheck,
  FileSignature,
  Fingerprint,
  KeyRound,
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

type VerifyResult = {
  valid: boolean;
  reason: string;
  signer: { name: string; email: string; serialNumber: string } | null;
  documentHash: string;
  signedAt: string | null;
  details: Record<string, unknown>;
};

type Tab = "home" | "keys" | "sign" | "verify";

const tabs: Array<{ tab: Tab; label: string; helper: string; icon: React.ReactNode }> = [
  { tab: "home", label: "Tổng quan", helper: "Quy trình demo", icon: <BadgeCheck size={18} /> },
  { tab: "keys", label: "Tạo khóa", helper: "RSA + certificate", icon: <KeyRound size={18} /> },
  { tab: "sign", label: "Ký tài liệu", helper: "Hash + signature", icon: <FileSignature size={18} /> },
  { tab: "verify", label: "Xác minh", helper: "Kiểm tra chữ ký", icon: <FileCheck size={18} /> }
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
          <p>SHA-256 trước, RSA-PSS sau. Private key plaintext chỉ dùng cho demo.</p>
        </div>
      </aside>

      <main>
        {activeTab === "home" && <Home setActiveTab={setActiveTab} />}
        {activeTab === "keys" && <GenerateKeys />}
        {activeTab === "sign" && <SignDocument />}
        {activeTab === "verify" && <VerifyDocument />}
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
            SecureDoc minh họa luồng ký số bằng SHA-256, RSA-PSS, cặp khóa công khai/bí mật và certificate giả lập.
          </p>
        </div>
        <button className="primary heroAction" onClick={() => setActiveTab("keys")}>
          <KeyRound size={18} />
          Bắt đầu tạo khóa
        </button>
      </div>

      <div className="workflowGrid" aria-label="Quy trình demo">
        <StepCard number="01" title="Tạo khóa" text="Sinh RSA key pair 2048-bit và certificate JSON cho người ký." />
        <StepCard number="02" title="Ký tài liệu" text="Băm file bằng SHA-256, sau đó ký digest bằng RSA-PSS." />
        <StepCard number="03" title="Xác minh" text="So khớp hash, certificate, trạng thái và chữ ký để kết luận hợp lệ." />
      </div>

      <div className="metricGrid">
        <InfoBox title="SHA-256" text="Băm file thành digest hex có độ dài cố định." />
        <InfoBox title="RSA-PSS" text="Ký digest bằng private key và xác minh bằng public key." />
        <InfoBox title="Certificate" text="Liên kết public key với danh tính người ký trong demo." />
        <InfoBox title="Kiểm thử" text="Sửa file, dùng sai key, hết hạn hoặc thu hồi certificate." />
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

function GenerateKeys() {
  const [name, setName] = useState("Nguyễn Văn A");
  const [email, setEmail] = useState("student@example.com");
  const [result, setResult] = useState<{ privateKeyPem: string; publicKeyPem: string; certificate: Certificate } | null>(null);
  const [error, setError] = useState("");

  async function submit() {
    setError("");
    const response = await fetch(`${API_BASE}/api/keys/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, email })
    });
    const data = await response.json();
    if (!response.ok) {
      setError(data.detail ?? "Không thể tạo khóa");
      return;
    }
    setResult(data);
  }

  return (
    <section className="page taskPage">
      <PageHeader title="Tạo khóa" description="Tạo RSA key pair 2048-bit và certificate JSON giả lập." />
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
          <PemBlock title="Certificate" value={JSON.stringify(result.certificate, null, 2)} filename="certificate.json" />
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
    const body = new FormData();
    body.append("file", file);
    body.append("privateKeyPem", privateKey);
    body.append("certificate", certificate);
    const response = await fetch(`${API_BASE}/api/sign`, { method: "POST", body });
    const data = await response.json();
    if (!response.ok) {
      setError(data.detail ?? "Không thể ký tài liệu");
      return;
    }
    setResult(data);
  }

  return (
    <section className="page taskPage">
      <PageHeader title="Ký tài liệu" description="Upload file, nhập private key và certificate để tạo signed package." />
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
            <div>
              <dt>Hash tài liệu</dt>
              <dd>{result.documentHash}</dd>
            </div>
            <div>
              <dt>Thời điểm ký</dt>
              <dd>{result.signedAt}</dd>
            </div>
            <div>
              <dt>Chữ ký</dt>
              <dd>{result.signatureBase64.slice(0, 96)}...</dd>
            </div>
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
    const body = new FormData();
    body.append("file", file);
    body.append("signedPackage", packageText);
    const response = await fetch(`${API_BASE}/api/verify`, { method: "POST", body });
    const data = await response.json();
    if (!response.ok) {
      setError(data.detail ?? "Không thể xác minh tài liệu");
      return;
    }
    setResult(data);
  }

  return (
    <section className="page taskPage">
      <PageHeader title="Xác minh tài liệu" description="Upload file gốc và signed package để kiểm tra hash, certificate và chữ ký." />
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
            <pre>{JSON.stringify(result.details, null, 2)}</pre>
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
