import React, { useState } from "react";
import { createRoot } from "react-dom/client";
import {
  BadgeCheck,
  Ban,
  Download,
  FileCheck,
  FileSignature,
  Fingerprint,
  KeyRound
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

function App() {
  const [activeTab, setActiveTab] = useState<Tab>("home");

  return (
    <div className="appShell">
      <aside className="sidebar">
        <div className="brand">
          <Fingerprint size={28} />
          <div>
            <h1>SecureDoc</h1>
            <span>Demo chữ ký số</span>
          </div>
        </div>
        <nav>
          <TabButton icon={<BadgeCheck size={18} />} label="Trang chủ" tab="home" active={activeTab} setActive={setActiveTab} />
          <TabButton icon={<KeyRound size={18} />} label="Tạo khóa" tab="keys" active={activeTab} setActive={setActiveTab} />
          <TabButton icon={<FileSignature size={18} />} label="Ký tài liệu" tab="sign" active={activeTab} setActive={setActiveTab} />
          <TabButton icon={<FileCheck size={18} />} label="Xác minh tài liệu" tab="verify" active={activeTab} setActive={setActiveTab} />
        </nav>
      </aside>

      <main>
        {activeTab === "home" && <Home />}
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
  tab: Tab;
  active: Tab;
  setActive: (tab: Tab) => void;
}) {
  return (
    <button className={props.active === props.tab ? "navButton active" : "navButton"} onClick={() => props.setActive(props.tab)}>
      {props.icon}
      <span>{props.label}</span>
    </button>
  );
}

function Home() {
  return (
    <section className="page">
      <div className="pageHeader">
        <p className="eyebrow">Nhập môn An toàn thông tin</p>
        <h2>Demo ký số và xác minh tài liệu điện tử</h2>
        <p>
          SecureDoc minh họa SHA-256, RSA-PSS, cặp khóa công khai/bí mật, certificate giả lập, và các trường hợp xác minh thất bại khi tài
          liệu hoặc certificate bị thay đổi.
        </p>
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
    <section className="page">
      <div className="pageHeader compact">
        <h2>Tạo khóa</h2>
        <p>Tạo RSA key pair 2048-bit và certificate JSON giả lập.</p>
      </div>
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
      {error && <p className="errorText">{error}</p>}
      {result && (
        <div className="outputStack">
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
    <section className="page">
      <div className="pageHeader compact">
        <h2>Ký tài liệu</h2>
        <p>Upload file, nhập private key và certificate để tạo signed package.</p>
      </div>
      <FileInput label="Tài liệu" onFile={setFile} />
      <TextOrFile label="Private key PEM" value={privateKey} setValue={setPrivateKey} />
      <TextOrFile label="Certificate JSON" value={certificate} setValue={setCertificate} />
      <button className="primary" onClick={submit}>
        <FileSignature size={18} />
        Ký tài liệu
      </button>
      {error && <p className="errorText">{error}</p>}
      {result && (
        <div className="resultPanel">
          <p><strong>Hash tài liệu:</strong> {result.documentHash}</p>
          <p><strong>Thời điểm ký:</strong> {result.signedAt}</p>
          <p><strong>Chữ ký:</strong> {result.signatureBase64.slice(0, 96)}...</p>
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
    <section className="page">
      <div className="pageHeader compact">
        <h2>Xác minh tài liệu</h2>
        <p>Upload file gốc và signed package để kiểm tra hash, certificate và chữ ký.</p>
      </div>
      <FileInput label="Tài liệu" onFile={setFile} />
      <TextOrFile label="signed_package.json" value={packageText} setValue={setPackageText} />
      <button className="primary" onClick={submit}>
        <FileCheck size={18} />
        Xác minh
      </button>
      {error && <p className="errorText">{error}</p>}
      {result && (
        <div className={result.valid ? "verifyBox valid" : "verifyBox invalid"}>
          {result.valid ? <BadgeCheck size={24} /> : <Ban size={24} />}
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

function FileInput({ label, onFile }: { label: string; onFile: (file: File | null) => void }) {
  return (
    <label className="fileRow">
      {label}
      <input type="file" onChange={(event) => onFile(event.target.files?.[0] ?? null)} />
    </label>
  );
}

function TextOrFile({ label, value, setValue }: { label: string; value: string; setValue: (value: string) => void }) {
  async function readFile(file: File | null) {
    if (file) setValue(await file.text());
  }

  return (
    <label>
      {label}
      <input type="file" onChange={(event) => readFile(event.target.files?.[0] ?? null)} />
      <textarea value={value} onChange={(event) => setValue(event.target.value)} spellCheck={false} />
    </label>
  );
}

function PemBlock({ title, value, filename }: { title: string; value: string; filename: string }) {
  return (
    <article className="pemBlock">
      <header>
        <h3>{title}</h3>
        <button className="iconButton" onClick={() => downloadText(filename, value)} title={`Tải ${filename}`}>
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
