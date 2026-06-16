import React, { useId, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  AlertTriangle,
  BadgeCheck,
  Ban,
  CheckCircle2,
  ClipboardCheck,
  Download,
  Eye,
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
import {
  browserSigningHashSupported,
  canonicalizePayload,
  hashDocument,
  importPrivateKey,
  prepareSigningRequest,
  signPayload,
  submitSignature,
  verifyV2,
  type Certificate,
  type HashAlgorithm,
  type PrepareResponse,
  type SignedPackageV2,
  type SubmitResponse,
  type VerificationReport,
  type VerificationStep,
  type VerifyV2Response
} from "./signing-v2";
import "./styles.css";

const API_BASE = "http://127.0.0.1:8000";

type LegacySignedPackage = {
  documentName: string;
  documentHash: string;
  hashAlgorithm: HashAlgorithm;
  signatureAlgorithm: string;
  signatureBase64: string;
  signedAt: string;
  certificate: Certificate;
};

type HashResult = {
  documentName: string;
  hashAlgorithm: HashAlgorithm;
  documentHash: string;
};

type VerifyDetails = Record<string, unknown> & {
  verificationSteps?: VerificationStep[];
};

type LegacyVerifyResult = {
  valid: boolean;
  reason: string;
  signer: { name: string; email: string; serialNumber: string } | null;
  documentHash: string;
  signedAt: string | null;
  details: VerifyDetails;
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

type Tab = "home" | "hash" | "keys" | "signv2" | "verifyv2" | "sign" | "verify" | "revoke" | "blind";

const tabs: Array<{ tab: Tab; label: string; helper: string; icon: React.ReactNode }> = [
  { tab: "home", label: "Tong quan", helper: "V2 flow", icon: <BadgeCheck size={18} /> },
  { tab: "hash", label: "Bam file", helper: "SHA-2/SHA-3", icon: <Hash size={18} /> },
  { tab: "keys", label: "Tao khoa", helper: "RSA 3072", icon: <KeyRound size={18} /> },
  { tab: "signv2", label: "Ky v2", helper: "Client-side", icon: <FileSignature size={18} /> },
  { tab: "verifyv2", label: "Xac minh v2", helper: "Report", icon: <ClipboardCheck size={18} /> },
  { tab: "revoke", label: "Thu hoi", helper: "By serial", icon: <RotateCcw size={18} /> },
  { tab: "sign", label: "Ky legacy", helper: "Insecure", icon: <AlertTriangle size={18} /> },
  { tab: "verify", label: "Verify legacy", helper: "Old package", icon: <FileCheck size={18} /> },
  { tab: "blind", label: "Chu ky mu", helper: "Unchanged", icon: <EyeOff size={18} /> }
];

const hashAlgorithmOptions: Array<{ value: HashAlgorithm; label: string; helper: string }> = [
  { value: "SHA-256", label: "SHA-256", helper: "Default for v2 browser signing." },
  { value: "SHA-384", label: "SHA-384", helper: "Stronger SHA-2 profile." },
  { value: "SHA-512", label: "SHA-512", helper: "512-bit SHA-2 digest." },
  { value: "SHA3-256", label: "SHA3-256", helper: "Backend supports it; browser Web Crypto cannot sign RSA-PSS with SHA3." }
];

const signingPurposes = [
  { value: "approve_document", label: "Approve document" },
  { value: "confirm_reading", label: "Confirm reading" },
  { value: "sign_contract", label: "Sign contract" },
  { value: "certify_copy", label: "Certify copy" },
  { value: "acknowledge_receipt", label: "Acknowledge receipt" }
];

function App() {
  const [activeTab, setActiveTab] = useState<Tab>("home");

  return (
    <div className="appShell">
      <aside className="sidebar" aria-label="SecureDoc navigation">
        <div className="brand">
          <div className="brandMark" aria-hidden="true">
            <Fingerprint size={26} />
          </div>
          <div>
            <h1>SecureDoc</h1>
            <span>Digital signature demo</span>
          </div>
        </div>
        <nav className="navList">
          {tabs.map((item) => (
            <TabButton key={item.tab} {...item} active={activeTab} setActive={setActiveTab} />
          ))}
        </nav>
        <div className="sidebarNote">
          <ShieldCheck size={18} />
          <p>Main flow is v2: the browser signs a canonical payload; the API verifies and stores the signed package.</p>
        </div>
      </aside>

      <main>
        {activeTab === "home" && <Home setActiveTab={setActiveTab} />}
        {activeTab === "hash" && <HashDocument />}
        {activeTab === "keys" && <GenerateKeys />}
        {activeTab === "signv2" && <SignDocumentV2 />}
        {activeTab === "verifyv2" && <VerifyDocumentV2 />}
        {activeTab === "revoke" && <RevokeCertificate />}
        {activeTab === "sign" && <SignDocumentLegacy />}
        {activeTab === "verify" && <VerifyDocumentLegacy />}
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
          <p className="eyebrow">Digital signature protocol</p>
          <h2>SecureDoc v2 signs canonical payloads in the browser</h2>
          <p>
            The main flow no longer sends a private key to the API. SecureDoc creates a signing payload,
            the client signs that canonical JSON, and the server verifies certificate trust, revocation,
            replay status, algorithm policy, document integrity, and the RSA-PSS signature.
          </p>
        </div>
        <div className="heroActions">
          <button className="primary heroAction" onClick={() => setActiveTab("keys")}>
            <KeyRound size={18} />
            Create keys
          </button>
          <button className="secondary heroAction" onClick={() => setActiveTab("signv2")}>
            <FileSignature size={18} />
            Sign v2
          </button>
        </div>
      </div>

      <div className="workflowGrid" aria-label="V2 workflow">
        <StepCard number="01" title="Create demo cert" text="Generate RSA 3072-bit keys and a legacy-demo JSON certificate signed by SecureDoc Demo CA." />
        <StepCard number="02" title="Review payload" text="Review file name, hash, signer, certificate serial, purpose, requestId, and nonce before signing." />
        <StepCard number="03" title="Verify report" text="Get a detailed report instead of a single boolean: integrity, signature, certificate, revocation, replay, and warnings." />
      </div>

      <div className="metricGrid">
        <InfoBox title="No server-side private key" text="The v2 signing endpoint receives only a signed package, never a private key." />
        <InfoBox title="Canonical JSON" text="The signature covers the full signingPayload, not only a detached document hash." />
        <InfoBox title="DB revocation" text="Revocation is checked by serialNumber from the server DB, not from package status." />
        <InfoBox title="Demo boundaries" text="Certificates are still legacy-demo JSON; no real CA, HSM, TSA, or PAdES profile is implemented." />
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
  const [hashAlgorithm, setHashAlgorithm] = useState<HashAlgorithm>("SHA-256");
  const [result, setResult] = useState<HashResult | null>(null);
  const [error, setError] = useState("");

  async function submit() {
    if (!file) {
      setError("Choose a document first.");
      return;
    }
    setError("");
    setResult(null);
    try {
      setResult(await hashDocument(file, hashAlgorithm));
    } catch (err) {
      setError(errorMessage(err, "Cannot hash document."));
    }
  }

  return (
    <section className="page taskPage">
      <PageHeader title="Hash document" description="Compute the document digest used by signing and verification flows." />
      <div className="surface">
        <FileInput label="Document" onFile={setFile} />
        <HashAlgorithmSelect value={hashAlgorithm} setValue={setHashAlgorithm} />
        <button className="primary" onClick={submit}>
          <Hash size={18} />
          Hash document
        </button>
        {error && <p className="errorText" role="alert">{error}</p>}
      </div>
      {result && (
        <div className="resultPanel" aria-label="Hash result">
          <div className="resultHeader">
            <CheckCircle2 size={22} />
            <div>
              <h3>Hash computed</h3>
              <p>{result.documentName}</p>
            </div>
          </div>
          <dl className="detailList">
            <DetailItem label="Hash algorithm" value={result.hashAlgorithm} />
            <DetailItem label="Document hash" value={result.documentHash} />
          </dl>
        </div>
      )}
    </section>
  );
}

function GenerateKeys() {
  const [name, setName] = useState("Nguyen Van A");
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
      setError(errorMessage(err, "Cannot generate keys."));
    }
  }

  return (
    <section className="page taskPage">
      <PageHeader title="Create keys and demo certificate" description="Generate an RSA 3072-bit key pair and a SecureDoc legacy-demo JSON certificate." />
      <div className="surface">
        <div className="warningBanner">
          <AlertTriangle size={16} />
          This demo returns the private key to the browser so you can test v2 client-side signing. Do not use these demo keys in production.
        </div>
        <div className="formGrid">
          <label>
            Full name
            <input value={name} onChange={(event) => setName(event.target.value)} />
          </label>
          <label>
            Email
            <input value={email} onChange={(event) => setEmail(event.target.value)} />
          </label>
        </div>
        <button className="primary" onClick={submit}>
          <KeyRound size={18} />
          Create key pair
        </button>
        {error && <p className="errorText" role="alert">{error}</p>}
      </div>
      {result && (
        <div className="outputStack" aria-label="Key generation result">
          <PemBlock title="Private key PEM" value={result.privateKeyPem} filename="private_key.pem" />
          <PemBlock title="Public key PEM" value={result.publicKeyPem} filename="public_key.pem" />
          <PemBlock title="Legacy-demo certificate JSON" value={JSON.stringify(result.certificate, null, 2)} filename="certificate.json" />
        </div>
      )}
    </section>
  );
}

type V2Step = "input" | "review" | "signed";

function SignDocumentV2() {
  const [step, setStep] = useState<V2Step>("input");
  const [file, setFile] = useState<File | null>(null);
  const [privateKeyPem, setPrivateKeyPem] = useState("");
  const [certificateText, setCertificateText] = useState("");
  const [hashAlgorithm, setHashAlgorithm] = useState<HashAlgorithm>("SHA-256");
  const [purpose, setPurpose] = useState("approve_document");
  const [prepareResult, setPrepareResult] = useState<PrepareResponse | null>(null);
  const [submitResult, setSubmitResult] = useState<SubmitResponse | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function prepare() {
    if (!file) {
      setError("Choose a document first.");
      return;
    }
    const certificate = parseCertificate(certificateText, setError);
    if (!certificate) return;
    setError("");
    setSubmitResult(null);
    setLoading(true);
    try {
      const hash = await hashDocument(file, hashAlgorithm);
      const response = await prepareSigningRequest({
        documentName: file.name,
        documentHash: hash.documentHash,
        hashAlgorithm: hash.hashAlgorithm,
        certificateSerialNumber: certificate.serialNumber,
        signingPurpose: purpose
      });
      setPrepareResult(response);
      setStep("review");
    } catch (err) {
      setError(errorMessage(err, "Cannot create signing request."));
    } finally {
      setLoading(false);
    }
  }

  async function sign() {
    if (!prepareResult) return;
    if (!privateKeyPem.trim()) {
      setError("Paste or upload the private key PEM.");
      return;
    }
    const certificate = parseCertificate(certificateText, setError);
    if (!certificate) return;
    if (certificate.serialNumber !== prepareResult.signingPayload.certificateSerialNumber) {
      setError("Certificate serial changed after prepare.");
      return;
    }
    const signingHash = prepareResult.signingPayload.hashAlgorithm;
    if (!browserSigningHashSupported(signingHash)) {
      setError("Browser Web Crypto cannot RSA-PSS sign with SHA3-256. Use SHA-256, SHA-384, SHA-512, or submit an externally created SHA3 package.");
      return;
    }

    setError("");
    setLoading(true);
    try {
      const canonicalPayload = canonicalizePayload(prepareResult.signingPayload);
      const key = await importPrivateKey(privateKeyPem, signingHash);
      const signatureBase64 = await signPayload(key, canonicalPayload, signingHash);
      const signedPackage: SignedPackageV2 = {
        packageVersion: "2.0",
        signingPayload: prepareResult.signingPayload,
        payloadCanonicalization: "JSON-canonical-sorted-keys",
        signatureAlgorithm: "RSA-PSS",
        signatureBase64,
        signerCertificate: certificate,
        signedAtClient: new Date().toISOString()
      };
      const response = await submitSignature(signedPackage);
      setSubmitResult(response);
      setStep("signed");
    } catch (err) {
      setError(errorMessage(err, "Cannot sign or submit package."));
    } finally {
      setLoading(false);
    }
  }

  function reset() {
    setStep("input");
    setPrepareResult(null);
    setSubmitResult(null);
    setError("");
  }

  return (
    <section className="page taskPage">
      <PageHeader title="Sign v2 - client-side" description="Create a signing request, review it, sign canonical JSON in the browser, then submit the signed package." />

      {step === "input" && (
        <div className="surface">
          <div className="warningBanner">
            <ShieldCheck size={16} />
            The private key is used only by browser Web Crypto in this v2 flow. It is not sent to the API.
          </div>
          <FileInput label="Document" onFile={setFile} />
          <HashAlgorithmSelect value={hashAlgorithm} setValue={setHashAlgorithm} />
          <label>
            Signing purpose
            <select value={purpose} onChange={(event) => setPurpose(event.target.value)}>
              {signingPurposes.map((item) => (
                <option key={item.value} value={item.value}>{item.label}</option>
              ))}
            </select>
          </label>
          <TextOrFile label="Certificate JSON" value={certificateText} setValue={setCertificateText} />
          <TextOrFile label="Private key PEM (local browser use only)" value={privateKeyPem} setValue={setPrivateKeyPem} />
          <button className="primary" onClick={prepare} disabled={loading}>
            <Eye size={18} />
            {loading ? "Preparing..." : "Create signing request"}
          </button>
          {error && <p className="errorText" role="alert">{error}</p>}
        </div>
      )}

      {step === "review" && prepareResult && (
        <div className="surface reviewPanel">
          <h3>Review before signing</h3>
          <dl className="detailList">
            <DetailItem label="Document" value={prepareResult.signingPayload.documentName} />
            <DetailItem label="Document hash" value={prepareResult.signingPayload.documentHash} />
            <DetailItem label="Hash algorithm" value={prepareResult.signingPayload.hashAlgorithm} />
            <DetailItem label="Signer" value={`${prepareResult.signingPayload.signerName} (${prepareResult.signingPayload.signerEmail})`} />
            <DetailItem label="Certificate serial" value={prepareResult.signingPayload.certificateSerialNumber} />
            <DetailItem label="Signing purpose" value={prepareResult.signingPayload.signingPurpose} />
            <DetailItem label="Request ID" value={prepareResult.requestId} />
            <DetailItem label="Nonce" value={prepareResult.nonce} />
            <DetailItem label="Canonicalization" value="JSON-canonical-sorted-keys" />
          </dl>
          {prepareResult.warnings.length > 0 && <WarningList warnings={prepareResult.warnings} />}
          <div className="buttonRow">
            <button className="primary" onClick={sign} disabled={loading}>
              <FileSignature size={18} />
              {loading ? "Signing..." : "Sign in browser"}
            </button>
            <button className="secondary" onClick={reset}>Cancel</button>
          </div>
          {error && <p className="errorText" role="alert">{error}</p>}
        </div>
      )}

      {step === "signed" && submitResult && (
        <div className="resultPanel">
          <div className="resultHeader">
            <CheckCircle2 size={22} />
            <div>
              <h3>Signed package accepted</h3>
              <p>Request ID: {submitResult.requestId}</p>
            </div>
          </div>
          <dl className="detailList">
            <DetailItem label="Received at server" value={submitResult.receivedAtServer} />
            <DetailItem label="Final decision" value={submitResult.verificationReport.finalDecision} />
            <DetailItem label="Signature" value={`${submitResult.signedPackage.signatureBase64.slice(0, 120)}...`} />
          </dl>
          {submitResult.warnings.length > 0 && <WarningList warnings={submitResult.warnings} />}
          <ReportPanel report={submitResult.verificationReport} />
          <div className="buttonRow">
            <button className="secondary" onClick={() => downloadText("signed_package_v2.json", JSON.stringify(submitResult.signedPackage, null, 2))}>
              <Download size={18} />
              Download signed_package_v2.json
            </button>
            <button className="secondary" onClick={reset}>Sign another document</button>
          </div>
        </div>
      )}
    </section>
  );
}

function VerifyDocumentV2() {
  const [file, setFile] = useState<File | null>(null);
  const [packageText, setPackageText] = useState("");
  const [result, setResult] = useState<VerifyV2Response | null>(null);
  const [error, setError] = useState("");

  async function submit() {
    if (!file) {
      setError("Choose the original document first.");
      return;
    }
    setError("");
    setResult(null);
    try {
      const parsedPackage = JSON.parse(packageText) as SignedPackageV2;
      const packageHashAlgorithm = (parsedPackage.signingPayload?.hashAlgorithm ?? "SHA-256") as HashAlgorithm;
      const hash = await hashDocument(file, packageHashAlgorithm);
      setResult(await verifyV2({ documentHash: hash.documentHash, hashAlgorithm: hash.hashAlgorithm, signedPackage: parsedPackage }));
    } catch (err) {
      setError(errorMessage(err, "Cannot verify signed package."));
    }
  }

  return (
    <section className="page taskPage">
      <PageHeader title="Verify v2 package" description="Upload the original document and a v2 signed package to get a detailed verification report." />
      <div className="surface">
        <FileInput label="Original document" onFile={setFile} />
        <TextOrFile label="signed_package_v2.json" value={packageText} setValue={setPackageText} />
        <button className="primary" onClick={submit}>
          <ClipboardCheck size={18} />
          Verify v2
        </button>
        {error && <p className="errorText" role="alert">{error}</p>}
      </div>
      {result && (
        <div className={result.valid ? "verifyBox valid" : "verifyBox invalid"} role="status" aria-live="polite">
          <div className="statusIcon" aria-hidden="true">
            {result.valid ? <BadgeCheck size={24} /> : <Ban size={24} />}
          </div>
          <div>
            <h3>{result.valid ? "Signature is valid" : "Signature is invalid"}</h3>
            <p>{result.reason}</p>
            {result.signer && <p>Signer: {result.signer.name} ({result.signer.email}), serial {result.signer.serialNumber}</p>}
            <ReportPanel report={result.report} />
          </div>
        </div>
      )}
    </section>
  );
}

function RevokeCertificate() {
  const [certificateText, setCertificateText] = useState("");
  const [serialNumber, setSerialNumber] = useState("");
  const [reason, setReason] = useState("key_compromise");
  const [result, setResult] = useState<{ serialNumber: string; status: string; reason: string; revokedAt: string } | null>(null);
  const [error, setError] = useState("");

  async function submit() {
    setError("");
    setResult(null);
    let serial = serialNumber.trim();
    if (!serial && certificateText.trim()) {
      const certificate = parseCertificate(certificateText, setError);
      if (!certificate) return;
      serial = certificate.serialNumber;
      setSerialNumber(serial);
    }
    if (!serial) {
      setError("Enter a certificate serial number or upload certificate JSON.");
      return;
    }
    try {
      const response = await fetch(`${API_BASE}/api/certificates/revoke/v2`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ serialNumber: serial, reason, revokedBy: "local-demo-user" })
      });
      setResult(await parseResponse<{ serialNumber: string; status: string; reason: string; revokedAt: string }>(response));
    } catch (err) {
      setError(errorMessage(err, "Cannot revoke certificate."));
    }
  }

  return (
    <section className="page taskPage">
      <PageHeader title="Revoke certificate" description="Revoke by server DB serial number. Verification does not trust package status." />
      <div className="surface">
        <label>
          Serial number
          <input value={serialNumber} onChange={(event) => setSerialNumber(event.target.value)} placeholder="Certificate serial" />
        </label>
        <label>
          Revocation reason
          <input value={reason} onChange={(event) => setReason(event.target.value)} />
        </label>
        <TextOrFile label="Optional certificate JSON (to fill serial)" value={certificateText} setValue={setCertificateText} />
        <button className="primary" onClick={submit}>
          <RotateCcw size={18} />
          Revoke certificate
        </button>
        {error && <p className="errorText" role="alert">{error}</p>}
      </div>
      {result && (
        <div className="resultPanel">
          <div className="resultHeader">
            <Ban size={22} />
            <div>
              <h3>Certificate revoked</h3>
              <p>Serial: {result.serialNumber}</p>
            </div>
          </div>
          <dl className="detailList">
            <DetailItem label="Status" value={result.status} />
            <DetailItem label="Reason" value={result.reason} />
            <DetailItem label="Revoked at" value={result.revokedAt} />
          </dl>
        </div>
      )}
    </section>
  );
}

function SignDocumentLegacy() {
  const [file, setFile] = useState<File | null>(null);
  const [privateKey, setPrivateKey] = useState("");
  const [certificate, setCertificate] = useState("");
  const [hashAlgorithm, setHashAlgorithm] = useState<HashAlgorithm>("SHA-256");
  const [result, setResult] = useState<LegacySignedPackage | null>(null);
  const [error, setError] = useState("");

  async function submit() {
    if (!file) {
      setError("Choose a document first.");
      return;
    }
    setError("");
    setResult(null);
    const body = new FormData();
    body.append("file", file);
    body.append("privateKeyPem", privateKey);
    body.append("certificate", certificate);
    body.append("hashAlgorithm", hashAlgorithm);
    try {
      const response = await fetch(`${API_BASE}/api/sign`, { method: "POST", body });
      setResult(await parseResponse<LegacySignedPackage>(response));
    } catch (err) {
      setError(errorMessage(err, "Cannot sign document."));
    }
  }

  return (
    <section className="page taskPage">
      <PageHeader title="Legacy sign endpoint" description="This insecure demo endpoint sends the private key to the backend. It is kept only for compatibility." />
      <div className="surface">
        <div className="warningBanner">
          <AlertTriangle size={16} />
          Legacy flow is insecure because the API receives privateKeyPem. Use Sign v2 for the main flow.
        </div>
        <FileInput label="Document" onFile={setFile} />
        <HashAlgorithmSelect value={hashAlgorithm} setValue={setHashAlgorithm} />
        <TextOrFile label="Private key PEM" value={privateKey} setValue={setPrivateKey} />
        <TextOrFile label="Certificate JSON" value={certificate} setValue={setCertificate} />
        <button className="primary" onClick={submit}>
          <FileSignature size={18} />
          Sign with legacy API
        </button>
        {error && <p className="errorText" role="alert">{error}</p>}
      </div>
      {result && (
        <div className="resultPanel" aria-label="Legacy signing result">
          <div className="resultHeader">
            <CheckCircle2 size={22} />
            <div>
              <h3>Legacy signed package created</h3>
              <p>Use only for old verify flow demonstrations.</p>
            </div>
          </div>
          <dl className="detailList">
            <DetailItem label="Document hash" value={result.documentHash} />
            <DetailItem label="Hash algorithm" value={result.hashAlgorithm} />
            <DetailItem label="Signed at" value={result.signedAt} />
            <DetailItem label="Signature" value={`${result.signatureBase64.slice(0, 120)}...`} />
          </dl>
          <button className="secondary" onClick={() => downloadText("signed_package_legacy.json", JSON.stringify(result, null, 2))}>
            <Download size={18} />
            Download legacy package
          </button>
        </div>
      )}
    </section>
  );
}

function VerifyDocumentLegacy() {
  const [file, setFile] = useState<File | null>(null);
  const [packageText, setPackageText] = useState("");
  const [result, setResult] = useState<LegacyVerifyResult | null>(null);
  const [error, setError] = useState("");

  async function submit() {
    if (!file) {
      setError("Choose a document first.");
      return;
    }
    setError("");
    setResult(null);
    const body = new FormData();
    body.append("file", file);
    body.append("signedPackage", packageText);
    try {
      const response = await fetch(`${API_BASE}/api/verify`, { method: "POST", body });
      setResult(await parseResponse<LegacyVerifyResult>(response));
    } catch (err) {
      setError(errorMessage(err, "Cannot verify document."));
    }
  }

  return (
    <section className="page taskPage">
      <PageHeader title="Legacy verify endpoint" description="Verifies old packages that signed only the document hash." />
      <div className="surface">
        <FileInput label="Document" onFile={setFile} />
        <TextOrFile label="signed_package_legacy.json" value={packageText} setValue={setPackageText} />
        <button className="primary" onClick={submit}>
          <FileCheck size={18} />
          Verify legacy package
        </button>
        {error && <p className="errorText" role="alert">{error}</p>}
      </div>
      {result && (
        <div className={result.valid ? "verifyBox valid" : "verifyBox invalid"} role="status" aria-live="polite">
          <div className="statusIcon" aria-hidden="true">
            {result.valid ? <BadgeCheck size={24} /> : <Ban size={24} />}
          </div>
          <div>
            <h3>{result.valid ? "Legacy signature valid" : "Legacy signature invalid"}</h3>
            <p>{result.reason}</p>
            {result.signer && <p>Signer: {result.signer.name} ({result.signer.email})</p>}
            {Array.isArray(result.details.verificationSteps) && <StepsList steps={result.details.verificationSteps} />}
            <pre>{JSON.stringify(result.details, null, 2)}</pre>
          </div>
        </div>
      )}
    </section>
  );
}

function BlindSignatureDemo() {
  const [message, setMessage] = useState("Anonymous ballot demo 01");
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
      setError(errorMessage(err, "Cannot run blind signature demo."));
    }
  }

  return (
    <section className="page taskPage">
      <PageHeader title="Blind signature demo" description="Existing educational RSA blind signature demo. It was not expanded in this change." />
      <div className="surface">
        <label>
          Message
          <textarea value={message} onChange={(event) => setMessage(event.target.value)} />
        </label>
        <button className="primary" onClick={submit}>
          <EyeOff size={18} />
          Run demo
        </button>
        {error && <p className="errorText" role="alert">{error}</p>}
      </div>
      {result && (
        <div className={result.valid ? "verifyBox valid" : "verifyBox invalid"} role="status" aria-live="polite">
          <div className="statusIcon" aria-hidden="true">
            {result.valid ? <BadgeCheck size={24} /> : <Ban size={24} />}
          </div>
          <div>
            <h3>{result.valid ? "Blind signature valid" : "Blind signature invalid"}</h3>
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

function ReportPanel({ report }: { report: VerificationReport }) {
  const cells: Array<[string, string]> = [
    ["Document integrity", report.documentIntegrity],
    ["Signing payload", report.signingPayloadValid],
    ["Signature", report.signatureValid],
    ["Certificate parsed", report.certificateParsed],
    ["Certificate trusted", report.certificateTrusted],
    ["Certificate type", report.certificateType],
    ["Chain", report.certificateChainValid],
    ["Validity period", report.certificateValidityPeriod],
    ["Revocation", report.certificateRevocationStatus],
    ["Key usage", report.keyUsageValid],
    ["Algorithm policy", report.algorithmPolicyValid],
    ["Replay", report.replayCheck],
    ["Timestamp", report.timestampStatus],
    ["Final decision", report.finalDecision]
  ];

  return (
    <div className="reportPanel">
      <div className="reportGrid">
        {cells.map(([label, value]) => (
          <ReportCell key={label} label={label} value={value} />
        ))}
      </div>
      {report.warnings.length > 0 && <WarningList warnings={report.warnings} />}
      <StepsList steps={report.verificationSteps} />
    </div>
  );
}

function ReportCell({ label, value }: { label: string; value: string }) {
  const good = value === "passed" || value === "valid";
  const bad = value === "failed" || value === "invalid" || value === "revoked";
  return (
    <div className={good ? "reportCell ok" : bad ? "reportCell bad" : "reportCell warn"}>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function WarningList({ warnings }: { warnings: string[] }) {
  return (
    <div className="warningBanner">
      <AlertTriangle size={16} />
      <span>{warnings.join(" | ")}</span>
    </div>
  );
}

function StepsList({ steps }: { steps: VerificationStep[] }) {
  return (
    <ol className="verifySteps">
      {steps.map((item, index) => (
        <li key={`${item.step}-${index}`} className={item.status === "passed" ? "passed" : item.status === "failed" ? "failed" : "warning"}>
          <strong>{item.step}</strong>
          <span>{item.message}</span>
        </li>
      ))}
    </ol>
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

function HashAlgorithmSelect({ value, setValue }: { value: HashAlgorithm; setValue: (value: HashAlgorithm) => void }) {
  const selected = hashAlgorithmOptions.find((item) => item.value === value);

  return (
    <label>
      Hash algorithm
      <select value={value} onChange={(event) => setValue(event.target.value as HashAlgorithm)}>
        {hashAlgorithmOptions.map((item) => (
          <option key={item.value} value={item.value}>{item.label}</option>
        ))}
      </select>
      {selected && <small className="fieldHint">{selected.helper}</small>}
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
        <button className="iconButton" onClick={() => downloadText(filename, value)} title={`Download ${filename}`} aria-label={`Download ${filename}`}>
          <Download size={18} />
        </button>
      </header>
      <pre>{value}</pre>
    </article>
  );
}

function parseCertificate(value: string, setError: (value: string) => void): Certificate | null {
  try {
    const certificate = JSON.parse(value) as Certificate;
    if (!certificate.serialNumber || !certificate.publicKeyPem) {
      setError("Certificate JSON is missing serialNumber or publicKeyPem.");
      return null;
    }
    return certificate;
  } catch {
    setError("Certificate JSON is invalid.");
    return null;
  }
}

async function parseResponse<T>(response: Response): Promise<T> {
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = data && typeof data.detail === "string" ? data.detail : "Request failed";
    throw new Error(detail);
  }
  return data as T;
}

function errorMessage(error: unknown, fallback: string) {
  return error instanceof Error ? error.message : fallback;
}

function downloadText(filename: string, content: string) {
  const blob = new Blob([content], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

createRoot(document.getElementById("root")!).render(<App />);
